package rules

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

// Defaults of a [Client].
const (
	DefaultTimeout     = 10 * time.Second
	DefaultFileTimeout = 60 * time.Second
	DefaultSettle      = 1500 * time.Millisecond
	DefaultParallel    = 6
	// MaxManifestSize bounds a manifest's download.
	MaxManifestSize = 1 << 20
)

// Cache keeps what a [Client] last got, so it keeps working when no host answers. Keys are
// branch paths ([ManifestPath] and the files' paths), so they are usable as file names. The
// client checks every value it gets against a manifest; a cache need not.
type Cache interface {
	Get(key string) ([]byte, bool)
	// Put stores a value. A cache that cannot store it drops it.
	Put(key string, value []byte)
}

// Client gets the branch from its hosts. Its zero value works, with the default hosts and
// http.DefaultClient; set fields before the first call and do not change them after.
type Client struct {
	// HTTP makes the requests. The caller controls routing, proxies and address policy
	// through it; its Timeout, if any, applies on top of the client's.
	HTTP *http.Client
	// Hosts are the hosts to ask, [DefaultHosts] if empty.
	Hosts []Host
	// Cache keeps the last good manifest and files. The cached manifest's version is the
	// lowest the client accepts from the network.
	Cache Cache
	// MinVersion is the lowest manifest version to accept, for a caller that keeps the last
	// version itself.
	MinVersion int64
	// Timeout bounds one manifest request, FileTimeout one file request.
	Timeout     time.Duration
	FileTimeout time.Duration
	// Settle is how long to wait, after the first manifest arrives, for other operators to
	// serve one, so that their agreement can decide the version.
	Settle time.Duration
	// Parallel bounds the requests in flight.
	Parallel int
}

// Snapshot is a manifest a [Client] accepted, with the hosts to download its files from.
type Snapshot struct {
	Manifest *Manifest
	// Hosts are ranked: those serving this manifest, fastest first; then those that did not
	// answer in time, in configured order; then those serving another version.
	Hosts []Host
	// Operators counts the operators that served this manifest byte for byte.
	Operators int

	raw    []byte
	client *Client
}

// Base returns the URL of the fastest host serving the manifest, the base to put in the template.
func (s *Snapshot) Base() string { return s.Hosts[0].Base }

// Save stores the manifest in the client's cache, making its version the lowest the client
// accepts. Save it after the files that depend on it, so the cache never holds a manifest
// whose files it lacks.
func (s *Snapshot) Save() {
	if s.client.Cache != nil {
		s.client.Cache.Put(ManifestPath, s.raw)
	}
}

type answer struct {
	host    int
	raw     []byte
	m       *Manifest
	latency time.Duration
	err     error
}

// Latest asks every host for the manifest at once and returns the version to use:
//
//   - The newest manifest that at least two operators serve byte for byte.
//   - Failing that, the newest manifest of the operator fewest hops from the branch that
//     answered, which must have served it over HTTPS.
//
// A manifest older than MinVersion or the cached manifest is never accepted. Latest waits for
// every host, or for Settle after the first manifest arrives, whichever comes first, and then
// cancels the requests still running.
func (c *Client) Latest(ctx context.Context) (*Snapshot, error) {
	hosts := c.hosts()
	if len(hosts) == 0 {
		return nil, ErrNoManifest
	}
	minVersion := c.MinVersion
	if m, _ := c.cachedManifest(); m != nil && m.Version > minVersion {
		minVersion = m.Version
	}

	probeCtx, cancel := context.WithCancel(ctx)
	answers := make(chan answer, len(hosts))
	slots := make(chan struct{}, c.parallel())
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-probeCtx.Done():
				answers <- answer{host: i, err: probeCtx.Err()}
				return
			}
			defer func() { <-slots }()
			answers <- c.probe(probeCtx, i, hosts[i], minVersion)
		}()
	}

	got := make([]*answer, len(hosts))
	var settle <-chan time.Time
collect:
	for range hosts {
		select {
		case a := <-answers:
			got[a.host] = &a
			if a.m != nil && settle == nil {
				timer := time.NewTimer(c.settle())
				defer timer.Stop()
				settle = timer.C
			}
		case <-settle:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	cancel()
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.decide(hosts, got, minVersion)
}

// probe fetches and parses one host's manifest. An answer with a manifest older than minVersion
// keeps the manifest, to rank the host, and an error.
func (c *Client) probe(ctx context.Context, i int, host Host, minVersion int64) answer {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	a := answer{host: i}
	a.raw, a.err = c.get(ctx, host.Base+"/"+ManifestPath, MaxManifestSize)
	if a.err == nil {
		a.m, a.err = ParseManifest(a.raw)
	}
	a.latency = time.Since(start)
	if a.err == nil && a.m.Version < minVersion {
		a.err = fmt.Errorf("%w: version %d, already saw %d", ErrRollback, a.m.Version, minVersion)
	}
	if a.err != nil {
		a.err = &HostError{Host: host.Base, Err: a.err}
	}
	return a
}

func (c *Client) decide(hosts []Host, got []*answer, minVersion int64) (*Snapshot, error) {
	// Group the usable answers by content.
	type candidate struct {
		raw       []byte
		m         *Manifest
		operators map[string]bool
		hops      int
	}
	var candidates []*candidate
	var errs []error
	for _, a := range got {
		if a == nil {
			continue
		}
		if a.err != nil {
			errs = append(errs, a.err)
			continue
		}
		host := hosts[a.host]
		i := slices.IndexFunc(candidates, func(c *candidate) bool { return bytes.Equal(c.raw, a.raw) })
		if i < 0 {
			candidates = append(candidates, &candidate{raw: a.raw, m: a.m, operators: map[string]bool{}, hops: host.Hops})
			i = len(candidates) - 1
		}
		candidates[i].operators[host.Operator] = true
		candidates[i].hops = min(candidates[i].hops, host.Hops)
	}

	var best *candidate
	for _, cand := range candidates {
		if len(cand.operators) >= 2 && (best == nil || cand.m.Version > best.m.Version) {
			best = cand
		}
	}
	if best == nil {
		// No agreement: trust the operator closest to the branch, then the newest it serves.
		for _, cand := range candidates {
			if best == nil || cand.hops < best.hops || cand.hops == best.hops && cand.m.Version > best.m.Version {
				best = cand
			}
		}
		if best != nil && !servedSecurely(hosts, got, best.raw) {
			return nil, fmt.Errorf("%w: %w", ErrNoManifest, ErrInsecure)
		}
	}
	if best == nil {
		if len(errs) == 0 {
			errs = append(errs, errors.New("no host answered in time"))
		}
		return nil, fmt.Errorf("%w (version %d or newer): %w", ErrNoManifest, minVersion, errors.Join(errs...))
	}

	return &Snapshot{
		Manifest:  best.m,
		Hosts:     rank(hosts, got, best.raw),
		Operators: len(best.operators),
		raw:       best.raw,
		client:    c,
	}, nil
}

// servedSecurely reports whether every host that served raw did so over HTTPS.
func servedSecurely(hosts []Host, got []*answer, raw []byte) bool {
	for _, a := range got {
		if a != nil && a.err == nil && bytes.Equal(a.raw, raw) {
			if u, err := url.Parse(hosts[a.host].Base); err != nil || u.Scheme != "https" {
				return false
			}
		}
	}
	return true
}

// rank orders the hosts for downloads: those that served raw by latency, then those that did not
// answer in configured order, then those serving another manifest by latency. Hosts that failed
// otherwise are left out.
func rank(hosts []Host, got []*answer, raw []byte) []Host {
	var serving, other []*answer
	var silent []Host
	for i, a := range got {
		switch {
		case a == nil || errors.Is(a.err, context.Canceled):
			silent = append(silent, hosts[i])
		case a.m == nil:
			// Failed without a manifest.
		case bytes.Equal(a.raw, raw):
			serving = append(serving, a)
		default:
			other = append(other, a)
		}
	}
	byLatency := func(a, b *answer) int { return cmp.Compare(a.latency, b.latency) }
	slices.SortStableFunc(serving, byLatency)
	slices.SortStableFunc(other, byLatency)
	ranked := make([]Host, 0, len(hosts))
	for _, a := range serving {
		ranked = append(ranked, hosts[a.host])
	}
	ranked = append(ranked, silent...)
	for _, a := range other {
		ranked = append(ranked, hosts[a.host])
	}
	return ranked
}

// Fetch returns a file of the manifest: from the cache if it holds this content, otherwise from
// the ranked hosts in turn, checking its size and digest. A downloaded file is put in the cache.
func (s *Snapshot) Fetch(ctx context.Context, path string) ([]byte, error) {
	f, ok := s.Manifest.File(path)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotListed, path)
	}
	c := s.client
	if c.Cache != nil {
		if data, ok := c.Cache.Get(path); ok && f.Matches(data) {
			return data, nil
		}
	}
	var errs []error
	for _, host := range s.Hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := c.download(ctx, host, f)
		if err == nil {
			if c.Cache != nil {
				c.Cache.Put(path, data)
			}
			return data, nil
		}
		errs = append(errs, &HostError{Host: host.Base, Err: err})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("rules: %s: %w", path, errors.Join(errs...))
}

func (c *Client) download(ctx context.Context, host Host, f File) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.fileTimeout())
	defer cancel()
	data, err := c.get(ctx, host.Base+"/"+f.Path, f.Size)
	if err != nil {
		return nil, err
	}
	if !f.Matches(data) {
		return nil, ErrDigest
	}
	return data, nil
}

// get downloads a URL, failing on any status but 200 and on bodies over limit bytes.
func (c *Client) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// Origin tells where a [Template] comes from.
type Origin int

const (
	// FromNetwork: downloaded now, or found in the cache unchanged since.
	FromNetwork Origin = iota
	// FromCache: the cached copy, because no host served a usable manifest or template.
	FromCache
)

// ErrNoTemplate reports that no host served the template and the cache holds none: the client
// never got it. Callers route by their own defaults until a later call succeeds.
var ErrNoTemplate = errors.New("rules: no template available")

// Template is the routing template, ready for subconv to fill in.
type Template struct {
	// YAML is the template, with [Placeholder] for the branch's base URL.
	YAML []byte
	// Base is the URL to put in for [Placeholder]: the fastest host serving the version, or the
	// first configured host for a cached template.
	Base    string
	Version int64
	Origin  Origin
	// Err tells why the template is FromCache.
	Err error
}

// Filled returns the template with Base in place of [Placeholder].
func (t *Template) Filled() ([]byte, error) { return Fill(t.YAML, t.Base) }

// Template returns the routing template: the latest version if a host serves it, otherwise the
// cached one, whose Err says why. It fails when ctx ends, and with [ErrNoTemplate] when neither
// hosts nor cache have the template.
func (c *Client) Template(ctx context.Context) (*Template, error) {
	snap, err := c.Latest(ctx)
	if err == nil {
		var data []byte
		if data, err = snap.Fetch(ctx, TemplatePath); err == nil {
			snap.Save()
			return &Template{YAML: data, Base: snap.Base(), Version: snap.Manifest.Version}, nil
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if t := c.cachedTemplate(); t != nil {
		t.Err = err
		return t, nil
	}
	return nil, fmt.Errorf("%w: %w", ErrNoTemplate, err)
}

func (c *Client) cachedManifest() (*Manifest, []byte) {
	if c.Cache == nil {
		return nil, nil
	}
	raw, ok := c.Cache.Get(ManifestPath)
	if !ok {
		return nil, nil
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, nil
	}
	return m, raw
}

func (c *Client) cachedTemplate() *Template {
	m, _ := c.cachedManifest()
	if m == nil {
		return nil
	}
	f, _ := m.File(TemplatePath)
	data, ok := c.Cache.Get(f.Path)
	if !ok || !f.Matches(data) {
		return nil
	}
	return &Template{YAML: data, Base: c.hosts()[0].Base, Version: m.Version, Origin: FromCache}
}

func (c *Client) hosts() []Host {
	if len(c.Hosts) > 0 {
		return c.Hosts
	}
	return defaultHosts
}

func (c *Client) timeout() time.Duration     { return orDefault(c.Timeout, DefaultTimeout) }
func (c *Client) fileTimeout() time.Duration { return orDefault(c.FileTimeout, DefaultFileTimeout) }
func (c *Client) settle() time.Duration      { return orDefault(c.Settle, DefaultSettle) }
func (c *Client) parallel() int              { return orDefault(c.Parallel, DefaultParallel) }

func orDefault[T int | time.Duration](v, def T) T {
	if v > 0 {
		return v
	}
	return def
}

// MemoryCache is a [Cache] in memory, safe for concurrent use.
type MemoryCache struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (c *MemoryCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return bytes.Clone(v), ok
}

func (c *MemoryCache) Put(key string, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string][]byte)
	}
	c.m[key] = bytes.Clone(value)
}
