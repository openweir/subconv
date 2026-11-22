package rules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A branch as the generator would publish it.
func branch(t *testing.T, version int64, template string) (manifest []byte, files map[string][]byte) {
	t.Helper()
	files = map[string][]byte{
		TemplatePath:                    []byte(template),
		"providers/dler/lan.ipcidr.txt": []byte("10.0.0.0/8\n"),
	}
	m := Manifest{
		Version:   version,
		Generated: time.Unix(version, 0).UTC().Format(time.RFC3339),
	}
	for _, p := range []string{"providers/dler/lan.ipcidr.txt", TemplatePath} {
		m.Files = append(m.Files, File{Path: p, Size: int64(len(files[p])), SHA256: digest(files[p]), Updated: "2026-11-21", Kind: "template"})
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return manifest, files
}

// mirror is a host of the branch with a configurable failure.
type mirror struct {
	srv      *httptest.Server
	manifest []byte
	files    map[string][]byte
	delay    time.Duration
	status   int
	hits     atomic.Int32
	canceled atomic.Int32
	inFlight atomic.Int32
	peak     atomic.Int32
}

func newMirror(t *testing.T, manifest []byte, files map[string][]byte) *mirror {
	m := &mirror{manifest: manifest, files: files}
	m.srv = httptest.NewTLSServer(m)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.hits.Add(1)
	n := m.inFlight.Add(1)
	defer m.inFlight.Add(-1)
	for {
		peak := m.peak.Load()
		if n <= peak || m.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-r.Context().Done():
			m.canceled.Add(1)
			return
		}
	}
	if m.status != 0 {
		w.WriteHeader(m.status)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == ManifestPath {
		w.Write(m.manifest)
		return
	}
	data, ok := m.files[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func (m *mirror) host(operator string, hops int) Host {
	return Host{Base: m.srv.URL, Operator: operator, Hops: hops}
}

// testClient trusts the test servers' certificate (all share one) and keeps no idle
// connections, so goroutine counts settle.
func testClient(t *testing.T, m *mirror, hosts ...Host) *Client {
	transport := m.srv.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	return &Client{HTTP: &http.Client{Transport: transport}, Hosts: hosts, Settle: 200 * time.Millisecond}
}

func TestLatestTakesTheAgreedVersion(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	v3, files3 := branch(t, 3, "tampered")
	tampered := newMirror(t, v3, files3)
	slow := newMirror(t, v2, files2)
	slow.delay = 50 * time.Millisecond
	fast := newMirror(t, v2, files2)
	client := testClient(t, fast, tampered.host("jsdmirror", 2), slow.host("jsdelivr", 1), fast.host("github", 0))

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Manifest.Version != 2 || snap.Operators != 2 {
		t.Fatalf("version %d from %d operators, want 2 from 2", snap.Manifest.Version, snap.Operators)
	}
	want := []string{fast.srv.URL, slow.srv.URL, tampered.srv.URL}
	if got := bases(snap.Hosts); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("ranking %v, want %v", got, want)
	}
	if snap.Base() != fast.srv.URL {
		t.Fatalf("base %s", snap.Base())
	}
}

func TestLatestCountsAnOperatorOnce(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	v3, files3 := branch(t, 3, "three")
	a := newMirror(t, v3, files3)
	b := newMirror(t, v3, files3)
	origin := newMirror(t, v2, files2)
	// Two jsDelivr hostnames agreeing are one source; GitHub is fewer hops away.
	client := testClient(t, a, a.host("jsdelivr", 1), b.host("jsdelivr", 1), origin.host("github", 0))

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Manifest.Version != 2 || snap.Operators != 1 {
		t.Fatalf("version %d from %d operators, want GitHub's 2", snap.Manifest.Version, snap.Operators)
	}
}

func TestLatestAcceptsASingleHTTPSSource(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	up := newMirror(t, v2, files2)
	down := newMirror(t, nil, nil)
	down.status = http.StatusBadGateway
	client := testClient(t, up, down.host("jsdmirror", 2), up.host("jsdelivr", 1))

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Manifest.Version != 2 || len(snap.Hosts) != 1 {
		t.Fatalf("version %d, hosts %v", snap.Manifest.Version, bases(snap.Hosts))
	}
}

func TestLatestRefusesASinglePlainHTTPSource(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	plain := httptest.NewServer(&mirror{manifest: v2, files: files2})
	defer plain.Close()
	client := &Client{Hosts: []Host{{Base: plain.URL, Operator: "local"}}}

	_, err := client.Latest(t.Context())
	if !errors.Is(err, ErrInsecure) || !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err %v, want ErrInsecure", err)
	}
}

func TestLatestRefusesRollback(t *testing.T) {
	v4, files4 := branch(t, 4, "four")
	a := newMirror(t, v4, files4)
	b := newMirror(t, v4, files4)
	client := testClient(t, a, a.host("jsdmirror", 2), b.host("jsdelivr", 1))
	client.MinVersion = 5

	_, err := client.Latest(t.Context())
	if !errors.Is(err, ErrRollback) || !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err %v, want ErrRollback", err)
	}

	// The cached floor holds for every host, agreeing or not.
	client.MinVersion = 0
	client.Cache = &MemoryCache{}
	client.Cache.Put(FloorKey, []byte("5\n"))
	if _, err := client.Latest(t.Context()); !errors.Is(err, ErrRollback) {
		t.Fatalf("err %v, want ErrRollback", err)
	}
}

// The cached manifest's version holds for a single operator other than GitHub, but two
// operators, or GitHub, may go below it: one operator may have set it.
func TestLatestLetsAgreementBelowTheCachedManifest(t *testing.T) {
	v4, files4 := branch(t, 4, "four")
	v5, _ := branch(t, 5, "five")
	a := newMirror(t, v4, files4)
	b := newMirror(t, v4, files4)
	for name, tc := range map[string]struct {
		hosts []Host
		want  int64
	}{
		"two operators":      {[]Host{a.host("jsdmirror", 2), b.host("jsdelivr", 1)}, 4},
		"GitHub":             {[]Host{a.host("github", 0)}, 4},
		"one operator":       {[]Host{a.host("jsdelivr", 1), b.host("jsdelivr", 1)}, 0},
		"one mirror":         {[]Host{a.host("jsdmirror", 2)}, 0},
		"GitHub under floor": {[]Host{a.host("github", 0)}, -5},
		"agreed under floor": {[]Host{a.host("jsdmirror", 2), b.host("jsdelivr", 1)}, -5},
	} {
		t.Run(name, func(t *testing.T) {
			client := testClient(t, a, tc.hosts...)
			client.Cache = &MemoryCache{}
			client.Cache.Put(ManifestPath, v5)
			if tc.want < 0 {
				client.Cache.Put(FloorKey, []byte(strconv.FormatInt(-tc.want, 10)))
			}
			snap, err := client.Latest(t.Context())
			switch {
			case tc.want <= 0 && !errors.Is(err, ErrRollback):
				t.Fatalf("err %v, want ErrRollback", err)
			case tc.want > 0 && (err != nil || snap.Manifest.Version != tc.want || !snap.Trusted):
				t.Fatalf("snapshot %+v, err %v", snap, err)
			}
		})
	}
}

// A mirror that alone answers in time is used, but cannot pin the client to its version: the
// reviewer's case of jsdmirror serving a far-future version with a template that routes
// everything direct.
func TestLoneMirrorDoesNotPin(t *testing.T) {
	now := time.Now().Unix()
	direct := "rules:\n  - MATCH,DIRECT\n"
	forged, forgedFiles := branch(t, now+12*3600, direct)
	honest, honestFiles := branch(t, now-3600, tpl("honest"))
	mirror := newMirror(t, forged, forgedFiles)
	jsdelivr := newMirror(t, honest, honestFiles)
	github := newMirror(t, honest, honestFiles)
	jsdelivr.status, github.status = http.StatusServiceUnavailable, http.StatusServiceUnavailable
	cache := &MemoryCache{}
	client := testClient(t, mirror, mirror.host("jsdmirror", 2), jsdelivr.host("jsdelivr", 1), github.host("github", 0))
	client.Cache = cache

	got, err := client.Template(t.Context())
	if err != nil || string(got.YAML) != direct || got.Base != mirror.srv.URL {
		t.Fatalf("lone mirror: %+v, %v", got, err)
	}
	if _, ok := cache.Get(FloorKey); ok {
		t.Fatal("a single operator raised the floor")
	}

	// jsDelivr and GitHub are back with the honest version, older than the forged one.
	jsdelivr.status, github.status = 0, 0
	got, err = client.Template(t.Context())
	if err != nil || string(got.YAML) != tpl("honest") || got.Version != now-3600 || got.Base != github.srv.URL {
		t.Fatalf("after agreement: %+v, %v", got, err)
	}
	if floor, _ := cache.Get(FloorKey); strings.TrimSpace(string(floor)) != strconv.FormatInt(now-3600, 10) {
		t.Fatalf("floor %q", floor)
	}

	// A version further ahead is refused outright, alone or agreed, and so is a forged floor
	// that a client without this check kept.
	for _, version := range []int64{1 << 62, now + 2*86400} {
		ahead, aheadFiles := branch(t, version, direct)
		mirror.manifest, mirror.files = ahead, aheadFiles
		jsdelivr.manifest, jsdelivr.files = ahead, aheadFiles
		github.status = http.StatusServiceUnavailable
		if _, err := client.Latest(t.Context()); !errors.Is(err, ErrAhead) || !errors.Is(err, ErrNoManifest) {
			t.Fatalf("version %d: err %v, want ErrAhead", version, err)
		}
		github.status = 0
		poisoned := &MemoryCache{}
		poisoned.Put(ManifestPath, ahead)
		poisoned.Put(TemplatePath, []byte(direct))
		poisoned.Put(FloorKey, []byte(strconv.FormatInt(version, 10)))
		fresh := testClient(t, github, github.host("github", 0))
		fresh.Cache, fresh.MinVersion = poisoned, version
		if got, err := fresh.Template(t.Context()); err != nil || got.Version != now-3600 || got.Origin != FromNetwork {
			t.Fatalf("poisoned cache, version %d: %+v, %v", version, got, err)
		}
	}
}

// Save raises the floor only for a version two operators or GitHub served.
func TestSaveRaisesTheFloorWhenTrusted(t *testing.T) {
	cache := &MemoryCache{}
	for _, step := range []struct {
		version int64
		hosts   []string // operators, GitHub 0 hops away and the rest 1
		floor   string
	}{
		{3, []string{"jsdmirror"}, ""},
		{4, []string{"github"}, "4"},
		{5, []string{"jsdmirror", "jsdelivr"}, "5"},
		{6, []string{"jsdelivr", "jsdelivr"}, "5"},
	} {
		v, files := branch(t, step.version, "x")
		var hosts []Host
		var first *mirror
		for _, operator := range step.hosts {
			m := newMirror(t, v, files)
			first = m
			hops := 1
			if operator == "github" {
				hops = 0
			}
			hosts = append(hosts, m.host(operator, hops))
		}
		client := testClient(t, first, hosts...)
		client.Cache = cache
		snap, err := client.Latest(t.Context())
		if err != nil {
			t.Fatalf("version %d: %v", step.version, err)
		}
		snap.Save()
		if floor, _ := cache.Get(FloorKey); strings.TrimSpace(string(floor)) != step.floor {
			t.Fatalf("version %d from %v: floor %q, want %q", step.version, step.hosts, floor, step.floor)
		}
		if m, _ := client.cachedManifest(); m == nil || m.Version != step.version {
			t.Fatalf("version %d: cached manifest %+v", step.version, m)
		}
	}
}

// A rollback does not start the wait for other hosts: the host that answers later with an
// acceptable version is still heard.
func TestLatestSettlesOnlyOnAcceptedAnswers(t *testing.T) {
	v4, files4 := branch(t, 4, "four")
	v6, files6 := branch(t, 6, "six")
	stale := newMirror(t, v4, files4)
	github := newMirror(t, v6, files6)
	github.delay = 300 * time.Millisecond
	for name, setup := range map[string]func(*Client){
		"below the floor":          func(c *Client) { c.MinVersion = 5 },
		"below the cached version": func(c *Client) { v5, _ := branch(t, 5, "five"); c.Cache.Put(ManifestPath, v5) },
	} {
		t.Run(name, func(t *testing.T) {
			client := testClient(t, stale, stale.host("jsdmirror", 2), github.host("github", 0))
			client.Settle = 50 * time.Millisecond
			client.Cache = &MemoryCache{}
			setup(client)
			snap, err := client.Latest(t.Context())
			if err != nil || snap.Manifest.Version != 6 {
				t.Fatalf("snapshot %+v, err %v", snap, err)
			}
		})
	}
}

// The template names the host fewest hops from the branch that serves the chosen version;
// downloads still go to the fastest first.
func TestBaseIsTheHostFewestHopsAway(t *testing.T) {
	v2, files2 := branch(t, 2, tpl("two"))
	v1, files1 := branch(t, 1, tpl("one"))
	mirror := newMirror(t, v2, files2)
	jsdelivr := newMirror(t, v2, files2)
	jsdelivr.delay = 30 * time.Millisecond
	github := newMirror(t, v2, files2)
	github.delay = 60 * time.Millisecond
	client := testClient(t, mirror, mirror.host("jsdmirror", 2), jsdelivr.host("jsdelivr", 1), github.host("github", 0))
	client.Settle = time.Second

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(bases(snap.Hosts), " "); got != strings.Join([]string{mirror.srv.URL, jsdelivr.srv.URL, github.srv.URL}, " ") {
		t.Fatalf("ranking %v", got)
	}
	if snap.Base() != github.srv.URL {
		t.Fatalf("base %s, want GitHub's", snap.Base())
	}

	// GitHub serves another version: of the two that agree, jsDelivr is closer.
	github.manifest, github.files = v1, files1
	got, err := client.Template(t.Context())
	if err != nil || got.Version != 2 || got.Base != jsdelivr.srv.URL {
		t.Fatalf("%+v, %v", got, err)
	}
}

// A template this client refuses is neither cached nor saved with its manifest: the last good
// one stays.
func TestTemplateValidatesBeforeCaching(t *testing.T) {
	v2, files2 := branch(t, 2, tpl("two"))
	bad := tpl("three") + "port: 7890\n"
	v3, files3 := branch(t, 3, bad)
	a := newMirror(t, v2, files2)
	b := newMirror(t, v2, files2)
	cache := &MemoryCache{}
	client := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	client.Cache = cache
	if _, err := client.Template(t.Context()); err != nil {
		t.Fatal(err)
	}

	a.manifest, a.files, b.manifest, b.files = v3, files3, v3, files3
	got, err := client.Template(t.Context())
	if err != nil || got.Origin != FromCache || got.Version != 2 || string(got.YAML) != tpl("two") || !errors.Is(got.Err, ErrInvalidTemplate) {
		t.Fatalf("%+v, %v", got, err)
	}
	manifest, _ := cache.Get(ManifestPath)
	template, _ := cache.Get(TemplatePath)
	floor, _ := cache.Get(FloorKey)
	if string(manifest) != string(v2) || string(template) != tpl("two") || strings.TrimSpace(string(floor)) != "2" {
		t.Fatalf("cache changed: manifest %.40q, template %.40q, floor %q", manifest, template, floor)
	}

	// Without a cached template there is none.
	fresh := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	if _, err := fresh.Template(t.Context()); !errors.Is(err, ErrNoTemplate) || !errors.Is(err, ErrInvalidTemplate) {
		t.Fatalf("err %v", err)
	}
}

func TestLatestStopsWaitingAfterSettle(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	fast := newMirror(t, v2, files2)
	hung := newMirror(t, v2, files2)
	hung.delay = time.Minute
	client := testClient(t, fast, fast.host("jsdelivr", 1), hung.host("github", 0))
	before := runtime.NumGoroutine()

	start := time.Now()
	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v", elapsed)
	}
	// The hung host was not heard from: it ranks after the one that answered.
	if got := bases(snap.Hosts); len(got) != 2 || got[0] != fast.srv.URL {
		t.Fatalf("ranking %v", got)
	}
	waitFor(t, func() bool { return hung.canceled.Load() == 1 }, "the hung request is canceled")
	waitFor(t, func() bool { return runtime.NumGoroutine() <= before }, "goroutines end")
}

func TestLatestReturnsWhenCanceled(t *testing.T) {
	hung := newMirror(t, nil, nil)
	hung.delay = time.Minute
	client := testClient(t, hung, hung.host("github", 0))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	if _, err := client.Latest(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
}

func TestLatestBoundsConcurrency(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	m := newMirror(t, v2, files2)
	m.delay = 20 * time.Millisecond
	client := testClient(t, m, m.host("a", 1), m.host("b", 1), m.host("c", 1))
	client.Parallel = 1
	client.Settle = time.Second

	if _, err := client.Latest(t.Context()); err != nil {
		t.Fatal(err)
	}
	if m.peak.Load() != 1 || m.hits.Load() != 3 {
		t.Fatalf("peak %d of %d requests, want 1 of 3", m.peak.Load(), m.hits.Load())
	}
}

func TestLatestReportsEveryHost(t *testing.T) {
	broken := newMirror(t, nil, nil)
	broken.status = http.StatusInternalServerError
	html := newMirror(t, []byte("<html>blocked</html>"), nil)
	client := testClient(t, broken, broken.host("a", 1), html.host("b", 1))

	_, err := client.Latest(t.Context())
	var hostErr *HostError
	if !errors.Is(err, ErrNoManifest) || !errors.Is(err, ErrInvalidManifest) || !errors.As(err, &hostErr) {
		t.Fatalf("err %v", err)
	}
}

func TestFetchFallsBackAndChecks(t *testing.T) {
	v2, files2 := branch(t, 2, "two")
	tamperedFiles := map[string][]byte{TemplatePath: []byte("twO")}
	tampered := newMirror(t, v2, tamperedFiles)
	oversized := newMirror(t, v2, map[string][]byte{TemplatePath: []byte("two and more")})
	good := newMirror(t, v2, files2)
	good.delay = 30 * time.Millisecond
	cache := &MemoryCache{}
	client := testClient(t, good, tampered.host("a", 1), oversized.host("b", 1), good.host("c", 0))
	client.Cache = cache

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	data, err := snap.Fetch(t.Context(), TemplatePath)
	if err != nil || string(data) != "two" {
		t.Fatalf("got %q, %v", data, err)
	}
	if cached, _ := cache.Get(TemplatePath); string(cached) != "two" {
		t.Fatalf("cached %q", cached)
	}

	// Served from the cache now.
	hits := good.hits.Load()
	if _, err := snap.Fetch(t.Context(), TemplatePath); err != nil || good.hits.Load() != hits {
		t.Fatalf("not from the cache: %v", err)
	}

	if _, err := snap.Fetch(t.Context(), "nope.txt"); !errors.Is(err, ErrNotListed) {
		t.Fatalf("err %v", err)
	}
}

func TestFetchRejectsTamperedAndOversizedFiles(t *testing.T) {
	v2, _ := branch(t, 2, "two")
	tampered := newMirror(t, v2, map[string][]byte{TemplatePath: []byte("twO")})
	oversized := newMirror(t, v2, map[string][]byte{TemplatePath: []byte("two and more")})
	client := testClient(t, tampered, tampered.host("a", 1), oversized.host("b", 1))

	snap, err := client.Latest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = snap.Fetch(t.Context(), TemplatePath)
	if !errors.Is(err, ErrDigest) || !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err %v, want ErrDigest and ErrTooLarge", err)
	}
}

func TestTemplateDegrades(t *testing.T) {
	two := tpl("two")
	v2, files2 := branch(t, 2, two)
	a := newMirror(t, v2, files2)
	b := newMirror(t, v2, files2)
	cache := &MemoryCache{}
	client := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	client.Cache = cache

	got, err := client.Template(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(got.YAML) != two || got.Version != 2 || got.Origin != FromNetwork || got.Err != nil || got.Base != b.srv.URL {
		t.Fatalf("%+v", got)
	}
	if raw, ok := cache.Get(ManifestPath); !ok || string(raw) != string(v2) {
		t.Fatal("manifest not cached")
	}

	a.status, b.status = http.StatusServiceUnavailable, http.StatusServiceUnavailable
	got, err = client.Template(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The cached template names the configured host fewest hops away.
	if got.Origin != FromCache || string(got.YAML) != two || got.Version != 2 || got.Base != b.srv.URL || !errors.Is(got.Err, ErrNoManifest) {
		t.Fatalf("%+v", got)
	}

	// A client that never got the template.
	fresh := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	fresh.Cache = &MemoryCache{}
	if _, err := fresh.Template(t.Context()); !errors.Is(err, ErrNoTemplate) || !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err %v", err)
	}
}

// tpl is a valid template told apart by a comment.
func tpl(label string) string { return "# " + label + "\n" + validTemplate }

func bases(hosts []Host) []string {
	var out []string
	for _, h := range hosts {
		out = append(out, h.Base)
	}
	return out
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
