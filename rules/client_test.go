package rules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
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

	// The cached manifest's version counts as seen.
	v5, _ := branch(t, 5, "five")
	client.MinVersion = 0
	client.Cache = &MemoryCache{}
	client.Cache.Put(ManifestPath, v5)
	if _, err := client.Latest(t.Context()); !errors.Is(err, ErrRollback) {
		t.Fatalf("err %v, want ErrRollback", err)
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
	v2, files2 := branch(t, 2, "two")
	a := newMirror(t, v2, files2)
	b := newMirror(t, v2, files2)
	cache := &MemoryCache{}
	client := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	client.Cache = cache

	tpl, err := client.Template(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(tpl.YAML) != "two" || tpl.Version != 2 || tpl.Origin != FromNetwork || tpl.Err != nil {
		t.Fatalf("%+v", tpl)
	}
	if raw, ok := cache.Get(ManifestPath); !ok || string(raw) != string(v2) {
		t.Fatal("manifest not cached")
	}

	a.status, b.status = http.StatusServiceUnavailable, http.StatusServiceUnavailable
	tpl, err = client.Template(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tpl.Origin != FromCache || string(tpl.YAML) != "two" || tpl.Version != 2 || tpl.Base != a.srv.URL || !errors.Is(tpl.Err, ErrNoManifest) {
		t.Fatalf("%+v", tpl)
	}

	// A client that never got the template.
	fresh := testClient(t, a, a.host("jsdmirror", 2), b.host("github", 0))
	fresh.Cache = &MemoryCache{}
	if _, err := fresh.Template(t.Context()); !errors.Is(err, ErrNoTemplate) || !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err %v", err)
	}
}

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
