package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/openweir/subconv/rules"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

// A layout as dler-io writes them: the rules' items without "rules:", then the providers. The
// client settings around them, like those of dler-io's Head*.yaml, must never reach a template.
const layout = `  - RULE-SET,Reject,REJECT
  - RULE-SET,Reject IP,REJECT
  - RULE-SET,Big,Proxy
  - RULE-SET,China IP,Domestic
  - DOMAIN,apps.apple.com , Proxy
  - RULE-SET,LAN,Local
  - GEOIP,CN,Domestic
  - MATCH,Others

rule-providers:
  Reject:
    type: http
    behavior: domain
    format: text
    url: 'https://sukka.example/Clash/domainset/reject.txt'
  Reject IP:
    type: http
    behavior: ipcidr
    format: text
    url: 'https://sukka.example/Clash/ip/reject.txt'
  China IP:
    type: http
    behavior: ipcidr
    format: text
    url: 'https://sukka.example/Clash/ip/china_ip.txt'
  Big:
    type: http
    behavior: classical
    url: 'https://fastly.jsdelivr.net/gh/dler/Rules@main/Clash/Provider/Big%20One.yaml'
  LAN:
    type: http
    behavior: classical
    url: 'https://fastly.jsdelivr.net/gh/dler/Rules@main/Clash/Provider/LAN.yaml'

port: 6152
socks-port: 6153
mixed-port: 8899
external-controller: 127.0.0.1:9090
secret: dler
dns:
  enable: true
  listen: 0.0.0.0:1053
tun:
  enable: true
proxies:
  - {name: x, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}
`

var upstreamFiles = map[string]string{
	"Clash/Rule.yaml": layout,
	"Clash/Provider/Big One.yaml": `payload:
  # > Big
  - DOMAIN,a.example
  - DOMAIN-SUFFIX,b.example
  - DOMAIN-SUFFIX,c.example
  - DOMAIN-SUFFIX,b.example
  - DOMAIN-KEYWORD,tracker
  - PROCESS-NAME,qbittorrent
  - USER-AGENT,Telegram*
  - IP-CIDR,91.108.4.0/22,no-resolve
  - IP-CIDR6,2001:b28:f23d::/48,no-resolve
  - IP-CIDR,1.2.3.4,no-resolve
`,
	"Clash/Provider/LAN.yaml": `payload:
  - DOMAIN-SUFFIX,local
  - IP-CIDR,10.0.0.0/8
`,
	"Clash/Head.yaml": "port: 6152\nsecret: dler\n",
}

var sukkaFiles = map[string]string{
	"/Clash/domainset/reject.txt": "# Sukka's Ruleset - Reject Base\n# License: AGPL 3.0\n#\nads.example\n+.tracker.example\n.sub.example\nbad entry\n",
	"/Clash/ip/reject.txt":        "# License: AGPL 3.0\nDOMAIN,canary.example\nIP-CIDR,10.72.25.0/24,no-resolve\nIP-CIDR,1.0.218.230/32\nIP-ASN,4134\n",
	"/Clash/ip/china_ip.txt":      "# Mainland China IPv4 CIDR\n# License: CC BY-SA 2.0\n1.0.1.0/24\n1.0.2.0/23\n",
}

const testConfig = `
max-size: 65536
max-shrink: 0.5
split-min: 3
interval: 86400
provider-path: ./rules/openweir
sources:
  - name: dler-io/Rules
    home: https://github.com/dler/Rules
    refs: [https://fastly.jsdelivr.net/gh/dler/Rules@main/]
    commit: {{server}}/api/commit
    archive: {{server}}/archive/{commit}.tar.gz
    fetch: https://raw.githubusercontent.com/dler/Rules/{commit}/
    output: dler
    strip: Clash/Provider/
    license: LicenseRef-dler
    notice: Redistribution permitted.
  - name: Sukka's Ruleset
    home: https://sukka.example
    refs: [https://sukka.example/]
    fetch: {{server}}/sukka/
    output: sukka
    strip: Clash/
    license: AGPL-3.0
    license-header: true
    notice: Sukka.
licenses:
  - id: AGPL-3.0
    names: [AGPL 3.0]
    text: {{server}}/license
  - id: CC-BY-SA-2.0
    names: [CC BY-SA 2.0]
    uri: https://creativecommons.org/licenses/by-sa/2.0/
  - id: LicenseRef-dler
template:
  layout: https://fastly.jsdelivr.net/gh/dler/Rules@main/Clash/Rule.yaml
  description: Test.
  policies: {Local: DIRECT}
  groups:
    - {name: Proxy, type: select, proxies: [Auto, DIRECT], include-all: true}
    - {name: Auto, type: url-test, include-all: true, exclude-filter: "{info}"}
    - {name: Domestic, type: select, proxies: [DIRECT, Proxy]}
    - {name: Others, type: select, proxies: [Proxy, Domestic]}
notice: "# Notices"
readme: "# Rules"
`

type upstream struct {
	srv    *httptest.Server
	files  map[string]string // served under /sukka/
	config string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{files: map[string]string{}}
	for k, v := range sukkaFiles {
		u.files[k] = v
	}
	archive := tarball(t, upstreamFiles)
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/api/commit":
			io.WriteString(w, commit)
		case p == "/archive/"+commit+".tar.gz":
			w.Write(archive)
		case p == "/license":
			io.WriteString(w, "GNU AFFERO GENERAL PUBLIC LICENSE\n")
		case strings.HasPrefix(p, "/sukka/"):
			body, ok := u.files[strings.TrimPrefix(p, "/sukka")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(u.srv.Close)
	u.config = strings.ReplaceAll(testConfig, "{{server}}", u.srv.URL)
	return u
}

func tarball(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "Rules-" + commit + "/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	gz.Close()
	return buf.Bytes()
}

// fakeMRS stands in for mihomo: it writes a digest of the text.
func fakeMRS(_ context.Context, behavior, src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return os.WriteFile(dst, []byte("MRS "+behavior+" "+hex.EncodeToString(sum[:])), 0o644)
}

func (u *upstream) build(t *testing.T, now time.Time, prev *rules.Manifest) (string, []string, error) {
	t.Helper()
	cfg, err := parseConfig([]byte(u.config))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	b := &builder{
		cfg:     cfg,
		fetch:   &fetcher{http: u.srv.Client(), maxSize: cfg.MaxSize, retries: 1, backoff: time.Millisecond},
		convert: fakeMRS,
		out:     out,
		now:     now,
		prev:    prev,
		log:     io.Discard,
	}
	changed, err := b.build(t.Context())
	return out, changed, err
}

func read(t *testing.T, dir, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBuild(t *testing.T) {
	u := newUpstream(t)
	now := time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)
	out, changed, err := u.build(t, now, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := read(t, out, rules.TemplatePath)
	if err := rules.Validate([]byte(template)); err != nil {
		t.Fatalf("%v\n%s", err, template)
	}
	for _, setting := range []string{"port", "secret", "dns", "tun", "external-controller", "\nproxies:", "1053", "6152"} {
		if strings.Contains(template, setting) {
			t.Errorf("template carries %q:\n%s", setting, template)
		}
	}
	wantRules := `rules:
  - RULE-SET,Reject,REJECT
  - RULE-SET,Reject IP,REJECT
  - RULE-SET,Big,Proxy
  - RULE-SET,Big (classical),Proxy
  - RULE-SET,Big (IP),Proxy,no-resolve
  - RULE-SET,China IP,Domestic
  - DOMAIN,apps.apple.com,Proxy
  - RULE-SET,LAN,DIRECT
  - GEOIP,CN,Domestic
  - MATCH,Others
`
	if !strings.HasSuffix(template, wantRules) {
		t.Errorf("rules:\n%s", template)
	}
	for _, provider := range []string{
		"Big (IP):\n    type: http\n    behavior: ipcidr\n    format: mrs\n    url: \"{rules}/providers/dler/big-one.ipcidr.mrs\"\n    path: ./rules/openweir/dler/big-one.ipcidr.mrs\n    interval: 86400\n",
		"LAN:\n    type: http\n    behavior: classical\n    format: text\n    url: \"{rules}/providers/dler/lan.classical.txt\"\n",
		"proxies: [Auto, DIRECT]",
		"exclude-filter: " + rules.InfoFilter + "\n",
	} {
		if !strings.Contains(template, provider) {
			t.Errorf("no %q in\n%s", provider, template)
		}
	}

	for path, want := range map[string]string{
		"providers/dler/big-one.domain.txt":           "a.example\n+.b.example\n+.c.example\n",
		"providers/dler/big-one.classical.txt":        "DOMAIN-KEYWORD,tracker\nPROCESS-NAME,qbittorrent\n",
		"providers/dler/big-one.ipcidr.txt":           "91.108.4.0/22\n2001:b28:f23d::/48\n1.2.3.4/32\n",
		"providers/dler/lan.classical.txt":            "DOMAIN-SUFFIX,local\nIP-CIDR,10.0.0.0/8\n",
		"providers/sukka/domainset/reject.domain.txt": "ads.example\n+.tracker.example\n.sub.example\n",
		"providers/sukka/ip/reject.ipcidr.txt":        "10.72.25.0/24\n1.0.218.230/32\n",
	} {
		got := read(t, out, path)
		if _, entries, _ := strings.Cut(got, "Converted by github.com/openweir/subconv (cmd/rules).\n"); entries != want {
			t.Errorf("%s:\n%s", path, got)
		}
	}
	if got := read(t, out, "providers/dler/big-one.domain.mrs"); !strings.HasPrefix(got, "MRS domain ") {
		t.Errorf("mrs %q", got)
	}

	m, err := rules.ParseManifest([]byte(read(t, out, rules.ManifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.File(rules.TemplatePath); m.Version != now.Unix() || !ok {
		t.Fatalf("manifest %+v", m)
	}
	f, _ := m.File("providers/sukka/ip/china_ip.ipcidr.mrs")
	if f.License != "CC-BY-SA-2.0" || f.Entries != 2 || f.Source != u.srv.URL+"/sukka/Clash/ip/china_ip.txt" || f.Retrieved != "2026-11-21" {
		t.Errorf("china_ip %+v", f)
	}
	f, _ = m.File("providers/dler/big-one.domain.mrs")
	if f.License != "LicenseRef-dler" || f.Source != "https://raw.githubusercontent.com/dler/Rules/"+commit+"/Clash/Provider/Big%20One.yaml" {
		t.Errorf("big-one %+v", f)
	}
	if read(t, out, "LICENSES/AGPL-3.0.txt") == "" {
		t.Error("no AGPL text")
	}
	notice := read(t, out, "NOTICE.md")
	for _, want := range []string{"## dler-io/Rules\n\n<https://github.com/dler/Rules>. License: LicenseRef-dler.", "`providers/sukka/ip/china_ip.*`: CC-BY-SA-2.0", "- CC-BY-SA-2.0: <https://creativecommons.org/licenses/by-sa/2.0/>"} {
		if !strings.Contains(notice, want) {
			t.Errorf("NOTICE.md lacks %q:\n%s", want, notice)
		}
	}
	if len(changed) != len(m.Files)+1 || changed[len(changed)-1] != rules.ManifestPath {
		t.Errorf("changed %v", changed)
	}

	// Nothing changes upstream: nothing to publish.
	_, changed, err = u.build(t, now.Add(24*time.Hour), m)
	if err != nil || len(changed) != 0 {
		t.Fatalf("changed %v, %v", changed, err)
	}

	// One file changes: it and the manifest, with only its date moving.
	u.files["/Clash/ip/china_ip.txt"] += "1.0.8.0/21\n"
	out, changed, err = u.build(t, now.Add(48*time.Hour), m)
	if err != nil {
		t.Fatal(err)
	}
	want := "providers/sukka/ip/china_ip.ipcidr.mrs providers/sukka/ip/china_ip.ipcidr.txt manifest.json"
	if strings.Join(changed, " ") != want {
		t.Fatalf("changed %v", changed)
	}
	m2, _ := rules.ParseManifest([]byte(read(t, out, rules.ManifestPath)))
	if f, _ := m2.File("providers/sukka/ip/china_ip.ipcidr.txt"); f.Updated != "2026-11-23" {
		t.Errorf("updated %s", f.Updated)
	}
	if f, _ := m2.File(rules.TemplatePath); f.Updated != "2026-11-21" {
		t.Errorf("updated %s", f.Updated)
	}
}

func TestBuildRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(u *upstream)
		want string
	}{
		"web page": {func(u *upstream) {
			u.files["/Clash/ip/china_ip.txt"] = "<!DOCTYPE html><html><body>Rate limited</body></html>"
		}, "web page"},
		"empty set": {func(u *upstream) {
			u.files["/Clash/ip/china_ip.txt"] = "# License: CC BY-SA 2.0\n# nothing\n"
		}, "no usable entries"},
		"unknown license": {func(u *upstream) {
			u.files["/Clash/ip/china_ip.txt"] = "# License: WTFPL\n1.0.1.0/24\n"
		}, "unknown license"},
		"missing group": {func(u *upstream) {
			u.config = strings.Replace(u.config, "{name: Others, type: select, proxies: [Proxy, Domestic]}", "{name: Rest, type: select, proxies: [Proxy, Domestic]}", 1)
		}, `unknown policy "Others"`},
		"unused group": {func(u *upstream) {
			u.config = strings.Replace(u.config, "    - {name: Others,", "    - {name: Spare, type: select, proxies: [Proxy]}\n    - {name: Others,", 1)
		}, "group Spare is not used"},
		"stale policy": {func(u *upstream) {
			u.config = strings.Replace(u.config, "policies: {Local: DIRECT}", "policies: {Local: DIRECT, Gone: Proxy}", 1)
		}, "no rule sends traffic to Gone"},
		"foreign rule set": {func(u *upstream) {
			u.config = strings.Replace(u.config, "refs: [https://sukka.example/]", "refs: [https://other.example/]", 1)
		}, "not from a configured source"},
		"oversized": {func(u *upstream) {
			u.files["/Clash/ip/china_ip.txt"] = "# License: CC BY-SA 2.0\n" + strings.Repeat("1.0.1.0/24\n", 7000)
		}, "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			u := newUpstream(t)
			tc.edit(u)
			_, _, err := u.build(t, time.Now(), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildRefusesShrinking(t *testing.T) {
	u := newUpstream(t)
	now := time.Now()
	out, _, err := u.build(t, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := rules.ParseManifest([]byte(read(t, out, rules.ManifestPath)))
	for i := range m.Files {
		if m.Files[i].Path == "providers/sukka/ip/china_ip.ipcidr.mrs" {
			m.Files[i].Entries = 5
		}
	}
	if _, _, err := u.build(t, now.Add(time.Hour), m); err == nil || !strings.Contains(err.Error(), "shrank from 5 to 2") {
		t.Fatalf("err %v", err)
	}
}

func TestParseRuleSet(t *testing.T) {
	parts, whole, dropped, err := parseRuleSet([]byte("payload:\n  - DOMAIN-SUFFIX,.a.com\n  - IP-CIDR,10.0.0.0/8\n  - IP-CIDR,11.0.0.0/8,no-resolve\n  - IP-CIDR,12.0.0.0/8,no-resolve,src\n  - DOMAIN,bad host\n  - URL-REGEX,^http\n"), "classical", "yaml")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range parts {
		got = append(got, p.kind+"="+strings.Join(p.entries, " "))
	}
	want := "domain=+.a.com|classical=IP-CIDR,12.0.0.0/8,no-resolve,src|ipcidr=11.0.0.0/8|ipcidr-resolve=10.0.0.0/8"
	if strings.Join(got, "|") != want {
		t.Errorf("parts %v", got)
	}
	if !parts[2].noResolve || parts[3].noResolve {
		t.Error("no-resolve")
	}
	if len(whole.entries) != 4 || dropped["invalid"] != 1 || dropped["URL-REGEX"] != 1 {
		t.Errorf("whole %v, dropped %v", whole.entries, dropped)
	}
}

// The real config loads, and its groups follow the template schema.
func TestConfig(t *testing.T) {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tpl := cfg.Template
	var groups strings.Builder
	groups.WriteString("proxy-groups:\n")
	for _, g := range tpl.Groups {
		groups.WriteString("  - {name: " + g.Name + ", type: " + g.Type + ", proxies: [DIRECT]}\n")
	}
	doc := []byte(groups.String() + "rules:\n  - MATCH," + tpl.Policies["Others"] + "\n")
	if err := rules.Validate(doc); err != nil {
		t.Fatal(err)
	}
	for _, g := range tpl.Groups {
		for _, f := range []string{g.Filter, g.ExcludeFilter} {
			if !termsInOrder(f) {
				t.Errorf("%s: English terms first, then Chinese, then flags: %s", g.Name, f)
			}
		}
		if g.IncludeAll && g.ExcludeFilter != rules.InfoFilter {
			t.Errorf("%s does not exclude rules.InfoFilter", g.Name)
		}
	}
	data, err := renderTemplate(tpl, cfg.Sources[0], "x", &yaml.Node{Kind: yaml.MappingNode}, []string{"MATCH," + tpl.Policies["Others"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.Validate(data); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
}

// termsInOrder checks that a filter lists English terms first, then Chinese, then flags.
func termsInOrder(filter string) bool {
	class := func(term string) int {
		c := 0
		for _, r := range term {
			switch {
			case r >= 0x1F000:
				return 2
			case r >= 0x80:
				c = 1
			}
		}
		return c
	}
	last, depth, start := 0, 0, 0
	filter = strings.TrimPrefix(filter, "(?i)")
	for i := 0; i <= len(filter); i++ {
		if i < len(filter) && filter[i] != '|' {
			switch filter[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			continue
		}
		if depth > 0 {
			continue
		}
		c := class(filter[start:i])
		if c < last {
			return false
		}
		last, start = c, i+1
	}
	return true
}
