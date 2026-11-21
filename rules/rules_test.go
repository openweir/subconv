package rules

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	good, _ := branch(t, 7, "seven")
	m, err := ParseManifest(good)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := m.File(TemplatePath); !ok || !f.Matches([]byte("seven")) {
		t.Fatalf("template %+v", f)
	}

	sha := strings.Repeat("a", 64)
	for name, body := range map[string]string{
		"not JSON":   `<html>`,
		"no version": `{"files":[]}`,
		"dot path": `{"version":1,"files":[{"path":"template.yaml","size":1,"sha256":"` + sha + `"},
			{"path":"../x","size":1,"sha256":"` + sha + `"}]}`,
		"short digest": `{"version":1,"files":[{"path":"template.yaml","size":1,"sha256":"abc"}]}`,
		"no template":  `{"version":1,"files":[{"path":"x","size":1,"sha256":"` + sha + `"}]}`,
	} {
		if _, err := ParseManifest([]byte(body)); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestFill(t *testing.T) {
	tpl := []byte(`url: "{rules}/providers/a.mrs"` + "\n" + `url: "{rules}/providers/b.txt"`)
	got, err := Fill(tpl, DefaultHosts()[0].Base+"/")
	if err != nil {
		t.Fatal(err)
	}
	want := `url: "https://cdn.jsdmirror.com/gh/openweir/subconv@rules/providers/a.mrs"` + "\n" +
		`url: "https://cdn.jsdmirror.com/gh/openweir/subconv@rules/providers/b.txt"`
	if string(got) != want {
		t.Fatalf("got\n%s", got)
	}
	for _, base := range []string{"", "ftp://x", "https://x/a b", `https://x/"`, "https://x/?q=1", "/relative", "https://x/{rules}"} {
		if _, err := Fill(tpl, base); !errors.Is(err, ErrInvalidBase) {
			t.Errorf("%q: err %v", base, err)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, p := range []string{"manifest.json", "providers/dler/media/disney-plus.domain.mrs", "LICENSES/AGPL-3.0.txt"} {
		if !ValidPath(p) {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"", "/abs", "a//b", "a/../b", "./a", "a b", "a/b/", `a\b`, "a%20b"} {
		if ValidPath(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

const validTemplate = `
proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto, DIRECT]
    include-all: true
  - name: Auto
    type: url-test
    include-all: true
    filter: (?i)(^|[^a-z])hk([^a-z]|$)|香港
  - name: Domestic
    type: select
    proxies: [DIRECT, Proxy]
rule-providers:
  LAN:
    type: http
    behavior: ipcidr
    format: mrs
    url: "{rules}/providers/dler/lan.ipcidr.mrs"
    path: ./rules/openweir/dler/lan.ipcidr.mrs
    interval: 86400
rules:
  - RULE-SET,LAN,DIRECT,no-resolve
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT
  - GEOIP,CN,Domestic
  - MATCH,Proxy
`

func TestValidate(t *testing.T) {
	if err := Validate([]byte(validTemplate)); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string][2]string{
		"proxies":           {"proxy-groups:", "proxies: []\nproxy-groups:"},
		"unknown key":       {"    include-all: true\n  - name: Auto", "    include-all: true\n    use: [x]\n  - name: Auto"},
		"unknown member":    {"[DIRECT, Proxy]", "[DIRECT, Proxies]"},
		"loop":              {"proxies: [Auto, DIRECT]", "proxies: [Auto, Domestic]"},
		"no nodes":          {"    proxies: [DIRECT, Proxy]\n", ""},
		"word boundary":     {"(^|[^a-z])hk([^a-z]|$)", `\bhk\b`},
		"backquote":         {"|香港", "`香港"},
		"bad regexp":        {"|香港", "|(香港"},
		"off branch":        {`"{rules}/providers`, `"https://example.com/providers`},
		"classical mrs":     {"behavior: ipcidr", "behavior: classical"},
		"parent path":       {"path: ./rules/", "path: ../rules/"},
		"unknown provider":  {"RULE-SET,LAN,", "RULE-SET,WAN,"},
		"unused provider":   {"  - RULE-SET,LAN,DIRECT,no-resolve\n", ""},
		"unknown policy":    {"GEOIP,CN,Domestic", "GEOIP,CN,China"},
		"no match":          {"  - MATCH,Proxy\n", ""},
		"match not last":    {"  - GEOIP,CN,Domestic\n", "  - MATCH,Proxy\n  - GEOIP,CN,Domestic\n"},
		"sub-rule":          {"GEOIP,CN,Domestic", "SUB-RULE,(NETWORK,UDP),Domestic"},
		"built-in as group": {"name: Domestic", "name: DIRECT"},
	} {
		changed := strings.Replace(validTemplate, edit[0], edit[1], 1)
		if changed == validTemplate {
			t.Fatalf("%s: edit does not apply", name)
		}
		if err := Validate([]byte(changed)); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

// Client settings, like those of dler-io's Head*.yaml, never pass.
func TestValidateRefusesClientSettings(t *testing.T) {
	for _, extra := range []string{
		"port: 6152", "socks-port: 6153", "mixed-port: 8899", "redir-port: 7892", "tproxy-port: 7893",
		"allow-lan: true", "bind-address: '*'", "mode: rule", "log-level: info", "ipv6: true",
		"external-controller: 127.0.0.1:9090", "external-ui: ui", "secret: dler",
		"dns: {enable: true, listen: 0.0.0.0:1053}", "tun: {enable: true}", "profile: {store-selected: true}",
		"sniffer: {enable: true}", "experimental: {ignore-resolve-fail: true}", "hosts: {a.com: 1.1.1.1}",
		"proxies: []", "proxy-providers: {}", "listeners: []", "sub-rules: {}", "tunnels: []",
		"geox-url: {}", "authentication: [u:p]", "interface-name: eth0", "routing-mark: 1",
		"<<: {port: 6152}", "---\nport: 6152",
	} {
		tpl := strings.Replace(extra, "\\n", "\n", 1) + "\n" + validTemplate
		if strings.HasPrefix(extra, "---") {
			tpl = validTemplate + "\n---\nport: 6152\n"
		}
		if err := Validate([]byte(tpl)); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: err %v", extra, err)
		}
	}
}

func TestInfoFilter(t *testing.T) {
	info := regexp.MustCompile(InfoFilter)
	for _, name := range []string{"剩余流量：10.5 GB", "套餐到期：2026-12-01", "Expire: 2026-12-01", "Traffic left 3 GB", "官网 example.com", "Website: example.com", "距离下次重置剩余：3 天"} {
		if !info.MatchString(name) {
			t.Errorf("%q kept", name)
		}
	}
	for _, name := range []string{"🇭🇰 HK 01", "日本 03 | 1x", "US-Seattle", "新加坡 IEPL"} {
		if info.MatchString(name) {
			t.Errorf("%q excluded", name)
		}
	}
	if !termsInOrder(InfoFilter) {
		t.Error("InfoFilter: English terms first, then Chinese")
	}
}

func TestSplitRule(t *testing.T) {
	got := SplitRule("AND,((DOMAIN,a.com),(NETWORK,UDP)),Proxy, no-resolve")
	want := []string{"AND", "((DOMAIN,a.com),(NETWORK,UDP))", "Proxy", "no-resolve"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
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
