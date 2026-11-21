package subconv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/openweir/subconv/rules"
)

// A routing template as the rules branch serves it, with emoji names, a filtered group and a
// rule provider on the branch.
const testTemplate = `proxy-groups:
  - name: "🚀 Proxy"
    type: select
    proxies: [♻️ Auto, DIRECT]
    include-all: true
    exclude-filter: (?i)expire|traffic|剩余
  - name: ♻️ Auto
    type: url-test
    include-all: true
    exclude-filter: (?i)expire|traffic|剩余
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: "🇭🇰 Hong Kong"
    type: url-test
    include-all: true
    filter: (?i)hk|香港
  - name: "🎯 Domestic"
    type: select
    proxies: [DIRECT, "🚀 Proxy"]
rule-providers:
  LAN:
    type: http
    behavior: classical
    format: text
    url: "{rules}/providers/dler/lan.classical.txt"
    path: ./rules/openweir/dler/lan.classical.txt
    interval: 86400
rules:
  - RULE-SET,LAN,DIRECT
  - "DOMAIN-SUFFIX,hk.example,🇭🇰 Hong Kong"
  - "GEOIP,CN,🎯 Domestic"
  - "MATCH,🚀 Proxy"
`

// branch serves a rules branch with the template; status, when set, is its answer instead.
type branch struct {
	srv    *httptest.Server
	status int
}

func newBranch(t *testing.T, template string) *branch {
	t.Helper()
	sum := sha256.Sum256([]byte(template))
	manifest, err := json.Marshal(rules.Manifest{
		Version: 42,
		Files: []rules.File{{Path: rules.TemplatePath, Size: int64(len(template)), SHA256: hex.EncodeToString(sum[:]),
			Updated: "2026-11-21", Kind: "template"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &branch{}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case b.status != 0:
			w.WriteHeader(b.status)
		case r.URL.Path == "/"+rules.ManifestPath:
			w.Write(manifest)
		case r.URL.Path == "/"+rules.TemplatePath:
			w.Write([]byte(template))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *branch) client() *rules.Client {
	return &rules.Client{HTTP: b.srv.Client(), Hosts: []rules.Host{{Base: b.srv.URL, Operator: "test"}}}
}

const clashWithRules = `proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: p}
  - {name: JP 01, type: ss, server: jp.example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Mine, type: select, proxies: [HK 01, JP 01]}
rules:
  - DOMAIN-SUFFIX,a.example,Mine
  - DOMAIN-SUFFIX,b.example,Mine
  - DOMAIN-SUFFIX,c.example,Mine
  - DOMAIN-SUFFIX,d.example,Mine
  - DOMAIN-SUFFIX,e.example,Mine
  - DOMAIN-SUFFIX,f.example,Mine
  - DOMAIN-SUFFIX,g.example,Mine
  - DOMAIN-SUFFIX,h.example,Mine
  - DOMAIN-SUFFIX,i.example,Mine
  - MATCH,Mine
`

const linkList = "ss://YWVzLTEyOC1nY206cA@hk.example.com:8388#HK%2001\n" +
	"ss://YWVzLTEyOC1nY206cA@jp.example.com:8388#JP%2001\n" +
	"ss://YWVzLTEyOC1nY206cA@info.example.com:8388#%E5%89%A9%E4%BD%99%E6%B5%81%E9%87%8F%EF%BC%9A10GB\n" +
	"ss://YWVzLTEyOC1nY206cA@hk2.example.com:8388#%E9%A6%99%E6%B8%AF%2002\n"

func TestBuildDecides(t *testing.T) {
	b := newBranch(t, testTemplate)
	for name, tc := range map[string]struct {
		body, choice, want string
	}{
		"no rules":          {linkList, RulesAuto, TemplateNoRules},
		"no MATCH":          {strings.Replace(clashWithRules, "  - MATCH,Mine\n", "", 1), RulesAuto, TemplateNoMatch},
		"MATCH gone":        {strings.Replace(clashWithRules, "MATCH,Mine", "MATCH,Gone", 1), RulesAuto, TemplateNoMatch},
		"too many dropped":  {strings.NewReplacer("DOMAIN-SUFFIX,a.example", "USER-AGENT,a", "DOMAIN-SUFFIX,b.example", "USER-AGENT,b").Replace(clashWithRules), RulesAuto, TemplateDropped},
		"few enough":        {clashWithRules, RulesAuto, ""},
		"template asked":    {clashWithRules, RulesTemplate, TemplateRequested},
		"subscription only": {linkList, RulesSubscription, ""},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := Build(t.Context(), []byte(tc.body), Options{Rules: tc.choice, Client: b.client()})
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.want == "" && result.Template != nil:
				t.Fatalf("template applied: %+v", result.Template)
			case tc.want == "":
				return
			case result.Template == nil || result.Template.Reason != tc.want || result.Template.Version != 42:
				t.Fatalf("template %+v, want %s", result.Template, tc.want)
			}
			applied := false
			for _, w := range result.Warnings {
				applied = applied || w.Code == WarnTemplateApplied && w.Detail == tc.want
			}
			if !applied || slices.ContainsFunc(result.Groups, func(g Object) bool { return g.String("name") == "Mine" }) {
				t.Errorf("warnings %v, groups %v", result.Warnings, result.Groups)
			}
		})
	}
	// One rule of ten dropped is not too many.
	result, err := Build(t.Context(), []byte(strings.Replace(clashWithRules, "DOMAIN-SUFFIX,a.example", "USER-AGENT,a", 1)), Options{Client: b.client()})
	if err != nil || result.Template != nil || result.RuleStats != (RuleStats{Total: 10, Dropped: 1, Match: true}) {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err := Build(t.Context(), []byte(linkList), Options{Rules: "lite"}); err == nil {
		t.Error("an unknown choice was taken")
	}
}

func TestBuildApplies(t *testing.T) {
	b := newBranch(t, testTemplate)
	result, err := Build(t.Context(), []byte(linkList), Options{Client: b.client()})
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string][]string{}
	for _, g := range result.Groups {
		var members []string
		for _, m := range g.Value("proxies").([]any) {
			members = append(members, m.(string))
		}
		groups[g.String("name")] = members
		if g.Value("include-all") != nil || g.Value("filter") != nil || g.Value("exclude-filter") != nil || g.Value("use") != nil {
			t.Errorf("%s keeps include-all or filters without providers: %v", g.String("name"), g)
		}
	}
	want := map[string][]string{
		"🚀 Proxy":      {"♻️ Auto", "DIRECT", "HK 01", "JP 01", "香港 02"},
		"♻️ Auto":      {"HK 01", "JP 01", "香港 02"},
		"🇭🇰 Hong Kong": {"HK 01", "香港 02"},
		"🎯 Domestic":   {"DIRECT", "🚀 Proxy"},
	}
	for name, members := range want {
		if !slices.Equal(groups[name], members) {
			t.Errorf("%s: %v, want %v", name, groups[name], members)
		}
	}
	provider := result.RuleProviders.Value("LAN").(Object)
	if provider.String("url") != b.srv.URL+"/providers/dler/lan.classical.txt" || provider.String("path") != "./rules/openweir/dler/lan.classical.txt" {
		t.Errorf("provider %v", provider)
	}
	if !slices.Equal(result.Rules, []string{"RULE-SET,LAN,DIRECT", "DOMAIN-SUFFIX,hk.example,🇭🇰 Hong Kong", "GEOIP,CN,🎯 Domestic", "MATCH,🚀 Proxy"}) {
		t.Errorf("rules %v", result.Rules)
	}
	if result.RuleStats.Total != 0 || len(result.Proxies) != 4 {
		t.Errorf("stats %+v, proxies %d", result.RuleStats, len(result.Proxies))
	}
}

// Proxy providers join every include-all group, with its filters for their proxies; groups the
// template leaves empty go, with the rules that use them.
func TestBuildProvidersAndEmptyGroups(t *testing.T) {
	b := newBranch(t, testTemplate)
	body := "proxies:\n  - {name: JP 01, type: ss, server: jp.example.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-providers:\n  airport: {type: http, url: https://example.com/sub}\n"
	result, err := Build(t.Context(), []byte(body), Options{Client: b.client()})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range result.Groups {
		if g.String("name") == "🇭🇰 Hong Kong" {
			if g.String("filter") != "(?i)hk|香港" || len(g.Value("use").([]any)) != 1 || g.Value("proxies") != nil {
				t.Errorf("Hong Kong %v", g)
			}
		}
	}

	// Without providers and without a node for it, Hong Kong is left empty.
	result, err = Build(t.Context(), []byte("ss://YWVzLTEyOC1nY206cA@jp.example.com:8388#JP%2001\n"), Options{Client: b.client()})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range result.Groups {
		if g.String("name") == "🇭🇰 Hong Kong" {
			t.Errorf("an empty group stays: %v", g)
		}
	}
	if slices.Contains(result.Rules, "DOMAIN-SUFFIX,hk.example,🇭🇰 Hong Kong") || len(result.Rules) != 3 {
		t.Errorf("rules %v", result.Rules)
	}
}

func TestBuildWithoutTemplate(t *testing.T) {
	b := newBranch(t, testTemplate)
	b.status = http.StatusServiceUnavailable
	result, err := Build(t.Context(), []byte(linkList), Options{Client: b.client()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Template != nil || len(result.Proxies) != 4 || result.Groups != nil {
		t.Fatalf("%+v", result)
	}
	last := result.Warnings[len(result.Warnings)-1]
	if last.Code != WarnTemplateUnavailable || !strings.Contains(last.Detail, "no template") {
		t.Errorf("warnings %v", result.Warnings)
	}

	// A template outside the schema is unavailable too.
	bad := newBranch(t, strings.Replace(testTemplate, "rules:", "port: 7890\nrules:", 1))
	result, err = Build(t.Context(), []byte(linkList), Options{Client: bad.client()})
	if err != nil || result.Template != nil || result.Warnings[len(result.Warnings)-1].Code != WarnTemplateUnavailable {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestBuildHead(t *testing.T) {
	b := newBranch(t, testTemplate)
	for _, head := range []bool{false, true} {
		result, err := Build(t.Context(), []byte(linkList), Options{Client: b.client(), Head: head})
		if err != nil {
			t.Fatal(err)
		}
		yaml, err := result.YAML()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(string(yaml), Head) != head || strings.Count(string(yaml), "mixed-port: 9347") != map[bool]int{false: 0, true: 1}[head] {
			t.Errorf("head %v:\n%s", head, yaml)
		}
		if !strings.Contains(string(yaml), "\nproxies:\n") && head || !strings.Contains(string(yaml), "🚀 Proxy") {
			t.Errorf("parts:\n%s", yaml)
		}
	}
}
