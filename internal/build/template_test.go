package build

import (
	"slices"
	"testing"

	"github.com/openweir/subconv/internal/convert"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/rules"
)

// A routing template as the rules branch serves it.
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

var templateGroups = []string{"🚀 Proxy", "♻️ Auto", "🇭🇰 Hong Kong", "🎯 Domestic"}

// apply converts a subscription and applies the template to it.
func apply(t *testing.T, subscription, template string) *model.Result {
	t.Helper()
	result, err := convert.Subscription([]byte(subscription), model.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(result, &rules.Template{YAML: []byte(template), Base: "https://rules.example.com/branch"}, model.Options{}); err != nil {
		t.Fatal(err)
	}
	return result
}

func groupNamed(result *model.Result, name string) model.Object {
	for _, g := range result.Groups {
		if g.String("name") == name {
			return g
		}
	}
	return nil
}

func proxyNamed(list []model.Object, name string) model.Object {
	for _, p := range list {
		if p.String("name") == name {
			return p
		}
	}
	return nil
}

func names(result *model.Result) (groups, proxies []string) {
	for _, g := range result.Groups {
		groups = append(groups, g.String("name"))
	}
	for _, p := range result.Proxies {
		proxies = append(proxies, p.String("name"))
	}
	return groups, proxies
}

func codes(result *model.Result, code string) []string {
	var details []string
	for _, w := range result.Warnings {
		if w.Code == code {
			details = append(details, w.Detail)
		}
	}
	return details
}

const ss = "type: ss, port: 8388, cipher: aes-128-gcm, password: p"

// A node or proxy provider with a template group's name gives the name up, and everything that
// named it follows: the template's rules and groups keep reaching the template's group.
func TestApplyTemplateNamesWin(t *testing.T) {
	result := apply(t, `proxies:
  - {name: "🚀 Proxy", server: a.example.com, `+ss+`}
  - {name: "🚀 Proxy 2", server: b.example.com, `+ss+`}
  - {name: HK 01, server: hk.example.com, `+ss+`, dialer-proxy: "🚀 Proxy"}
proxy-providers:
  "♻️ Auto": {type: http, url: https://example.com/sub, proxy: "🚀 Proxy"}
  inline:
    type: inline
    payload:
      - {name: Inner, server: c.example.com, `+ss+`, dialer-proxy: "🚀 Proxy"}
`, testTemplate)

	groups, proxies := names(result)
	if !slices.Equal(groups, templateGroups) || !slices.Equal(proxies, []string{"🚀 Proxy 3", "🚀 Proxy 2", "HK 01"}) {
		t.Fatalf("groups %q, proxies %q", groups, proxies)
	}
	if dialer := proxyNamed(result.Proxies, "HK 01").String("dialer-proxy"); dialer != "🚀 Proxy 3" {
		t.Errorf("HK 01 dials through %q", dialer)
	}
	if keys := []string{result.ProxyProviders[0].Key, result.ProxyProviders[1].Key}; !slices.Equal(keys, []string{"♻️ Auto 2", "inline"}) {
		t.Fatalf("providers %q", keys)
	}
	if via := model.AsObject(result.ProxyProviders[0].Value).String("proxy"); via != "🚀 Proxy 3" {
		t.Errorf("the provider downloads through %q", via)
	}
	var payload []model.Object
	for _, item := range model.AsList(model.AsObject(result.ProxyProviders[1].Value).Value("payload")) {
		payload = append(payload, model.AsObject(item))
	}
	if dialer := proxyNamed(payload, "Inner").String("dialer-proxy"); dialer != "🚀 Proxy 3" {
		t.Errorf("the inline proxy dials through %q", dialer)
	}

	proxy := groupNamed(result, "🚀 Proxy")
	members, use := model.AsStrings(proxy.Value("proxies")), model.AsStrings(proxy.Value("use"))
	if !slices.Equal(members, []string{"♻️ Auto", "DIRECT", "🚀 Proxy 3", "🚀 Proxy 2", "HK 01"}) || !slices.Equal(use, []string{"♻️ Auto 2", "inline"}) {
		t.Errorf("🚀 Proxy: proxies %q, use %q", members, use)
	}
	if domestic := model.AsStrings(groupNamed(result, "🎯 Domestic").Value("proxies")); !slices.Equal(domestic, []string{"DIRECT", "🚀 Proxy"}) {
		t.Errorf("🎯 Domestic: %q", domestic)
	}
	if result.Rules[len(result.Rules)-1] != "MATCH,🚀 Proxy" {
		t.Errorf("rules %q", result.Rules)
	}
	want := []string{
		"🚀 Proxy: renamed 🚀 Proxy 3, the name of a template group",
		"♻️ Auto: proxy provider renamed ♻️ Auto 2, the name of a template group",
	}
	if renamed := codes(result, model.WarnRenamed); !slices.Equal(renamed, want) {
		t.Errorf("renamed %q", renamed)
	}
	if unknown := codes(result, model.WarnUnknownReference); len(unknown) > 0 {
		t.Errorf("unknown references %q", unknown)
	}
}

// The subscription's groups that dialer-proxy chains go through stay, with the groups they
// contain, so a landing node keeps dialing through them; one with a template group's name is
// renamed.
func TestApplyKeepsChains(t *testing.T) {
	result := apply(t, `proxies:
  - {name: Entry A, server: a.example.com, `+ss+`}
  - {name: Entry B, server: b.example.com, `+ss+`}
  - {name: Landing, server: l.example.com, `+ss+`, dialer-proxy: Entries}
  - {name: Landing CN, server: cn.example.com, `+ss+`, dialer-proxy: "🎯 Domestic"}
proxy-providers:
  remote: {type: http, url: https://example.com/sub, override: {dialer-proxy: Via}}
proxy-groups:
  - {name: Mine, type: select, proxies: [Landing, Entry A]}
  - {name: Entries, type: fallback, proxies: [Inner, Entry B], url: https://www.gstatic.com/generate_204, interval: 300}
  - {name: Inner, type: select, proxies: [Entry A]}
  - {name: "🎯 Domestic", type: select, proxies: [Entry B, DIRECT]}
  - {name: Via, type: select, proxies: [Entry A]}
rules:
  - MATCH,Mine
`, testTemplate)

	groups, _ := names(result)
	if want := append(slices.Clone(templateGroups), "Entries", "Inner", "🎯 Domestic 2", "Via"); !slices.Equal(groups, want) {
		t.Fatalf("groups %q, want %q", groups, want)
	}
	for name, want := range map[string][]string{
		"Entries":      {"Inner", "Entry B"},
		"Inner":        {"Entry A"},
		"🎯 Domestic 2": {"Entry B", "DIRECT"},
		"Via":          {"Entry A"},
		"🎯 Domestic":   {"DIRECT", "🚀 Proxy"},
	} {
		if members := model.AsStrings(groupNamed(result, name).Value("proxies")); !slices.Equal(members, want) {
			t.Errorf("%s: %q, want %q", name, members, want)
		}
	}
	if entries := groupNamed(result, "Entries"); entries.String("type") != "fallback" || entries.String("url") == "" {
		t.Errorf("Entries changed: %v", entries)
	}
	for name, want := range map[string]string{"Landing": "Entries", "Landing CN": "🎯 Domestic 2"} {
		if dialer := proxyNamed(result.Proxies, name).String("dialer-proxy"); dialer != want {
			t.Errorf("%s dials through %q, want %q", name, dialer, want)
		}
	}
	override := model.AsObject(model.AsObject(result.ProxyProviders.Value("remote")).Value("override"))
	if dialer := override.String("dialer-proxy"); dialer != "Via" {
		t.Errorf("the provider's proxies dial through %q", dialer)
	}
	if unknown := codes(result, model.WarnUnknownReference); len(unknown) > 0 {
		t.Errorf("unknown references %q", unknown)
	}
	if !slices.Equal(result.Rules, []string{"RULE-SET,LAN,DIRECT", "DOMAIN-SUFFIX,hk.example,🇭🇰 Hong Kong", "GEOIP,CN,🎯 Domestic", "MATCH,🚀 Proxy"}) {
		t.Errorf("rules %q", result.Rules)
	}
}
