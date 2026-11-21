package subconv

import (
	"os"
	"path/filepath"
	"testing"
)

// Subscriptions come from anywhere: no input may make Convert panic, and whatever it converts
// must render. go test runs the seeds; go test -fuzz FuzzConvert explores further.
func FuzzConvert(f *testing.F) {
	inputs, _ := filepath.Glob("testdata/*/input.*")
	panel, _ := filepath.Glob("testdata/panel/*")
	for _, path := range append(inputs, panel...) {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte(`{"outbounds":[{"type":"selector","tag":"a","outbounds":["a"]}]}`))
	f.Add([]byte("proxies: [1, null, {}]\nrules: {}\n"))
	f.Add([]byte("ss://@:\nvmess://e30\nssr://Og\nsnell://@[::1]:x\n"))
	f.Add([]byte("proxies:\n  - {name: a\n\t- x\n  -\nrules: [\n"))
	f.Add([]byte("[Proxy]\na = wireguard, section-name=x\n[Proxy Group]\nb = relay, a, b\n[Rule]\nAND,((\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Convert(data)
		if err != nil {
			return
		}
		if _, err := result.YAML(); err != nil {
			t.Fatalf("converted but does not render: %v", err)
		}
	})
}

// Rule-set and proxy-provider bodies come from anywhere too.
func FuzzConvertRuleSet(f *testing.F) {
	inputs, _ := filepath.Glob("testdata/ruleset/*/input.*")
	for _, path := range inputs {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(data, "classical", "text")
		}
	}
	f.Add([]byte("payload: [a.com, '+.b.com']"), "domain", "yaml")
	f.Add([]byte("AND,((DOMAIN,a),(PROTOCOL,UDP)\n.x.com\n1.1.1.1"), "", "")
	f.Fuzz(func(t *testing.T, data []byte, behavior, format string) {
		set, err := ConvertRuleSet(data, behavior, format)
		if err != nil {
			return
		}
		if set.Behavior != "domain" && set.Behavior != "ipcidr" && set.Behavior != "classical" {
			t.Fatalf("behavior %q", set.Behavior)
		}
	})
}

func FuzzConvertProxies(f *testing.F) {
	inputs, _ := filepath.Glob("testdata/*/input.*")
	for _, path := range inputs {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := ConvertProxies(data)
		if err != nil {
			return
		}
		if _, err := result.YAML(); err != nil {
			t.Fatalf("converted but does not render: %v", err)
		}
	})
}
