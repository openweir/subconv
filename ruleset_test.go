package subconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rule-set vectors: testdata/ruleset/<case>/input.* is a provider's content, provider.json
// what the provider declares, and expected.json what ConvertRuleSet makes of it.
func TestRuleSetVectors(t *testing.T) {
	cases, err := filepath.Glob("testdata/ruleset/*/input.*")
	if err != nil || len(cases) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	for _, input := range cases {
		dir := filepath.Dir(input)
		t.Run(filepath.Base(dir), func(t *testing.T) {
			data, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			var declared struct{ Behavior, Format string }
			readJSON(t, filepath.Join(dir, "provider.json"), &declared)
			set, err := ConvertRuleSet(data, declared.Behavior, declared.Format)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(map[string]any{
				"behavior": set.Behavior,
				"format":   set.Format,
				"entries":  set.Entries,
				"skipped":  set.Skipped,
				"body":     strings.Split(strings.TrimSuffix(string(set.Body), "\n"), "\n"),
				"warnings": set.Warnings,
			}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join(dir, "expected.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs; run go test -update and review the diff\n%s", path, got)
			}
		})
	}
}

func TestRuleSetErrors(t *testing.T) {
	mrs := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, "frame"...)
	if set, err := ConvertRuleSet(mrs, "domain", "mrs"); err != nil || set.Format != "mrs" || !bytes.Equal(set.Body, mrs) {
		t.Errorf("MRS does not pass through: %v", err)
	}
	if _, err := ConvertRuleSet(mrs, "classical", "mrs"); err == nil {
		t.Error("a classical MRS rule set converted")
	}
	if _, err := ConvertRuleSet([]byte("<html><body>404</body></html>"), "domain", "text"); !errors.Is(err, ErrWebPage) {
		t.Errorf("a web page: %v", err)
	}
	if _, err := ConvertRuleSet([]byte("# nothing\n\n"), "domain", "text"); !errors.Is(err, ErrNoRules) {
		t.Errorf("an empty list: %v", err)
	}
	huge := bytes.Repeat([]byte("1.1.1.1\n"), 250001)
	if _, err := ConvertRuleSet(huge, "ipcidr", "text"); !errors.Is(err, ErrRuleSetTooLarge) {
		t.Errorf("too many entries: %v", err)
	}
}

// A proxy provider's content converts to its proxies alone, in any format.
func TestConvertProxies(t *testing.T) {
	clash := "proxies:\n  - {name: A, type: ss, server: a.example.com, port: 8388, cipher: aes-128-gcm, password: p, dialer-proxy: Main}\n" +
		"  - {name: B, type: vmess, server: b.example.com, port: 443, uuid: 7c8c8c0e-0000-4000-8000-000000000001}\n" +
		"  - {name: C, type: trojan, server: c.example.com}\n" +
		"proxy-groups:\n  - {name: G, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n"
	result, err := ConvertProxies([]byte(clash))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Proxies) != 2 || result.Groups != nil || result.Rules != nil {
		t.Fatalf("proxies %d, groups %v, rules %v", len(result.Proxies), result.Groups, result.Rules)
	}
	if result.Proxies[0].String("dialer-proxy") != "Main" {
		t.Error("a dialer-proxy into the config was removed")
	}
	if result.Proxies[1].Value("alterId") == nil {
		t.Error("the VMess proxy was not repaired")
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != WarnInvalidProxy {
		t.Errorf("warnings: %v", result.Warnings)
	}
	links, err := ConvertProxies([]byte("dHJvamFuOi8vcHdAdC5leGFtcGxlLmNvbTo0NDMjVA=="))
	if err != nil || len(links.Proxies) != 1 || links.Format != FormatLinks {
		t.Errorf("Base64 links: %v, %v", links, err)
	}
}
