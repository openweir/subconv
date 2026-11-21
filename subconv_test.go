package subconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
)

var update = flag.Bool("update", false, "rewrite testdata/*/expected.json from the current output")

// The shared vectors: testdata/<case>/input.* converts to testdata/<case>/expected.json. Other
// implementations (the iOS client's Rust core) check themselves against the same files.
func TestVectors(t *testing.T) {
	cases, err := filepath.Glob("testdata/*/input.*")
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
			result, err := Convert(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(result, "", "  ")
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
			if _, err := result.YAML(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	for input, want := range map[string]Format{
		`{"outbounds":[]}`:                                                          FormatSingBox,
		`{"endpoints":[]}`:                                                          FormatSingBox,
		"proxies:\n  - {name: a, type: ss}\n":                                       FormatClash,
		"\xef\xbb\xbfproxies: []\n":                                                 FormatClash,
		"vless://uuid@example.com:443#a\n":                                          FormatLinks,
		"dmxlc3M6Ly91dWlkQGV4YW1wbGUuY29tOjQ0MyNh":                                  FormatLinks,
		"// comment\n{\"outbounds\":[],}":                                           FormatSingBox,
		"Proxy:\n  - {name: a, type: ss}\n":                                         FormatClash,
		"# Shadowrocket\nvless://u@h:1#a\n":                                         FormatLinks,
		"[Proxy]\na = ss, h, 1, encrypt-method=none\n":                              FormatSurge,
		"shadowsocks=h:1, method=none, tag=a\n":                                     FormatQuantumultX,
		"\xff\xfev\x00l\x00e\x00s\x00s\x00:\x00/\x00/\x00u\x00@\x00h\x00:\x001\x00": FormatLinks,
	} {
		if got, err := Detect([]byte(input)); err != nil || got != want {
			t.Errorf("Detect(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "hello", `{"log":{}}`} {
		if _, err := Detect([]byte(input)); err == nil {
			t.Errorf("Detect(%q) accepted it", input)
		}
	}
}

// Servers answer with error pages and messages; Convert names them instead of converting them.
func TestDetectErrors(t *testing.T) {
	for input, want := range map[string]error{
		"":                      ErrEmpty,
		" \r\n\xef\xbb\xbf":     ErrEmpty,
		"<!DOCTYPE html><html>": ErrWebPage,
		"<html><head><title>403 Forbidden</title></head></html>": ErrWebPage,
		"token expired":                   ErrMessage,
		"订阅已过期，请续费":                       ErrMessage,
		`{"message":"invalid token"}`:     ErrMessage,
		`{"error":{"msg":"user banned"}}`: ErrMessage,
		`{"log":{}}`:                      ErrUnknownFormat,
		"QmluYXJ5IGRhdGEgdGhhdCBpcyBub3QgYSBzdWJzY3JpcHRpb24AAQI=": ErrUnknownFormat,
	} {
		_, err := Convert([]byte(input))
		if !errors.Is(err, want) || !errors.Is(err, ErrUnknownFormat) {
			t.Errorf("Convert(%q) = %v; want %v", input, err, want)
		}
	}
	_, err := Convert([]byte(`{"msg":"token expired"}`))
	if err == nil || !strings.Contains(err.Error(), "token expired") {
		t.Errorf("the message is not in the error: %v", err)
	}
}

// Clients key what users chose (selected proxies, local groups) to the proxies' fields, so
// valid parts must come back exactly as written: no added defaults, renamed keys or retyped
// values.
func TestValidClashUnchanged(t *testing.T) {
	data, err := os.ReadFile("testdata/clash-valid/input.yaml")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Convert(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) > 0 {
		t.Errorf("warnings: %v", result.Warnings)
	}
	value, err := model.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	config := model.AsObject(value)
	same := func(part string, got, want any) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if !bytes.Equal(g, w) {
			t.Errorf("%s changed:\n got %s\nwant %s", part, g, w)
		}
	}
	same("proxies", result.Proxies, config.Value("proxies"))
	same("proxy-providers", result.ProxyProviders, config.Value("proxy-providers"))
	same("proxy-groups", result.Groups, config.Value("proxy-groups"))
	same("rule-providers", result.RuleProviders, config.Value("rule-providers"))
	same("rules", result.Rules, config.Value("rules"))
}

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

// The panel's own client formats (testdata/panel, from scripts/panel-vectors.ts): converting
// its sing-box outbounds and its share links must give the proxies it writes for OpenWeir
// clients, except where a format cannot carry a setting. Each exception is listed, by format,
// proxy and key; anything else that differs fails.
var panelExceptions = map[string]map[string][]string{
	"sing-box": {
		// The panel's Clash proxies leave out what is the default; sing-box writes it.
		"*":   {"udp", "packet-encoding"},
		"Hy2": {"alpn"},
		// sing-box has v5 as v4, the same wire protocol; the panel's Clash proxy says 5.
		"Snell v5": {"version"},
	},
	"links": {
		// Links carry neither TCP Fast Open for VMess, SSR and Mieru nor these defaults.
		"*":         {"udp"},
		"VMess WS":  {"tfo"},
		"VMess TCP": {"tfo"},
		"SSR":       {"tfo"},
		"Mieru":     {"tfo"},
		"TUIC":      {"udp-relay-mode"},
		"AnyTLS":    {"client-fingerprint"},
		"HTTPS":     {"sni"},
		"SS obfs":   {"plugin-opts"}, // the panel's link has the obfs mode but not the host
	},
}

// Proxies a format cannot express at all, so they are not in the panel's file for it.
var panelAbsent = map[string][]string{
	"sing-box": {"VLESS XHTTP", "SS obfs", "SSR", "Naive", "Naive QUIC", "Mieru", "Nowhere"},
}

func TestPanelVectors(t *testing.T) {
	var want []map[string]any
	readJSON(t, "testdata/panel/openweir.json", &want)
	proxies, err := os.ReadFile("testdata/panel/openweir.json")
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{
		// The panel's own proxies, as a Clash subscription, come back as they are.
		"clash": append(append([]byte(`{"proxies":`), proxies...), '}'),
	}
	for format, file := range map[string]string{"sing-box": "singbox.json", "links": "links.txt"} {
		if inputs[format], err = os.ReadFile("testdata/panel/" + file); err != nil {
			t.Fatal(err)
		}
	}
	for format, data := range inputs {
		t.Run(format, func(t *testing.T) {
			result, err := Convert(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Warnings) > 0 {
				t.Errorf("warnings: %v", result.Warnings)
			}
			got := map[string]map[string]any{}
			for _, proxy := range result.Proxies {
				var decoded map[string]any
				encoded, _ := json.Marshal(proxy)
				_ = json.Unmarshal(encoded, &decoded)
				got[proxy.String("name")] = decoded
			}
			exceptions := panelExceptions[format]
			for _, proxy := range want {
				name := proxy["name"].(string)
				converted, ok := got[name]
				if !ok {
					if !slices.Contains(panelAbsent[format], name) {
						t.Errorf("%s: missing", name)
					}
					continue
				}
				for _, key := range union(proxy, converted) {
					if slices.Contains(exceptions["*"], key) || slices.Contains(exceptions[name], key) {
						continue
					}
					if !reflect.DeepEqual(proxy[key], converted[key]) {
						t.Errorf("%s: %s is %v, the panel writes %v", name, key, converted[key], proxy[key])
					}
				}
			}
		})
	}
}

func union(a, b map[string]any) []string {
	var keys []string
	for key := range a {
		keys = append(keys, key)
	}
	for key := range b {
		if _, ok := a[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}

// Every vector's conversion loads in OpenWeir mihomo. SUBCONV_MIHOMO names a mihomo binary,
// whose "-t" parses a config the way it loads one: proxies, groups, providers and rules alike.
// SUBCONV_MIHOMO_WITHOUT lists proxy types the binary was built without (naive needs the
// with_naive tag), which are taken out first. The test is skipped without a binary.
func TestVectorsLoadInMihomo(t *testing.T) {
	mihomo := os.Getenv("SUBCONV_MIHOMO")
	if mihomo == "" {
		t.Skip("SUBCONV_MIHOMO is not set")
	}
	without := strings.Split(os.Getenv("SUBCONV_MIHOMO_WITHOUT"), ",")
	inputs, err := filepath.Glob("testdata/*/input.*")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir() // shared, so that GeoIP data is downloaded once
	for _, input := range inputs {
		name := filepath.Base(filepath.Dir(input))
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Convert(data)
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(result.Proxies, func(p Object) bool { return slices.Contains(without, p.String("type")) }) {
				result.Proxies = slices.DeleteFunc(result.Proxies, func(p Object) bool { return slices.Contains(without, p.String("type")) })
				normalize.Result(result, model.Options{})
			}
			result.Head = Head
			config, err := result.YAML()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, name+".yaml")
			if err := os.WriteFile(path, config, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(mihomo, "-t", "-d", home, "-f", path).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "test is successful") {
				t.Errorf("mihomo refuses it: %v\n%s\n%s", err, output, config)
			}
		})
	}
}

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
