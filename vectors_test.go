package subconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openweir/subconv/internal/model"
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
