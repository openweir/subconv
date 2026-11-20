package subconv

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
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
		`{"outbounds":[]}`:                         FormatSingBox,
		`{"endpoints":[]}`:                         FormatSingBox,
		"proxies:\n  - {name: a, type: ss}\n":      FormatClash,
		"\xef\xbb\xbfproxies: []\n":                FormatClash,
		"vless://uuid@example.com:443#a\n":         FormatLinks,
		"dmxlc3M6Ly91dWlkQGV4YW1wbGUuY29tOjQ0MyNh": FormatLinks,
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
