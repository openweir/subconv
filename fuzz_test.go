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
