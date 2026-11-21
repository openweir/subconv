package subconv

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
)

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
