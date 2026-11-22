package rules

import (
	"errors"
	"strings"
	"testing"
)

// A rule provider writes its file under ProviderDir and nowhere else in mihomo's home.
func TestValidateProviderPath(t *testing.T) {
	const path = "path: ./rules/openweir/dler/lan.ipcidr.mrs\n"
	if !strings.Contains(validTemplate, path) {
		t.Fatal("the template has no such path")
	}
	for _, p := range []string{
		"./geoip.dat", "./config.yaml", "./rules/lan.mrs", "./rules/openweir", "./rules/openweir/",
		"rules/openweir/lan.mrs", "/etc/openweir/lan.mrs", "./rules/openweir/../../geoip.dat",
		"./rules/openweir//lan.mrs", "./rules/openweir/./lan.mrs", "./rules/openweir/a b.mrs",
		`./rules/openweir/..\geoip.dat`, "./rules/openweirs/lan.mrs", "~/rules/openweir/lan.mrs",
	} {
		changed := strings.Replace(validTemplate, path, "path: '"+p+"'\n", 1)
		if err := Validate([]byte(changed)); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: err %v", p, err)
		}
	}
	// The path is part of the schema: without it, mihomo would cache by URL, which changes with
	// the host.
	if err := Validate([]byte(strings.Replace(validTemplate, path, "", 1))); !errors.Is(err, ErrInvalidTemplate) {
		t.Errorf("no path: err %v", err)
	}
	for _, p := range []string{"./rules/openweir/lan.mrs", "./rules/openweir/dler/media/disney-plus.domain.mrs"} {
		if !ValidProviderPath(p) {
			t.Errorf("%s refused", p)
		}
		if err := Validate([]byte(strings.Replace(validTemplate, path, "path: "+p+"\n", 1))); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
