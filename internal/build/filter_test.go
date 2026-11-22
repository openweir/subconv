package build

import (
	"reflect"
	"testing"

	"github.com/openweir/subconv/internal/model"
)

// An include-all group lists the proxies mihomo would pick: filters read by regexp2, so
// lookaround works and \d is any decimal digit.
func TestExpandReadsFiltersAsMihomo(t *testing.T) {
	group := model.New("name", "Auto", "type", "url-test", "include-all", true,
		"filter", "^(?!.*到期)", "exclude-filter", `\d{2}$`)
	var proxies []model.Object
	for _, name := range []string{"HK 1", "HK 到期", "JP １２", "US 12", "SG"} {
		proxies = append(proxies, model.New("name", name, "type", "ss"))
	}
	expanded, err := expand(group, proxies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := expanded.Value("proxies"), []any{"HK 1", "SG"}; !reflect.DeepEqual(got, want) {
		t.Errorf("proxies %v, want %v", got, want)
	}
}
