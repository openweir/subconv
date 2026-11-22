package normalize

import (
	"testing"

	"github.com/openweir/subconv/internal/model"
)

// Regular expressions are checked as mihomo compiles them, with regexp2: Go's own syntax goes,
// regexp2's stays.
func TestBadRegex(t *testing.T) {
	for pattern, bad := range map[string]bool{
		"":                               false,
		"(?i)港|hk|hongkong":              false,
		"^(?!.*(?:剩余|到期|官网)).*$":         false,
		"(?<=香港)\\d+":                    false,
		"(a)\\1":                         false,
		"\\pL\\x{4e00}[\\u4e00-\\u9fa5]": false,
		"(?x:a b)c":                      false,
		"(?x)a b(?-x)":                   false,
		"hk`us":                          false,
		"\\Qa.b\\E":                      true, // Go reads it, regexp2 does not
		"(?P<n>a)":                       true,
		"\\_":                            true,
		"[z-a]":                          true, // both refuse it
		"a{3,1}":                         true,
		"a**":                            true,
		"(":                              true,
		"\\1":                            true,
		"hk`(":                           true, // a part does not compile
		"(hk`us)":                        true, // nor do they, though the whole does
		"(?x)a b":                        true, // joined with another filter, x is still on
		"(?n)a":                          true, // and so is n
	} {
		if got := badRegex(pattern); got != bad {
			t.Errorf("badRegex(%q) = %v, want %v", pattern, got, bad)
		}
	}
}

// A filter matches as regexp2 reads it: any of its parts, \d for any decimal digit.
func TestFilter(t *testing.T) {
	f, err := CompileFilter("^JP`\\d$")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"JP 1": true, "HK １": true, "HK": false} {
		if got, err := f.Match(name); got != want || err != nil {
			t.Errorf("Match(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if f, err := CompileFilter(""); f != nil || err != nil {
		t.Errorf("an empty filter: %v, %v", f, err)
	}
	if _, err := CompileFilter("(?P<n>a)"); err == nil {
		t.Error("a filter regexp2 refuses compiled")
	}
}

// exclude-type compares mihomo's own names of the types, in any case.
func TestExcludedType(t *testing.T) {
	s := &state{
		r: &model.Result{Groups: []model.Object{model.New("name", "Auto", "type", "url-test")}},
		proxies: map[string]model.Object{
			"a": model.New("name", "a", "type", "ss"),
			"b": model.New("name", "b", "type", "vless-reverse"),
			"c": model.New("name", "c", "type", "hysteria2"),
		},
	}
	for _, c := range []struct {
		types, name string
		want        bool
	}{
		{"Shadowsocks", "a", true},
		{"ss", "a", false},
		{"vmess|shadowsocks", "a", true},
		{"VlessReverse", "b", true},
		{"Hysteria", "c", false},
		{"Hysteria2", "c", true},
		{"urltest", "Auto", true},
		{"Selector", "Auto", false},
		{"Direct", "DIRECT", false},
	} {
		if got := s.excludedType(c.types, c.name); got != c.want {
			t.Errorf("excludedType(%q, %q) = %v, want %v", c.types, c.name, got, c.want)
		}
	}
}

// A landing proxy may dial through a group of all proxies that excludes it, by name or by type,
// explicit members included; a group that keeps it, or falls back to it, is a loop.
func TestChainThroughExcludingGroup(t *testing.T) {
	ss := func(name, dialer string) model.Object {
		p := model.New("name", name, "type", "ss", "server", "s.example.com", "port", 8388,
			"cipher", "aes-128-gcm", "password", "p")
		if dialer != "" {
			p.Set("dialer-proxy", dialer)
		}
		return p
	}
	for _, c := range []struct {
		front model.Object
		loop  bool
	}{
		{model.New("name", "Front", "type", "select", "include-all", true, "exclude-filter", "^Landing"), false},
		{model.New("name", "Front", "type", "select", "include-all", true, "exclude-filter", "HK`Landing"), false},
		{model.New("name", "Front", "type", "select", "proxies", []any{"Landing", "HK"}, "exclude-filter", "Landing"), false},
		{model.New("name", "Front", "type", "select", "include-all", true, "exclude-type", "Shadowsocks"), false},
		{model.New("name", "Front", "type", "select", "include-all", true, "exclude-type", "ss"), true},
		{model.New("name", "Front", "type", "select", "include-all", true, "exclude-filter", "^HK"), true},
		{model.New("name", "Front", "type", "select", "include-all", true, "filter", "(?i)landing"), true},
		{model.New("name", "Front", "type", "select", "proxies", []any{"HK"}, "exclude-filter", "HK",
			"empty-fallback", "Landing"), true},
	} {
		r := &model.Result{
			Proxies: []model.Object{ss("HK", ""), ss("Landing", "Front")},
			Groups:  []model.Object{c.front},
			Rules:   []string{"MATCH,Front"},
		}
		Result(r, model.Options{})
		kept := r.Proxies[1].String("dialer-proxy") == "Front"
		if kept == c.loop {
			t.Errorf("%v: dialer-proxy kept %v; warnings %v", c.front, kept, r.Warnings)
		}
	}
}
