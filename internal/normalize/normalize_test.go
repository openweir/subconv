package normalize

import "testing"

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
