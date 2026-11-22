package normalize

import "testing"

// mihomo's utils.NewUnsignedRanges refuses the whole config over a status it cannot read.
func TestStatusRanges(t *testing.T) {
	for text, want := range map[string]bool{
		"":                  true,
		"*":                 true,
		" 204 ":             true,
		"200/302":           true,
		"200,204,401-429":   true,
		"200-299/[300-302]": true,
		"200//204/":         true,
		"200-":              false,
		"-299":              false,
		"200-300-400":       false,
		"2xx":               false,
		"*/200":             false,
		"-1":                false,
		"1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28":    true,
		"1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29": false,
	} {
		if got := statusRanges(text); got != want {
			t.Errorf("statusRanges(%q) = %v, want %v", text, got, want)
		}
	}
}
