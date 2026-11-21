package model

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestReadable(t *testing.T) {
	value := map[string]any{
		"name":    "🚀 Proxy",
		"members": []string{"♻️ Auto", "🕹️ miHoYo", "Ⓜ️ Microsoft", `say "\U0001F680"`, "plain"},
		"rule":    "MATCH,🐟 Others",
	}
	encoded, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	readable := Readable(encoded)
	var back map[string]any
	if err := yaml.Unmarshal(readable, &back); err != nil {
		t.Fatalf("%v\n%s", err, readable)
	}
	want, _ := yaml.Marshal(value)
	got, _ := yaml.Marshal(back)
	if string(got) != string(want) {
		t.Errorf("round trip changed:\n%s\nfrom\n%s", readable, encoded)
	}
	for _, name := range []string{"🚀 Proxy", "🕹️ miHoYo", "🐟 Others"} {
		if !strings.Contains(string(readable), name) {
			t.Errorf("%q is not written as itself:\n%s", name, readable)
		}
	}
}
