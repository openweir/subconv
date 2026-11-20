package subconv

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// The panel's own client formats (testdata/panel, from scripts/panel-vectors.ts): converting
// its sing-box outbounds and its share links must give the proxies it writes for OpenWeir
// clients, except where a format cannot carry a setting. Each exception is listed, by format,
// proxy and key; anything else that differs fails.
var panelExceptions = map[string]map[string][]string{
	"sing-box": {
		// The panel's Clash proxies leave out what is the default; sing-box writes it.
		"*":   {"udp", "alterId", "packet-encoding"},
		"Hy2": {"alpn"},
		// sing-box has v5 as v4, the same wire protocol; the panel's Clash proxy says 5.
		"Snell v5": {"version"},
	},
	"links": {
		// Links carry neither TCP Fast Open for VMess, SSR and Mieru nor these defaults.
		"*":         {"udp", "alterId"},
		"VMess WS":  {"tfo"},
		"VMess TCP": {"tfo"},
		"SSR":       {"tfo"},
		"Mieru":     {"tfo"},
		"TUIC":      {"udp-relay-mode"},
		"AnyTLS":    {"client-fingerprint"},
		"HTTPS":     {"sni"},
		"SS obfs":   {"plugin-opts"}, // the panel's link has the obfs mode but not the host
	},
}

// Proxies a format cannot express at all, so they are not in the panel's file for it.
var panelAbsent = map[string][]string{
	"sing-box": {"VLESS XHTTP", "SS obfs", "SSR", "Naive", "Naive QUIC", "Mieru", "Nowhere"},
}

func TestPanelVectors(t *testing.T) {
	var want []map[string]any
	readJSON(t, "testdata/panel/openweir.json", &want)
	for format, file := range map[string]string{"sing-box": "singbox.json", "links": "links.txt"} {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile("testdata/panel/" + file)
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
			got := map[string]map[string]any{}
			for _, proxy := range result.Proxies {
				var decoded map[string]any
				encoded, _ := json.Marshal(proxy)
				_ = json.Unmarshal(encoded, &decoded)
				got[proxy.String("name")] = decoded
			}
			exceptions := panelExceptions[format]
			for _, proxy := range want {
				name := proxy["name"].(string)
				converted, ok := got[name]
				if !ok {
					if !slices.Contains(panelAbsent[format], name) {
						t.Errorf("%s: missing", name)
					}
					continue
				}
				for _, key := range union(proxy, converted) {
					if slices.Contains(exceptions["*"], key) || slices.Contains(exceptions[name], key) {
						continue
					}
					if !reflect.DeepEqual(proxy[key], converted[key]) {
						t.Errorf("%s: %s is %v, the panel writes %v", name, key, converted[key], proxy[key])
					}
				}
			}
		})
	}
}

func union(a, b map[string]any) []string {
	var keys []string
	for key := range a {
		keys = append(keys, key)
	}
	for key := range b {
		if _, ok := a[key]; !ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
