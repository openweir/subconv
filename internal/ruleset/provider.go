// Package ruleset handles rule sets: the providers that name them and the content mihomo reads
// from them.
package ruleset

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/openweir/subconv/internal/model"
)

// MetaCubeX's mihomo rule sets, the counterparts of the geosite and geoip sets other clients use.
const metaRules = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo"

// Behavior returns mihomo's name for a rule set's behavior, or "".
func Behavior(name string) string {
	switch strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "-") {
	case "domain", "domains", "domain-set", "domainset":
		return "domain"
	case "ipcidr", "ip-cidr", "ip", "ipset", "ip-set", "cidr":
		return "ipcidr"
	case "classical", "classic", "rule-set", "ruleset":
		return "classical"
	}
	return ""
}

// Format returns mihomo's name for a rule set's format: yaml, text, mrs, or another name for
// what mihomo cannot read ("srs", "json"), or "" when unknown.
func Format(name string) string {
	switch name = strings.ToLower(strings.TrimSpace(name)); name {
	case "yaml", "yml":
		return "yaml"
	case "text", "txt", "list", "conf":
		return "text"
	case "mrs":
		return "mrs"
	case "binary", "srs":
		return "srs"
	case "source", "json":
		return "json"
	}
	return ""
}

// FormatOf guesses a rule set's format from its URL's extension.
func FormatOf(raw string) string {
	return Format(strings.TrimPrefix(path.Ext(urlPath(raw)), "."))
}

// WebURL reports a URL a client can download.
func WebURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// MetaCubeX returns the MetaCubeX .mrs provider for a well-known geosite or geoip set: SagerNet's
// sing-geosite and sing-geoip, MetaCubeX's own sing branch and the sets named after them. The
// URL's file name, its directory or the tag must say geosite or geoip.
func MetaCubeX(raw, tag string, interval int) (model.Object, bool) {
	kind, category, ok := wellKnown(raw, tag)
	if !ok {
		return nil, false
	}
	behavior := "domain"
	if kind == "geoip" {
		behavior = "ipcidr"
	}
	return model.New(
		"type", "http",
		"behavior", behavior,
		"format", "mrs",
		"url", fmt.Sprintf("%s/%s/%s.mrs", metaRules, kind, category),
		"interval", interval,
	), true
}

func wellKnown(raw, tag string) (kind, category string, ok bool) {
	p := urlPath(raw)
	name := strings.TrimSuffix(path.Base(p), path.Ext(p))
	if dir := path.Base(path.Dir(p)); (dir == "geosite" || dir == "geoip") && name != "" && raw != "" {
		return dir, strings.ToLower(name), true
	}
	for _, candidate := range []string{name, tag} {
		if kind, category, ok := strings.Cut(strings.ToLower(candidate), "-"); ok && (kind == "geosite" || kind == "geoip") && category != "" {
			return kind, category, true
		}
	}
	return "", "", false
}

func urlPath(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return parsed.Path
}
