// Package clash reads Clash and mihomo configs, and Stash's, which share the format. It takes
// the parts as they are; internal/normalize repairs them.
package clash

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openweir/subconv/internal/model"
)

var errNotAConfig = errors.New("not a Clash config")

// Convert takes a Clash, mihomo or Stash config's proxies, proxy providers, groups, rule
// providers and rules.
func Convert(data []byte) (*model.Result, error) {
	value, err := model.Decode(data)
	config := model.AsObject(value)
	var recovered []model.Warning
	if err != nil {
		config, recovered = Recover(data)
	}
	if config == nil {
		return nil, fmt.Errorf("clash: %w", errNotAConfig)
	}
	result := &model.Result{Format: Dialect(config), Warnings: recovered}
	if rewrites := model.AsList(model.AsObject(config.Value("http")).Value("rewrite")); len(rewrites) > 0 {
		// Stash's URL rewrites block and redirect requests, which mihomo's rules cannot.
		result.Warn(model.WarnUnsupportedRule, "http rewrite: %d rules", len(rewrites))
	}
	config = sections(config)
	for index, item := range model.AsList(config.Value("proxies")) {
		if proxy := model.AsObject(item); proxy != nil {
			result.Proxies = append(result.Proxies, proxy)
		} else {
			result.Warn(model.WarnInvalidProxy, "proxy %d: not a mapping", index+1)
		}
	}
	result.ProxyProviders = model.AsObject(config.Value("proxy-providers"))
	for index, item := range model.AsList(config.Value("proxy-groups")) {
		if group := model.AsObject(item); group != nil {
			result.Groups = append(result.Groups, stashGroup(group))
		} else {
			result.Warn(model.WarnUnsupportedGroup, "group %d: not a mapping", index+1)
		}
	}
	result.RuleProviders = model.AsObject(config.Value("rule-providers"))
	for _, item := range model.AsList(config.Value("rules")) {
		if rule, ok := model.Text(item); ok && rule != "" {
			result.Rules = append(result.Rules, rule)
		}
	}
	return result, nil
}

// Clash's early names for the sections, before it settled on lowercase.
var sectionNames = map[string]string{
	"proxies":         "proxies",
	"proxy":           "proxies",
	"proxy-providers": "proxy-providers",
	"proxy-groups":    "proxy-groups",
	"proxy group":     "proxy-groups",
	"proxy-group":     "proxy-groups",
	"rule-providers":  "rule-providers",
	"rules":           "rules",
	"rule":            "rules",
}

// sections returns the config's sections under their current names; the current name wins.
func sections(config model.Object) model.Object {
	out := model.Object{}
	for _, field := range config {
		name, ok := sectionNames[strings.ToLower(field.Key)]
		if !ok {
			continue
		}
		if _, set := out.Get(name); set && field.Key != name {
			continue
		}
		out.Set(name, field.Value)
	}
	return out
}

// Dialect tells Stash's configs from Clash's: Stash names a group's health check benchmark-url
// and keeps its scripts and rewrites under script and http.
func Dialect(config model.Object) model.Format {
	if config.Value("script") != nil || model.AsObject(config.Value("http")).Value("rewrite") != nil {
		return model.FormatStash
	}
	for _, item := range model.AsList(config.Value("proxy-groups")) {
		group := model.AsObject(item)
		if group.Value("benchmark-url") != nil || group.Value("benchmark-timeout") != nil {
			return model.FormatStash
		}
	}
	return model.FormatClash
}

// stashGroup gives Stash's health-check options mihomo's names: benchmark-url is url, and
// benchmark-timeout seconds are timeout milliseconds.
func stashGroup(group model.Object) model.Object {
	url, timeout := group.Value("benchmark-url"), group.Value("benchmark-timeout")
	if url == nil && timeout == nil {
		return group
	}
	group = group.Clone()
	if _, set := group.Get("url"); !set && url != nil {
		group.Rename("benchmark-url", "url")
	}
	if seconds, ok := model.Int(timeout); ok {
		if _, set := group.Get("timeout"); !set {
			group.Rename("benchmark-timeout", "timeout")
			group.Set("timeout", seconds*1000)
		}
	}
	group.Delete("benchmark-url")
	group.Delete("benchmark-timeout")
	return group
}
