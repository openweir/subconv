// Package build is what the root package's Build adds to a conversion: the routing template
// from the rules branch in place of the subscription's routing (template.go), and the OpenWeir
// default head (head.go).
package build

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
	"github.com/openweir/subconv/rules"
)

// Reason says why a subscription with these rule statistics needs the routing template: it has
// no rules, its final rule did not survive, or more than a tenth of its rules were left out. It
// returns "" when the subscription's own routing holds.
func Reason(stats model.RuleStats) string {
	switch {
	case stats.Total == 0:
		return model.TemplateNoRules
	case !stats.Match:
		return model.TemplateNoMatch
	case stats.Dropped*10 > stats.Total:
		return model.TemplateDropped
	}
	return ""
}

// Apply replaces the result's groups, rule providers and rules with the template's: its
// include-all groups list the result's proxies (and use its proxy providers), and groups left
// empty go with their references.
func Apply(result *model.Result, template *rules.Template, options model.Options) error {
	if err := rules.Validate(template.YAML); err != nil {
		return err
	}
	filled, err := template.Filled()
	if err != nil {
		return err
	}
	value, err := model.Decode(filled)
	if err != nil {
		return fmt.Errorf("rules: template: %w", err)
	}
	config := model.AsObject(value)
	var groups []model.Object
	for _, item := range model.AsList(config.Value("proxy-groups")) {
		group, err := expand(model.AsObject(item), result)
		if err != nil {
			return err
		}
		groups = append(groups, group)
	}
	stats, providers := result.RuleStats, model.AsObject(config.Value("rule-providers"))
	result.Groups = groups
	result.RuleProviders = providers
	result.Rules = model.AsStrings(config.Value("rules"))
	// Groups the template leaves empty go, with their references; the proxies come through
	// unchanged, having been normalized already.
	normalize.Result(result, options)
	// The statistics stay the subscription's, and the template's providers as it writes them:
	// their paths keep the rule sets' cache when the host changes.
	result.RuleStats = stats
	for index, field := range result.RuleProviders {
		result.RuleProviders[index].Value = providers.Value(field.Key)
	}
	return nil
}

// mihomo's names of proxy types, which exclude-type lists.
var typeNames = map[string]string{
	"ss": "Shadowsocks", "ssr": "ShadowsocksR", "socks5": "Socks5", "http": "Http", "vmess": "Vmess",
	"vless": "Vless", "trojan": "Trojan", "snell": "Snell", "hysteria": "Hysteria", "hysteria2": "Hysteria2",
	"wireguard": "WireGuard", "tuic": "Tuic", "ssh": "Ssh", "mieru": "Mieru", "anytls": "AnyTLS",
}

// expand turns an include-all group into one that lists its members: its own first, then the
// proxies its filters let through, in subscription order. With proxy providers, it uses them
// all and keeps its filters for their proxies.
func expand(group model.Object, result *model.Result) (model.Object, error) {
	if all, _ := model.Bool(group.Value("include-all")); !all {
		return group, nil
	}
	group = group.Clone()
	filter, err := compile(group.String("filter"))
	if err != nil {
		return nil, err
	}
	exclude, err := compile(group.String("exclude-filter"))
	if err != nil {
		return nil, err
	}
	excludedTypes := strings.Split(strings.ToLower(group.String("exclude-type")), "|")
	excluded := func(kind string) bool { return kind != "" && slices.Contains(excludedTypes, kind) }
	members := toAny(model.AsStrings(group.Value("proxies")))
	for _, p := range result.Proxies {
		name, kind := p.String("name"), p.String("type")
		switch {
		case filter != nil && !filter.MatchString(name),
			exclude != nil && exclude.MatchString(name),
			excluded(strings.ToLower(kind)) || excluded(strings.ToLower(typeNames[kind])):
			continue
		}
		members = append(members, name)
	}
	group.Delete("include-all")
	group.InsertAfter("type", "proxies", members)
	if len(result.ProxyProviders) > 0 {
		var use []any
		for _, field := range result.ProxyProviders {
			use = append(use, field.Key)
		}
		group.InsertAfter("proxies", "use", use)
	} else {
		group.Delete("filter")
		group.Delete("exclude-filter")
		group.Delete("exclude-type")
	}
	return group, nil
}

func compile(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	return regexp.Compile(pattern) // rules.Validate keeps filters to what Go and mihomo read alike
}

func toAny(list []string) []any {
	out := make([]any, len(list))
	for index, item := range list {
		out[index] = item
	}
	return out
}
