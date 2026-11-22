// Package build is what the root package's Build adds to a conversion: the routing template
// from the rules branch in place of the subscription's routing (template.go), and the OpenWeir
// default head (head.go).
package build

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
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
// empty go with their references. The template's group names win: proxies and proxy providers
// that share one are renamed, and so is every reference to them. The subscription's groups that
// its proxies and proxy providers dial or download through stay, after the template's, so
// chains keep their routing.
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
	providers := model.AsObject(config.Value("rule-providers"))
	for _, field := range providers {
		// The paths go to mihomo as written, so they are held to the template's directory here
		// too, whatever validated them.
		if path := model.AsObject(field.Value).String("path"); !rules.ValidProviderPath(path) {
			return fmt.Errorf("%w: rule provider %s: path %q is not under %s", rules.ErrInvalidTemplate, field.Key, path, rules.ProviderDir)
		}
	}
	var templateGroups []model.Object
	names := map[string]bool{}
	for _, item := range model.AsList(config.Value("proxy-groups")) {
		group := model.AsObject(item)
		templateGroups = append(templateGroups, group)
		names[group.String("name")] = true
	}
	// The subscription's parts that stay are changed as copies, so that a template that fails
	// leaves the result as it was.
	sub := &subscription{
		proxies:   cloneAll(result.Proxies),
		providers: result.ProxyProviders.Clone(),
		groups:    chained(result),
	}
	sub.makeRoom(names)
	var groups []model.Object
	for _, group := range templateGroups {
		group, err := expand(group, sub.proxies, sub.providers)
		if err != nil {
			return err
		}
		groups = append(groups, group)
	}
	stats := result.RuleStats
	result.Proxies = sub.proxies
	result.ProxyProviders = sub.providers
	result.Groups = append(groups, sub.groups...)
	result.RuleProviders = providers
	result.Rules = model.AsStrings(config.Value("rules"))
	result.Warnings = append(result.Warnings, sub.warnings...)
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

// subscription is what stays of the subscription under the template: its proxies, its proxy
// providers and the groups its chains go through.
type subscription struct {
	proxies   []model.Object
	providers model.Object
	groups    []model.Object
	warnings  []model.Warning
}

// chained returns copies of the subscription's groups that its proxies dial through
// (dialer-proxy) and its proxy providers download or dial through, with the groups those
// contain, in the subscription's order. The template's groups would route these chains
// elsewhere, and dropping the reference would send them direct.
func chained(result *model.Result) []model.Object {
	byName := make(map[string]model.Object, len(result.Groups))
	for _, group := range result.Groups {
		byName[group.String("name")] = group
	}
	needed := map[string]bool{}
	var need func(name string)
	need = func(name string) {
		group, ok := byName[name]
		if !ok || needed[name] {
			return
		}
		needed[name] = true
		for _, member := range model.AsStrings(group.Value("proxies")) {
			need(member)
		}
	}
	for _, p := range result.Proxies {
		need(p.String("dialer-proxy"))
	}
	for _, field := range result.ProxyProviders {
		for _, r := range providerRefs(model.AsObject(field.Value)) {
			need(r.String(r.key))
		}
	}
	var out []model.Object
	for _, group := range result.Groups {
		if needed[group.String("name")] {
			out = append(out, group.Clone())
		}
	}
	return out
}

// ref is an object with a key that names a proxy or group.
type ref struct {
	model.Object
	key string
}

// providerRefs lists what in a proxy provider names a proxy or group of the config: the proxy
// it downloads through, its dialer-proxy and its override's, and those of its inline proxies.
// The objects share their contents with the provider's, so setting an existing key changes it.
func providerRefs(provider model.Object) []ref {
	refs := []ref{{provider, "proxy"}, {provider, "dialer-proxy"}}
	if override := model.AsObject(provider.Value("override")); override != nil {
		refs = append(refs, ref{override, "dialer-proxy"})
	}
	for _, item := range model.AsList(provider.Value("payload")) {
		if p := model.AsObject(item); p != nil {
			refs = append(refs, ref{p, "dialer-proxy"})
		}
	}
	return refs
}

// Names mihomo keeps: the built-in policies, the GLOBAL group and the default proxy provider.
var reserved = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL", "default"}

// makeRoom gives the template's groups their names: proxies, kept groups and proxy providers
// that hold one are renamed, and every reference to them follows (dialer-proxy, a provider's
// proxy, group members, use and empty-fallback). Proxies and groups share one namespace, proxy
// providers another; the new names are new to both.
func (s *subscription) makeRoom(names map[string]bool) {
	taken := map[string]bool{}
	for name := range names {
		taken[name] = true
	}
	for _, name := range reserved {
		taken[name] = true
	}
	for _, p := range s.proxies {
		taken[p.String("name")] = true
	}
	for _, group := range s.groups {
		taken[group.String("name")] = true
	}
	for _, field := range s.providers {
		taken[field.Key] = true
	}
	rename := func(name, what string) string {
		for n := 2; ; n++ {
			if candidate := name + " " + strconv.Itoa(n); !taken[candidate] {
				taken[candidate] = true
				s.warnings = append(s.warnings, model.Warning{Code: model.WarnRenamed,
					Detail: fmt.Sprintf("%s: %srenamed %s, the name of a template group", name, what, candidate)})
				return candidate
			}
		}
	}
	renamed, renamedProviders := map[string]string{}, map[string]string{}
	for _, list := range [][]model.Object{s.proxies, s.groups} {
		for index := range list {
			if name := list[index].String("name"); names[name] {
				renamed[name] = rename(name, "")
				list[index].Set("name", renamed[name])
			}
		}
	}
	for index, field := range s.providers {
		if names[field.Key] {
			renamedProviders[field.Key] = rename(field.Key, "proxy provider ")
			s.providers[index].Key = renamedProviders[field.Key]
		}
	}
	follow := func(o model.Object, key string) {
		if to, ok := renamed[o.String(key)]; ok {
			o.Set(key, to) // the key exists: set in place
		}
	}
	for _, p := range s.proxies {
		follow(p, "dialer-proxy")
	}
	for _, field := range s.providers {
		for _, r := range providerRefs(model.AsObject(field.Value)) {
			follow(r.Object, r.key)
		}
	}
	for index := range s.groups {
		group := &s.groups[index]
		follow(*group, "empty-fallback")
		for key, to := range map[string]map[string]string{"proxies": renamed, "use": renamedProviders} {
			if list, set := group.Get(key); set && len(to) > 0 {
				members := model.AsStrings(list)
				for i, member := range members {
					if name, ok := to[member]; ok {
						members[i] = name
					}
				}
				group.Set(key, toAny(members))
			}
		}
	}
}

func cloneAll(list []model.Object) []model.Object {
	out := make([]model.Object, len(list))
	for index, o := range list {
		out[index] = o.Clone()
	}
	return out
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
func expand(group model.Object, proxies []model.Object, providers model.Object) (model.Object, error) {
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
	for _, p := range proxies {
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
	if len(providers) > 0 {
		var use []any
		for _, field := range providers {
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
