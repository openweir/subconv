package singbox

import (
	"fmt"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/ruleset"
)

// route converts route.rule_set into rule providers and route.rules and route.final into
// Clash rules, in order.
func (c *singBox) route(route model.Object) {
	sets := map[string]bool{}
	for _, item := range model.AsList(route.Value("rule_set")) {
		set := model.AsObject(item)
		tag := set.String("tag")
		if tag == "" {
			continue
		}
		if provider, reason := c.provider(set); provider != nil {
			c.result.RuleProviders.Set(tag, provider)
			sets[tag] = true
		} else {
			c.result.Warn(model.WarnUnsupportedRuleSet, "%s: %s", tag, reason)
		}
	}
	for index, item := range model.AsList(route.Value("rules")) {
		rule := model.AsObject(item)
		target, reason := c.action(rule)
		if target == "" {
			if reason != "" {
				c.result.Warn(model.WarnUnsupportedRule, "rule %d: %s", index+1, reason)
			}
			continue
		}
		conditions, reason := c.conditions(rule, sets)
		if conditions == nil {
			if reason != "" {
				c.result.Warn(model.WarnUnsupportedRule, "rule %d to %s: %s", index+1, target, reason)
			}
			continue
		}
		for _, condition := range conditions {
			c.result.Rules = append(c.result.Rules, withTarget(condition, target))
		}
	}
	final := or(route.String("final"), c.first)
	target, reason := c.target(final)
	if target == "" {
		target = "DIRECT"
		if reason != "" {
			c.result.Warn(model.WarnUnsupportedRule, "final: %s; DIRECT instead", reason)
		}
	}
	c.result.Rules = append(c.result.Rules, "MATCH,"+target)
}

// action returns a rule's Clash policy, or "" with a reason to leave the rule out. Rules that
// do not route (sniffing, DNS hijacking, resolving and route options) are a client's own and
// go without a reason.
func (c *singBox) action(rule model.Object) (string, string) {
	switch rule.String("action") {
	case "", "route":
		return c.target(rule.String("outbound"))
	case "reject":
		if rule.String("method") == "drop" {
			return "REJECT-DROP", ""
		}
		return "REJECT", ""
	default: // sniff, hijack-dns, resolve, route-options, bypass
		return "", ""
	}
}

// sing-box matches the fields of a rule in groups: any of a group's fields, and every group
// (route/rule/rule_default.go). Fields of no group are each their own.
var fieldGroups = map[string]string{
	"domain": "destination", "domain_suffix": "destination", "domain_keyword": "destination",
	"domain_regex": "destination", "geosite": "destination", "geoip": "destination", "ip_cidr": "destination",
	"ip_is_private": "destination", "rule_set": "destination",
	"port": "port", "port_range": "port",
	"source_geoip": "source", "source_ip_cidr": "source", "source_ip_is_private": "source",
	"source_port": "source port", "source_port_range": "source port",
}

// conditions returns the Clash conditions a rule matches, any of which routes: one per value
// when the rule tests one group of fields, or one AND of the groups (each an OR of its values).
func (c *singBox) conditions(rule model.Object, sets map[string]bool) ([]string, string) {
	if rule.String("type") == "logical" {
		var parts []string
		for _, item := range model.AsList(rule.Value("rules")) {
			sub, reason := c.conditions(model.AsObject(item), sets)
			if sub == nil {
				return nil, reason
			}
			parts = append(parts, anyOf(sub))
		}
		if len(parts) == 0 {
			return nil, "a logical rule with no rules"
		}
		mode := "AND"
		if rule.String("mode") == "or" {
			mode = "OR"
		}
		return []string{invert(rule, logical(mode, parts))}, ""
	}
	source := model.AsBool(rule.Value("rule_set_ip_cidr_match_source")) || model.AsBool(rule.Value("rule_set_ipcidr_match_source"))
	var order []string
	groups := map[string][]string{}
	for _, field := range rule {
		switch field.Key {
		case "action", "outbound", "method", "no_drop", "invert", "type", "rule_set_ip_cidr_match_source",
			"rule_set_ipcidr_match_source", "rule_set_ip_cidr_accept_empty", "override_address", "override_port",
			"network_strategy", "fallback_delay", "udp_disable_domain_unmapping", "udp_connect", "udp_timeout",
			"tls_fragment", "tls_record_fragment", "sniffer", "timeout", "strategy", "server":
			continue
		case "clash_mode":
			// Mode switching is Clash's own; the rules only exist for sing-box's Clash API.
			return nil, ""
		case "protocol":
			if strings.Join(model.AsStrings(field.Value), ",") == "dns" {
				return nil, "" // DNS hijacking, the client's own
			}
		}
		atoms, reason := c.atoms(field, sets, source)
		if atoms == nil {
			return nil, reason
		}
		group := fieldGroups[field.Key]
		if group == "" {
			group = field.Key
		}
		if groups[group] == nil {
			order = append(order, group)
		}
		groups[group] = append(groups[group], atoms...)
	}
	switch len(order) {
	case 0:
		return nil, "a rule with no conditions"
	case 1:
		if model.AsBool(rule.Value("invert")) {
			return []string{invert(rule, anyOf(groups[order[0]]))}, ""
		}
		return groups[order[0]], ""
	}
	parts := make([]string, len(order))
	for index, group := range order {
		parts[index] = anyOf(groups[group])
	}
	return []string{invert(rule, logical("AND", parts))}, ""
}

// atoms converts one field of a rule into Clash conditions, one per value.
func (c *singBox) atoms(field model.Field, sets map[string]bool, source bool) ([]string, string) {
	values := model.AsStrings(field.Value)
	each := func(kind string, transform func(string) string) []string {
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, kind+","+transform(value))
		}
		return out
	}
	same := func(value string) string { return value }
	lan := func(value string) string {
		if strings.EqualFold(value, "private") {
			return "lan" // mihomo's built-in set of non-public addresses
		}
		return value
	}
	switch field.Key {
	case "domain":
		return each("DOMAIN", same), ""
	case "domain_suffix":
		return each("DOMAIN-SUFFIX", func(value string) string { return strings.TrimPrefix(value, ".") }), ""
	case "domain_keyword":
		return each("DOMAIN-KEYWORD", same), ""
	case "domain_regex":
		return each("DOMAIN-REGEX", same), ""
	case "geosite":
		return each("GEOSITE", same), ""
	case "geoip":
		// sing-box matches IP rules against the destination address without resolving it.
		return each("GEOIP", func(value string) string { return lan(value) + ",no-resolve" }), ""
	case "source_geoip":
		return each("SRC-GEOIP", lan), ""
	case "ip_cidr":
		out := make([]string, 0, len(values))
		for _, value := range values {
			kind := "IP-CIDR"
			if strings.Contains(value, ":") {
				kind = "IP-CIDR6"
			}
			out = append(out, kind+","+value+",no-resolve")
		}
		return out, ""
	case "ip_is_private":
		if model.AsBool(field.Value) {
			return []string{"GEOIP,lan,no-resolve"}, ""
		}
	case "source_ip_is_private":
		if model.AsBool(field.Value) {
			return []string{"SRC-GEOIP,lan"}, ""
		}
	case "source_ip_cidr":
		return each("SRC-IP-CIDR", same), ""
	case "port":
		return each("DST-PORT", same), ""
	case "port_range":
		return each("DST-PORT", portRange), ""
	case "source_port":
		return each("SRC-PORT", same), ""
	case "source_port_range":
		return each("SRC-PORT", portRange), ""
	case "network":
		return each("NETWORK", strings.ToLower), ""
	case "process_name":
		return each("PROCESS-NAME", same), ""
	case "process_path":
		return each("PROCESS-PATH", same), ""
	case "process_path_regex":
		return each("PROCESS-PATH-REGEX", same), ""
	case "package_name":
		return each("PROCESS-NAME", same), "" // mihomo matches Android packages by process name
	case "user_id":
		return each("UID", same), ""
	case "rule_set":
		out := make([]string, 0, len(values))
		for _, tag := range values {
			if !sets[tag] {
				return nil, fmt.Sprintf("rule set %s was left out", tag)
			}
			if source {
				out = append(out, "RULE-SET,"+tag+",src")
			} else {
				out = append(out, "RULE-SET,"+tag)
			}
		}
		return out, ""
	}
	return nil, fmt.Sprintf("a rule with %s", field.Key)
}

// provider converts a sing-box rule set into a mihomo rule provider: inline rules become an
// inline provider, and well-known geosite and geoip sets MetaCubeX's .mrs twins. Other remote
// sets are sing-box's binary or JSON format, which mihomo cannot read; a caller that converts
// rule-set content (Options.ConvertsRuleSets) gets the JSON ones as they are.
func (c *singBox) provider(set model.Object) (model.Object, string) {
	tag := set.String("tag")
	kind := set.String("type")
	if kind == "" {
		switch {
		case set.String("url") != "":
			kind = "remote"
		case set.String("path") != "":
			kind = "local"
		default:
			kind = "inline"
		}
	}
	switch kind {
	case "inline":
		var payload []any
		for _, item := range model.AsList(set.Value("rules")) {
			atoms, reason := c.conditions(model.AsObject(item), nil)
			if atoms == nil {
				return nil, or(reason, "an inline rule with no conditions")
			}
			for _, atom := range atoms {
				payload = append(payload, atom)
			}
		}
		if len(payload) == 0 {
			return nil, "an inline rule set with no rules"
		}
		return model.New("type", "inline", "behavior", "classical", "payload", payload), ""
	case "remote":
		url := set.String("url")
		interval := seconds(set.String("update_interval"), 86400)
		provider, ok := ruleset.MetaCubeX(url, tag, interval)
		if !ok {
			format := ruleset.Format(set.String("format"))
			if format == "" {
				format = ruleset.FormatOf(url)
			}
			if format != "json" || !c.options.ConvertsRuleSets {
				return nil, "a remote sing-box rule set that is not a well-known geosite or geoip set"
			}
			provider = model.New("type", "http", "behavior", "classical", "format", "text", "url", url, "interval", interval)
		}
		if detour := set.String("download_detour"); detour != "" {
			if name := c.names[detour]; name != "" && name != "DIRECT" {
				provider.Set("proxy", name)
			}
		}
		return provider, ""
	default:
		return nil, "a local rule set file"
	}
}

func withTarget(condition, target string) string {
	// Trailing options stay after the policy.
	if !strings.HasPrefix(condition, "AND,") && !strings.HasPrefix(condition, "OR,") && !strings.HasPrefix(condition, "NOT,") {
		for _, option := range []string{",no-resolve", ",src"} {
			if base, found := strings.CutSuffix(condition, option); found {
				return base + "," + target + option
			}
		}
	}
	return condition + "," + target
}

// anyOf joins a field's conditions: one stays as it is, more become an OR.
func anyOf(atoms []string) string {
	if len(atoms) == 1 {
		return atoms[0]
	}
	return logical("OR", atoms)
}

func logical(mode string, parts []string) string {
	wrapped := make([]string, len(parts))
	for index, part := range parts {
		wrapped[index] = "(" + part + ")"
	}
	return mode + ",(" + strings.Join(wrapped, ",") + ")"
}

func invert(rule model.Object, condition string) string {
	if model.AsBool(rule.Value("invert")) {
		return logical("NOT", []string{condition})
	}
	return condition
}

func portRange(value string) string {
	return strings.ReplaceAll(value, ":", "-")
}
