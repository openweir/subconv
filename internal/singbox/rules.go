package singbox

import (
	"github.com/openweir/subconv/internal/model"

	"fmt"
	"net/url"
	"path"
	"strings"
)

// MetaCubeX's mihomo rule sets, the counterparts of sing-box's geosite-*.srs and geoip-*.srs.
const metaRules = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo"

// route converts route.rule_set into rule providers and route.rules and route.final into
// Clash rules, in order.
func (c *singBox) route(route model.Object) {
	sets := map[string]bool{}
	for _, item := range model.AsList(route.Value("rule_set")) {
		set := model.AsObject(item)
		tag := set.String("tag")
		if provider, reason := c.provider(set); provider != nil {
			c.result.RuleProviders.Set(tag, provider)
			sets[tag] = true
		} else if tag != "" {
			c.result.Warn(model.WarnUnsupportedRuleSet, "%s: %s", tag, reason)
		}
	}
	for _, item := range model.AsList(route.Value("rules")) {
		rule := model.AsObject(item)
		target, keep := c.action(rule)
		if !keep {
			continue
		}
		conditions, reason := c.conditions(rule, sets)
		if conditions == nil {
			if reason != "" {
				c.result.Warn(model.WarnUnsupportedRule, "%s", reason)
			}
			continue
		}
		for _, condition := range conditions {
			c.result.Rules = append(c.result.Rules, withTarget(condition, target))
		}
	}
	final := or(route.String("final"), c.first)
	if target, keep := c.target(final); keep {
		c.result.Rules = append(c.result.Rules, "MATCH,"+target)
	} else {
		c.result.Rules = append(c.result.Rules, "MATCH,DIRECT")
	}
}

// action returns a rule's Clash policy, or false for rules that do not route: sniffing, DNS
// hijacking, resolving and route options, which a client configures on its own.
func (c *singBox) action(rule model.Object) (string, bool) {
	switch rule.String("action") {
	case "", "route":
		return c.target(rule.String("outbound"))
	case "reject":
		if rule.String("method") == "drop" {
			return "REJECT-DROP", true
		}
		return "REJECT", true
	default: // sniff, hijack-dns, resolve, route-options, bypass
		return "", false
	}
}

// conditions returns the Clash conditions a rule matches, any of which routes: one per value
// when the rule tests one field, or one AND of the fields (each an OR of its values).
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
		mode := "AND"
		if rule.String("mode") == "or" {
			mode = "OR"
		}
		return []string{invert(rule, logical(mode, parts))}, ""
	}
	var fields [][]string
	for _, field := range rule {
		switch field.Key {
		case "action", "outbound", "method", "no_drop", "invert", "type":
			continue
		case "clash_mode":
			// Mode switching is Clash's own; the rules only exist for sing-box's Clash API.
			return nil, ""
		case "protocol":
			if strings.Join(model.AsStrings(field.Value), ",") == "dns" {
				return nil, "" // DNS hijacking, the client's own
			}
		}
		atoms, reason := c.atoms(field, sets)
		if atoms == nil {
			return nil, reason
		}
		fields = append(fields, atoms)
	}
	switch len(fields) {
	case 0:
		return nil, "a rule with no conditions"
	case 1:
		if model.AsBool(rule.Value("invert")) {
			return []string{invert(rule, anyOf(fields[0]))}, ""
		}
		return fields[0], ""
	}
	parts := make([]string, len(fields))
	for index, atoms := range fields {
		parts[index] = anyOf(atoms)
	}
	return []string{invert(rule, logical("AND", parts))}, ""
}

// atoms converts one field of a rule into Clash conditions, one per value.
func (c *singBox) atoms(field model.Field, sets map[string]bool) ([]string, string) {
	values := model.AsStrings(field.Value)
	each := func(kind string, transform func(string) string) []string {
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, kind+","+transform(value))
		}
		return out
	}
	same := func(value string) string { return value }
	switch field.Key {
	case "domain":
		return each("DOMAIN", same), ""
	case "domain_suffix":
		return each("DOMAIN-SUFFIX", func(value string) string { return strings.TrimPrefix(value, ".") }), ""
	case "domain_keyword":
		return each("DOMAIN-KEYWORD", same), ""
	case "domain_regex":
		return each("DOMAIN-REGEX", same), ""
	case "ip_cidr":
		// sing-box matches IP rules against the destination address without resolving it.
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
			return []string{"GEOIP,private,no-resolve"}, ""
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
	case "rule_set":
		out := make([]string, 0, len(values))
		for _, tag := range values {
			if !sets[tag] {
				return nil, fmt.Sprintf("a rule with rule set %s, which was left out", tag)
			}
			out = append(out, "RULE-SET,"+tag)
		}
		return out, ""
	}
	return nil, fmt.Sprintf("a rule with %s", field.Key)
}

// provider converts a sing-box rule set into a mihomo rule provider: inline rules become an
// inline provider, and MetaCubeX's geosite-*/geoip-* sets the matching .mrs files. Other remote
// sets are sing-box's binary or JSON format, which mihomo cannot read.
func (c *singBox) provider(set model.Object) (model.Object, string) {
	tag := set.String("tag")
	switch set.String("type") {
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
		return model.New("type", "inline", "behavior", "classical", "payload", payload), ""
	case "remote":
		name := strings.TrimSuffix(path.Base(urlPath(set.String("url"))), path.Ext(urlPath(set.String("url"))))
		for _, candidate := range []string{name, tag} {
			if kind, category, ok := strings.Cut(strings.ToLower(candidate), "-"); ok && (kind == "geosite" || kind == "geoip") {
				behavior := "domain"
				if kind == "geoip" {
					behavior = "ipcidr"
				}
				return model.New(
					"type", "http",
					"behavior", behavior,
					"format", "mrs",
					"url", fmt.Sprintf("%s/%s/%s.mrs", metaRules, kind, category),
					"path", "./ruleset/"+tag+".mrs",
					"interval", seconds(set.String("update_interval"), 86400),
				), ""
			}
		}
		return nil, "a remote sing-box rule set that is not one of MetaCubeX's geosite or geoip sets"
	default:
		return nil, "a local rule set file"
	}
}

func withTarget(condition, target string) string {
	// A trailing ",no-resolve" stays after the policy.
	if base, found := strings.CutSuffix(condition, ",no-resolve"); found && !strings.HasPrefix(condition, "AND,") && !strings.HasPrefix(condition, "OR,") && !strings.HasPrefix(condition, "NOT,") {
		return base + "," + target + ",no-resolve"
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
		wrapped[index] = "(" + strings.TrimSuffix(part, ",no-resolve") + ")"
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

func urlPath(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return parsed.Path
}
