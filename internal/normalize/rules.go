package normalize

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
)

// The rule types OpenWeir mihomo parses (rules/parser.go).
var ruleTypes = map[string]bool{}

func init() {
	for _, kind := range strings.Fields("DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX DOMAIN-WILDCARD GEOSITE " +
		"GEOIP SRC-GEOIP IP-ASN SRC-IP-ASN IP-CIDR IP-CIDR6 SRC-IP-CIDR IP-SUFFIX SRC-IP-SUFFIX SRC-PORT DST-PORT " +
		"IN-PORT DSCP PROCESS-NAME PROCESS-PATH PROCESS-NAME-REGEX PROCESS-PATH-REGEX PROCESS-NAME-WILDCARD " +
		"PROCESS-PATH-WILDCARD NETWORK UID IN-TYPE IN-USER IN-NAME REMATCH-NAME AND OR NOT RULE-SET MATCH") {
		ruleTypes[kind] = true
	}
}

// Other clients' names for mihomo's rule types: Surge, Quantumult X and older Clash.
var ruleAliases = map[string]string{
	"HOST":           "DOMAIN",
	"HOST-SUFFIX":    "DOMAIN-SUFFIX",
	"HOST-KEYWORD":   "DOMAIN-KEYWORD",
	"HOST-WILDCARD":  "DOMAIN-WILDCARD",
	"HOST-REGEX":     "DOMAIN-REGEX",
	"IP6-CIDR":       "IP-CIDR6",
	"IP-CIDR6":       "IP-CIDR6",
	"DEST-PORT":      "DST-PORT",
	"DEST-PORTS":     "DST-PORT",
	"SRC-IP":         "SRC-IP-CIDR",
	"SOURCE-IP-CIDR": "SRC-IP-CIDR",
	"FINAL":          "MATCH",
	"PROCESS":        "PROCESS-NAME",
	"IP-ASN6":        "IP-ASN",
}

// Rule types whose payload may contain commas: the policy is the last field.
var commaPayload = map[string]bool{"AND": true, "OR": true, "NOT": true, "SUB-RULE": true,
	"DOMAIN-REGEX": true, "PROCESS-NAME-REGEX": true, "PROCESS-PATH-REGEX": true}

// Policies of other clients that mean REJECT to mihomo.
var rejects = map[string]string{
	"REJECT-TINYGIF": "REJECT", "REJECT-IMG": "REJECT", "REJECT-200": "REJECT", "REJECT-DICT": "REJECT",
	"REJECT-ARRAY": "REJECT", "REJECT-NO-DROP": "REJECT", "REJECT-VIDEO": "REJECT",
}

// rules keeps the rules mihomo can parse whose policies and rule sets exist, and ends them with
// one MATCH.
func (s *state) rules() {
	if len(s.r.Rules) == 0 {
		return
	}
	var out []string
	final := false
	for _, line := range s.r.Rules {
		rule, problem := s.rule(line)
		if problem != "" {
			s.r.Warn(model.WarnUnsupportedRule, "%s: %s", line, problem)
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "MATCH,") || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FINAL,") {
				out = append(out, "MATCH,DIRECT")
				final = true
				break
			}
			continue
		}
		out = append(out, rule)
		if strings.HasPrefix(rule, "MATCH,") {
			// Rules after MATCH never match.
			final = true
			break
		}
	}
	if !final {
		// mihomo sends what no rule matches DIRECT; say so.
		out = append(out, "MATCH,DIRECT")
	}
	s.r.Rules = out
}

// rule checks one rule and returns it in mihomo's spelling, or why it cannot be kept.
func (s *state) rule(line string) (string, string) {
	items := strings.Split(line, ",")
	for index := range items {
		items[index] = strings.TrimSpace(items[index])
	}
	kind := strings.ToUpper(items[0])
	if alias, ok := ruleAliases[kind]; ok {
		kind = alias
	}
	if kind == "MATCH" {
		if len(items) < 2 || items[1] == "" {
			return "", "no policy"
		}
		target, problem := s.policy(items[1])
		if problem != "" {
			return "", problem
		}
		return "MATCH," + target, ""
	}
	if !ruleTypes[kind] {
		if kind == "SUB-RULE" {
			return "", "sub-rules are not carried over"
		}
		return "", "rule type " + kind
	}
	var payload, target string
	var params []string
	if commaPayload[kind] {
		if len(items) < 3 {
			return "", "no policy"
		}
		target = items[len(items)-1]
		payload = strings.Join(items[1:len(items)-1], ",")
	} else {
		if len(items) < 3 {
			return "", "no policy"
		}
		payload, target = items[1], items[2]
		for _, param := range items[3:] {
			switch param = strings.ToLower(param); param {
			case "no-resolve", "src":
				if !slices.Contains(params, param) {
					params = append(params, param)
				}
			}
		}
	}
	payload, problem := s.condition(kind, payload, 0)
	if problem != "" {
		return "", problem
	}
	target, problem = s.policy(target)
	if problem != "" {
		return "", problem
	}
	return strings.Join(append([]string{kind, payload, target}, params...), ","), ""
}

// condition checks a rule's payload, and a logical rule's rules, and returns it repaired.
func (s *state) condition(kind, payload string, depth int) (string, string) {
	if payload == "" {
		return "", "no " + strings.ToLower(kind) + " value"
	}
	switch kind {
	case "AND", "OR", "NOT":
		if depth > 16 {
			return "", "logical rules nested too deep"
		}
		parts, ok := subRules(payload)
		if !ok || len(parts) == 0 || kind == "NOT" && len(parts) != 1 {
			return "", "a malformed " + kind + " rule"
		}
		out := make([]string, len(parts))
		for index, part := range parts {
			items := strings.Split(part, ",")
			sub := strings.ToUpper(strings.TrimSpace(items[0]))
			if alias, ok := ruleAliases[sub]; ok {
				sub = alias
			}
			if !ruleTypes[sub] || sub == "MATCH" {
				return "", "rule type " + sub
			}
			rest := ""
			if len(items) > 1 {
				rest = strings.TrimSpace(strings.Join(items[1:], ","))
			}
			var params []string
			if !commaPayload[sub] && len(items) > 2 {
				rest = strings.TrimSpace(items[1])
				for _, param := range items[2:] {
					params = append(params, strings.ToLower(strings.TrimSpace(param)))
				}
			}
			value, problem := s.condition(sub, rest, depth+1)
			if problem != "" {
				return "", problem
			}
			out[index] = "(" + strings.Join(append([]string{sub, value}, params...), ",") + ")"
		}
		return "(" + strings.Join(out, ",") + ")", ""
	case "DOMAIN-SUFFIX":
		// mihomo matches the suffix after a dot; a leading dot or "+." would match nothing.
		return strings.TrimPrefix(strings.TrimPrefix(payload, "+"), "."), ""
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "IP-SUFFIX", "SRC-IP-SUFFIX":
		if _, err := netip.ParsePrefix(payload); err == nil {
			return payload, ""
		}
		if addr, err := netip.ParseAddr(payload); err == nil {
			return netip.PrefixFrom(addr, addr.BitLen()).String(), ""
		}
		return "", "IP range " + payload
	case "DST-PORT", "SRC-PORT", "IN-PORT":
		ports := strings.ReplaceAll(payload, ":", "-")
		for part := range strings.SplitSeq(ports, "/") {
			low, high, ranged := strings.Cut(part, "-")
			if !port(low) || ranged && !port(high) {
				return "", "port " + payload
			}
		}
		return ports, ""
	case "NETWORK":
		switch strings.ToLower(payload) {
		case "tcp", "udp":
			return payload, ""
		}
		return "", "network " + payload
	case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		if badRegex(payload) {
			return "", "regular expression " + payload
		}
	case "RULE-SET":
		if !s.ruleSets[payload] {
			if s.droppedRuleSets[payload] {
				return "", "rule set " + payload + " was left out"
			}
			return "", "rule set " + payload + " does not exist"
		}
	}
	return payload, ""
}

// policy returns the name a rule's policy has, or why it has none.
func (s *state) policy(name string) (string, string) {
	if s.exists(name) || name == "GLOBAL" {
		return name, ""
	}
	upper := strings.ToUpper(name)
	if slices.Contains(builtIn, upper) || upper == "GLOBAL" {
		return upper, ""
	}
	if reject, ok := rejects[upper]; ok {
		return reject, ""
	}
	// Another case of a name that exists, as Quantumult X writes policies.
	var matches []string
	for candidate := range s.proxies {
		if strings.EqualFold(candidate, name) {
			matches = append(matches, candidate)
		}
	}
	for candidate := range s.groups {
		if strings.EqualFold(candidate, name) && s.proxies[candidate] == nil {
			matches = append(matches, candidate)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], ""
	case 0:
	default:
		return "", "policy " + name + " is ambiguous"
	}
	if s.dropped[name] {
		return "", "policy " + name + " was left out"
	}
	return "", "policy " + name + " does not exist"
}

// subRules splits a logical rule's payload, "((A,x),(B,y))", into its rules "A,x" and "B,y".
func subRules(payload string) ([]string, bool) {
	payload = strings.TrimSpace(payload)
	if len(payload) < 2 || payload[0] != '(' || payload[len(payload)-1] != ')' {
		return nil, false
	}
	inner := payload[1 : len(payload)-1]
	var parts []string
	depth, start := 0, -1
	for index, r := range inner {
		switch r {
		case '(':
			if depth == 0 {
				start = index + 1
			}
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
			if depth == 0 {
				parts = append(parts, inner[start:index])
			}
		default:
			if depth == 0 && r != ',' && r != ' ' {
				return nil, false
			}
		}
	}
	return parts, depth == 0
}

func port(text string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(text))
	return err == nil && n >= 0 && n <= 65535
}
