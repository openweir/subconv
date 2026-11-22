package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ErrInvalidTemplate reports a template outside the schema [Validate] checks.
var ErrInvalidTemplate = errors.New("rules: invalid template")

// Group is a proxy group of a template. A template never names nodes: IncludeAll stands for
// every node of the subscription, narrowed by Filter and ExcludeFilter (regular expressions on
// node names). These are mihomo's own fields, so a template loads in mihomo as it is; subconv
// expands them into explicit proxies in subscription order when it fills the nodes in.
type Group struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Proxies        []string `yaml:"proxies,omitempty"`
	IncludeAll     bool     `yaml:"include-all,omitempty"`
	Filter         string   `yaml:"filter,omitempty"`
	ExcludeFilter  string   `yaml:"exclude-filter,omitempty"`
	ExcludeType    string   `yaml:"exclude-type,omitempty"`
	URL            string   `yaml:"url,omitempty"`
	Interval       int      `yaml:"interval,omitempty"`
	Tolerance      int      `yaml:"tolerance,omitempty"`
	Timeout        int      `yaml:"timeout,omitempty"`
	Lazy           *bool    `yaml:"lazy,omitempty"`
	MaxFailedTimes int      `yaml:"max-failed-times,omitempty"`
	ExpectedStatus string   `yaml:"expected-status,omitempty"`
	Strategy       string   `yaml:"strategy,omitempty"`
	DisableUDP     bool     `yaml:"disable-udp,omitempty"`
	Hidden         bool     `yaml:"hidden,omitempty"`
	Icon           string   `yaml:"icon,omitempty"`
}

// Provider is a rule provider of a template. Its URL is [Placeholder] followed by a path on the
// branch; its Path is a file under [ProviderDir].
type Provider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	Format   string `yaml:"format"`
	URL      string `yaml:"url"`
	Path     string `yaml:"path,omitempty"`
	Interval int    `yaml:"interval,omitempty"`
}

// ProviderDir is the directory, relative to mihomo's home, that a template's rule providers keep
// their files in. Their paths do not depend on the host, so the cache survives a change of host.
const ProviderDir = "./rules/openweir/"

// ValidProviderPath reports whether a rule provider's path is a file under [ProviderDir], the
// only place in mihomo's home a template may write to: not over geoip.dat, config.yaml or
// another program's rule sets.
func ValidProviderPath(path string) bool {
	rest, ok := strings.CutPrefix(path, ProviderDir)
	return ok && ValidPath(rest)
}

type templateDoc struct {
	Groups    []Group             `yaml:"proxy-groups"`
	Providers map[string]Provider `yaml:"rule-providers"`
	Rules     []string            `yaml:"rules"`
}

// Policies every config has without defining them.
var builtinPolicies = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true}

// Rule types a template may use: mihomo's, without SUB-RULE.
var ruleTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"DOMAIN-WILDCARD": true, "GEOSITE": true, "GEOIP": true, "SRC-GEOIP": true, "IP-ASN": true,
	"SRC-IP-ASN": true, "IP-CIDR": true, "IP-CIDR6": true, "SRC-IP-CIDR": true, "IP-SUFFIX": true,
	"SRC-IP-SUFFIX": true, "SRC-PORT": true, "DST-PORT": true, "IN-PORT": true, "DSCP": true,
	"PROCESS-NAME": true, "PROCESS-PATH": true, "PROCESS-NAME-REGEX": true,
	"PROCESS-PATH-REGEX": true, "PROCESS-NAME-WILDCARD": true, "PROCESS-PATH-WILDCARD": true,
	"NETWORK": true, "UID": true, "IN-TYPE": true, "IN-USER": true, "IN-NAME": true,
	"AND": true, "OR": true, "NOT": true, "RULE-SET": true, "MATCH": true,
}

// IsRuleType reports whether a template may use a rule type: mihomo's types without SUB-RULE.
// Every one but RULE-SET and MATCH may also appear in a classical rule set.
func IsRuleType(kind string) bool { return ruleTypes[kind] }

var groupTypes = map[string]bool{"select": true, "url-test": true, "fallback": true, "load-balance": true}

// Validate checks a template against the schema of the branch's templates: only proxy-groups,
// rule-providers and rules; groups that reach nodes only through include-all with portable
// filters; providers on the branch that keep their files under [ProviderDir]; rules that end in
// MATCH and send traffic only to the template's groups and the built-in policies.
func Validate(template []byte) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidTemplate, fmt.Sprintf(format, args...))
	}
	// Only the three sections decode; any other key (ports, dns, tun, external-controller,
	// secret, proxies, …) fails, merged in with "<<" or not, and so does a second document.
	var doc templateDoc
	dec := yaml.NewDecoder(bytes.NewReader(template))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return invalid("%v", err)
	}
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return invalid("more than one document")
	}

	groups := make(map[string]*Group, len(doc.Groups))
	for i := range doc.Groups {
		g := &doc.Groups[i]
		switch {
		case !validName(g.Name) || builtinPolicies[g.Name] || groups[g.Name] != nil:
			return invalid("group name %q", g.Name)
		case !groupTypes[g.Type]:
			return invalid("group %s: type %q", g.Name, g.Type)
		case len(g.Proxies) == 0 && !g.IncludeAll:
			return invalid("group %s: neither proxies nor include-all", g.Name)
		case !g.IncludeAll && (g.Filter != "" || g.ExcludeFilter != "" || g.ExcludeType != ""):
			return invalid("group %s: a filter without include-all", g.Name)
		}
		for _, f := range []string{g.Filter, g.ExcludeFilter} {
			if err := checkFilter(f); err != nil {
				return invalid("group %s: %v", g.Name, err)
			}
		}
		groups[g.Name] = g
	}
	for _, g := range doc.Groups {
		for _, p := range g.Proxies {
			if !builtinPolicies[p] && groups[p] == nil {
				return invalid("group %s: unknown member %q", g.Name, p)
			}
		}
	}
	if err := checkCycles(doc.Groups, groups); err != nil {
		return invalid("%v", err)
	}

	for name, p := range doc.Providers {
		path, onBranch := strings.CutPrefix(p.URL, Placeholder+"/")
		switch {
		case !validName(name):
			return invalid("rule provider name %q", name)
		case p.Type != "http":
			return invalid("rule provider %s: type %q", name, p.Type)
		case p.Behavior != "domain" && p.Behavior != "ipcidr" && p.Behavior != "classical":
			return invalid("rule provider %s: behavior %q", name, p.Behavior)
		case p.Format != "mrs" && p.Format != "text" && p.Format != "yaml",
			p.Format == "mrs" && p.Behavior == "classical":
			return invalid("rule provider %s: format %q", name, p.Format)
		case !onBranch || !ValidPath(path):
			return invalid("rule provider %s: url %q is not on the branch", name, p.URL)
		case !ValidProviderPath(p.Path):
			return invalid("rule provider %s: path %q is not under %s", name, p.Path, ProviderDir)
		}
	}

	if len(doc.Rules) == 0 {
		return invalid("no rules")
	}
	used := make(map[string]bool, len(doc.Providers))
	for i, rule := range doc.Rules {
		fields := SplitRule(rule)
		kind := strings.ToUpper(fields[0])
		var target string
		switch {
		case !ruleTypes[kind]:
			return invalid("rule %q: type", rule)
		case kind == "MATCH":
			if len(fields) != 2 || i != len(doc.Rules)-1 {
				return invalid("rule %q: MATCH must be the last rule, and only it", rule)
			}
			target = fields[1]
		case len(fields) < 3:
			return invalid("rule %q: no policy", rule)
		default:
			target = fields[2]
		}
		if kind == "RULE-SET" {
			if _, ok := doc.Providers[fields[1]]; !ok {
				return invalid("rule %q: unknown rule provider", rule)
			}
			used[fields[1]] = true
		}
		if !builtinPolicies[target] && groups[target] == nil {
			return invalid("rule %q: unknown policy %q", rule, target)
		}
	}
	if !strings.EqualFold(SplitRule(doc.Rules[len(doc.Rules)-1])[0], "MATCH") {
		return invalid("the last rule is not MATCH")
	}
	for name := range doc.Providers {
		if !used[name] {
			return invalid("rule provider %s is not used", name)
		}
	}
	return nil
}

// SplitRule splits a Clash rule at the commas outside parentheses, so the payload of AND, OR and
// NOT stays whole.
func SplitRule(rule string) []string {
	var fields []string
	depth, start := 0, 0
	for i := 0; i < len(rule); i++ {
		switch rule[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(rule[start:i]))
				start = i + 1
			}
		}
	}
	return append(fields, strings.TrimSpace(rule[start:]))
}

func validName(name string) bool {
	return strings.TrimSpace(name) == name && name != "" && !strings.ContainsAny(name, ",\n")
}

// checkFilter keeps filters to what Go's regexp (which subconv expands them with) and mihomo's
// regexp2 read alike: RE2 syntax, no backquote (mihomo splits filters at it), and no \b, \w, \d
// or \s, which mean ASCII to one and Unicode to the other.
func checkFilter(filter string) error {
	if filter == "" {
		return nil
	}
	if strings.Contains(filter, "`") {
		return fmt.Errorf("filter %q: backquote", filter)
	}
	for i := 0; i < len(filter)-1; i++ {
		if filter[i] == '\\' {
			if strings.IndexByte("bBwWdDsS", filter[i+1]) >= 0 {
				return fmt.Errorf("filter %q: \\%c differs between regexp engines", filter, filter[i+1])
			}
			i++
		}
	}
	if _, err := regexp.Compile(filter); err != nil {
		return fmt.Errorf("filter %q: %v", filter, err)
	}
	return nil
}

func checkCycles(list []Group, groups map[string]*Group) error {
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int, len(list))
	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("group %s is part of a loop", name)
		case done:
			return nil
		}
		state[name] = visiting
		for _, p := range groups[name].Proxies {
			if groups[p] != nil {
				if err := visit(p); err != nil {
					return err
				}
			}
		}
		state[name] = done
		return nil
	}
	for _, g := range list {
		if err := visit(g.Name); err != nil {
			return err
		}
	}
	return nil
}

// InfoFilter matches the names of the pseudo-nodes subscriptions use to show remaining
// traffic, expiry dates and websites. The templates' groups exclude them; clients that list
// nodes can reuse it.
const InfoFilter = "(?i)expire|remaining|traffic|website|剩余|到期|过期|流量|官网|套餐|重置"

// InfoToken stands for [InfoFilter] in the generator's config. Templates never contain it.
const InfoToken = "{info}"
