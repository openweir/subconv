package main

import (
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/openweir/subconv/rules"
)

// The parts a rule set is split into, in the order their rules go into the template. A large
// classical set is split so that its domains and IP ranges load as mihomo's compact domain and
// ipcidr sets (.mrs), which take less memory and match without a scan, instead of as a list of
// rules mihomo tries one by one; only rules of other types stay classical. A small set stays
// whole unless it splits into one part, so that the template does not multiply rule providers.
const (
	partDomain    = "domain"
	partClassical = "classical"
	partIP        = "ipcidr"         // IP ranges, no-resolve if the source said so for all
	partIPResolve = "ipcidr-resolve" // the ranges without no-resolve, when a set mixes both
)

// ruleSet is an upstream rule set and the parts it converts to.
type ruleSet struct {
	ref      string // the URL layouts name it by
	src      *source
	path     string // within the source
	base     string // output path without part and extension
	license  *license
	behavior string
	parts    []*part
	dropped  map[string]int // rules left out, by type
	// additions are OpenWeir's entries merged into the upstream ones.
	additions []string
}

type part struct {
	kind      string
	behavior  string
	noResolve bool
	entries   []string
	// file is what the template loads: the .mrs, or the text if there is none.
	file   string
	format string
}

// parseRuleSet reads an upstream rule set in mihomo's yaml or text format, followed by the
// classical rules in additions. For a classical set, whole is the set unsplit: its rules that
// mihomo can load, normalized.
func parseRuleSet(body []byte, behavior, format string, additions []string) (parts []*part, whole *part, dropped map[string]int, err error) {
	entries, err := payload(body, format)
	if err != nil {
		return nil, nil, nil, err
	}
	entries = append(entries, additions...)
	dropped = map[string]int{}
	collect := map[string][]string{}
	seen := map[string]map[string]bool{}
	add := func(kind, entry string) {
		if seen[kind] == nil {
			seen[kind] = map[string]bool{}
		}
		if !seen[kind][entry] {
			seen[kind][entry] = true
			collect[kind] = append(collect[kind], entry)
		}
	}
	for _, entry := range entries {
		switch behavior {
		case "domain", "ipcidr":
			// Entries written as classical rules are taken when they are of the set's
			// behavior: some layouts declare Sukka's classical IP lists ipcidr, which
			// mihomo would load as empty.
			kind, value, ok := entry, entry, true
			if strings.Contains(entry, ",") {
				kind, value, ok = splitClassical(entry)
			} else if behavior == "domain" {
				kind, ok = partDomain, validDomainPattern(entry)
			} else {
				kind = partIP
				value, ok = parsePrefix(entry)
			}
			if kind == partIPResolve {
				kind = partIP
			}
			switch {
			case !ok:
				dropped["invalid"]++
			case behavior == "domain" && kind == partDomain, behavior == "ipcidr" && kind == partIP:
				add(kind, value)
			default:
				dropped[strings.ToUpper(rules.SplitRule(entry)[0])]++
			}
		case "classical":
			kind, value, ok := splitClassical(entry)
			if ok {
				add(kind, value)
				fields := rules.SplitRule(entry)
				fields[0] = strings.ToUpper(fields[0])
				add("whole", strings.Join(fields, ","))
			} else {
				dropped[kind]++
			}
		default:
			return nil, nil, nil, fmt.Errorf("behavior %q", behavior)
		}
	}
	if w := collect["whole"]; len(w) > 0 {
		whole = &part{kind: partClassical, behavior: "classical", entries: w}
	}

	if d := collect[partDomain]; len(d) > 0 {
		parts = append(parts, &part{kind: partDomain, behavior: "domain", entries: d})
	}
	if c := collect[partClassical]; len(c) > 0 {
		parts = append(parts, &part{kind: partClassical, behavior: "classical", entries: c})
	}
	ip, resolve := collect[partIP], collect[partIPResolve]
	if len(ip) > 0 {
		// A plain ipcidr set leaves no-resolve to the layout's rule.
		parts = append(parts, &part{kind: partIP, behavior: "ipcidr", noResolve: behavior == "classical", entries: ip})
	}
	if len(resolve) > 0 {
		kind := partIPResolve
		if len(ip) == 0 {
			kind = partIP
		}
		parts = append(parts, &part{kind: kind, behavior: "ipcidr", entries: resolve})
	}
	if len(parts) == 0 {
		return nil, nil, nil, fmt.Errorf("no usable entries among %d", len(entries))
	}
	return parts, whole, dropped, nil
}

// splitClassical sorts a classical rule into its part: domains and IP ranges into theirs, in the
// form domain and ipcidr sets write them; other rules mihomo knows stay as they are.
func splitClassical(rule string) (kind, entry string, ok bool) {
	fields := rules.SplitRule(rule)
	ruleType := strings.ToUpper(fields[0])
	noResolve := len(fields) == 3 && strings.EqualFold(fields[2], "no-resolve")
	switch {
	case len(fields) < 2:
		return "invalid", "", false
	case ruleType == "DOMAIN" && len(fields) == 2:
		if !validDomain(fields[1]) {
			return "invalid", "", false
		}
		return partDomain, fields[1], true
	case ruleType == "DOMAIN-SUFFIX" && len(fields) == 2:
		suffix := strings.TrimPrefix(fields[1], ".")
		if !validDomain(suffix) {
			return "invalid", "", false
		}
		return partDomain, "+." + suffix, true
	case (ruleType == "IP-CIDR" || ruleType == "IP-CIDR6") && (len(fields) == 2 || noResolve):
		prefix, ok := parsePrefix(fields[1])
		switch {
		case !ok:
			return "invalid", "", false
		case noResolve:
			return partIP, prefix, true
		}
		return partIPResolve, prefix, true
	case rules.IsRuleType(ruleType) && ruleType != "RULE-SET" && ruleType != "MATCH":
		fields[0] = ruleType
		return partClassical, strings.Join(fields, ","), true
	}
	return ruleType, "", false
}

// payload returns the entries of a rule file.
func payload(body []byte, format string) ([]string, error) {
	var entries []string
	switch format {
	case "yaml", "":
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		if doc.Payload == nil {
			return nil, fmt.Errorf("no payload")
		}
		entries = doc.Payload
	case "text":
		entries = strings.Split(string(body), "\n")
	default:
		return nil, fmt.Errorf("format %q", format)
	}
	var out []string
	for _, e := range entries {
		e = strings.TrimSpace(strings.TrimPrefix(e, "\ufeff"))
		if e == "" || strings.HasPrefix(e, "#") || strings.HasPrefix(e, "//") {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func parsePrefix(s string) (string, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`,/\:;"'#?@[](){}<>|`, r) {
			return false
		}
	}
	return true
}

// validDomainPattern accepts the entries of a domain set: a domain, or one after "+." (with its
// subdomains), "." (subdomains only) or "*." (one label).
func validDomainPattern(s string) bool {
	for _, prefix := range []string{"+.", "*.", "."} {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			return validDomain(rest)
		}
	}
	return validDomain(s)
}

// outputBase is where a source's rule set goes on the branch, without part and extension:
// lower case, spaces as dashes, "+" spelled out.
func outputBase(src *source, file string) (string, error) {
	name := strings.TrimPrefix(file, src.Strip)
	name = strings.TrimSuffix(name, path.Ext(name))
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '/':
			b.WriteRune(r)
		case r == '+':
			b.WriteString("-plus")
		default:
			b.WriteByte('-')
		}
	}
	segments := strings.Split(b.String(), "/")
	for i, seg := range segments {
		for strings.Contains(seg, "--") {
			seg = strings.ReplaceAll(seg, "--", "-")
		}
		segments[i] = strings.Trim(seg, "-")
	}
	out := "providers/" + src.Output + "/" + strings.Join(segments, "/")
	if !rules.ValidPath(out) {
		return "", fmt.Errorf("%s: no usable output path", file)
	}
	return out, nil
}

// providerName names a part's rule provider in a template: the layout's name for the domain part
// or the only part, with the part's kind after it for the others.
func providerName(layoutName string, set *ruleSet, p *part) string {
	if len(set.parts) == 1 {
		return layoutName
	}
	switch p.kind {
	case partDomain:
		return layoutName
	case partClassical:
		return layoutName + " (classical)"
	case partIP:
		return layoutName + " (IP)"
	default:
		return layoutName + " (IP resolve)"
	}
}

// ruleText renders a part as a mihomo text rule set, with a header naming its source.
func ruleText(set *ruleSet, p *part) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s, %s rules\n", set.src.Name, set.path, p.kind)
	fmt.Fprintf(&b, "# From %s\n", set.ref)
	fmt.Fprintf(&b, "# License: %s. See NOTICE.md. Converted by github.com/openweir/subconv (cmd/rules).\n", set.license.ID)
	if len(set.additions) > 0 {
		b.WriteString("# With OpenWeir's additions from cmd/rules/config.yaml.\n")
	}
	for _, e := range p.entries {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// licenseHeader returns the license a Sukka-style header names ("# License: AGPL 3.0").
func licenseHeader(body []byte) string {
	for i, line := range strings.SplitN(string(body), "\n", 40) {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "# License:"); ok {
			return strings.TrimSpace(name)
		}
		if i > 0 && !strings.HasPrefix(line, "#") {
			break
		}
	}
	return ""
}

func countEntries(parts []*part) int {
	n := 0
	for _, p := range parts {
		n += len(p.entries)
	}
	return n
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func countKind(parts []*part, kind string) int {
	n := 0
	for _, p := range parts {
		if p.kind == kind {
			n += len(p.entries)
		}
	}
	return n
}
