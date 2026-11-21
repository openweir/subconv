package ruleset

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/openweir/subconv/internal/body"
	"github.com/openweir/subconv/internal/model"
)

// Limits on a rule set's content, as clients enforce them on what they download.
const (
	MaxBody    = 32 << 20
	MaxEntries = 250000
	maxLine    = 8192
	// YAML larger than this is read line by line rather than parsed as a whole.
	maxParsedYAML = 4 << 20
)

var (
	ErrTooLarge = errors.New("rule set too large")
	ErrNoRules  = errors.New("no rules in the rule set")
	ErrWebPage  = errors.New("a web page, not a rule set")
)

// zstd's magic number, which starts MRS files.
var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// Content is a rule set's content in a form mihomo reads.
type Content struct {
	// The behavior the content needs: the declared one, or classical when the entries are not
	// all domains or all IP ranges.
	Behavior string
	// text, or mrs for MRS, which passes through unread.
	Format string
	// One entry per line for text.
	Body []byte
	// Entries in Body, and entries left out as invalid or without a counterpart.
	Entries, Skipped int
	Warnings         []model.Warning
}

// An entry of a rule set, read into one of mihomo's rule types. Domain entries keep how far
// they match: DOMAIN the name, DOMAIN-SUFFIX the name and its subdomains, subdomain its
// subdomains only, DOMAIN-WILDCARD a pattern.
type entry struct {
	kind, value string
	params      []string
}

const subdomains = "subdomains"

// Convert reads a rule set's content: Clash's YAML payload or text, Surge and Loon lists,
// Quantumult X filter lists, sing-box source JSON, or MRS. behavior and format are what the
// provider declares, as hints; the content decides.
func Convert(data []byte, behavior, format string) (*Content, error) {
	if len(data) > MaxBody {
		return nil, ErrTooLarge
	}
	behavior, format = Behavior(behavior), Format(format)
	if bytes.HasPrefix(data, zstdMagic) || format == "mrs" {
		if !bytes.HasPrefix(data, zstdMagic) {
			return nil, errors.New("not an MRS file")
		}
		if behavior != "domain" && behavior != "ipcidr" {
			return nil, errors.New("an MRS file holds domains or IP ranges, not " + or(behavior, "an unknown behavior"))
		}
		return &Content{Behavior: behavior, Format: "mrs", Body: data}, nil
	}
	text := bytes.TrimSpace(body.Clean(data))
	if body.WebPage(text) {
		return nil, ErrWebPage
	}
	c := &converter{}
	var lines []string
	switch {
	case len(text) > 0 && (text[0] == '{' || text[0] == '['):
		if err := c.singBox(body.JSONC(text)); err != nil {
			return nil, err
		}
	default:
		var ok bool
		if lines, ok = payload(text); !ok {
			lines = strings.Split(string(text), "\n")
		}
		for _, line := range lines {
			c.line(line)
			if len(c.entries) > MaxEntries {
				return nil, ErrTooLarge
			}
		}
	}
	if len(c.entries) > MaxEntries {
		return nil, ErrTooLarge
	}
	if len(c.entries) == 0 {
		return nil, ErrNoRules
	}
	out := c.render(behavior)
	for reason, count := range c.skipped {
		out.Warnings = append(out.Warnings, model.Warning{Code: model.WarnUnsupportedRule, Detail: fmt.Sprintf("%d entries: %s", count, reason)})
		out.Skipped += count
	}
	sortWarnings(out.Warnings)
	return out, nil
}

type converter struct {
	entries []entry
	skipped map[string]int
	// Whether the list writes "+.": then a leading dot means subdomains only, as in mihomo;
	// otherwise it means the domain too, as in Surge's DOMAIN-SET.
	plus, dots bool
}

func (c *converter) skip(reason string) {
	if c.skipped == nil {
		c.skipped = map[string]int{}
	}
	c.skipped[reason]++
}

// line reads one line of a text list or YAML payload.
func (c *converter) line(raw string) {
	line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "\uFEFF"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
		return
	}
	if len(line) > maxLine {
		c.skip("longer than 8192 characters")
		return
	}
	if !strings.Contains(line, ",") {
		c.bare(line)
		return
	}
	items := strings.Split(line, ",")
	for index := range items {
		items[index] = strings.TrimSpace(items[index])
	}
	kind := strings.ToUpper(items[0])
	if alias, ok := Aliases[kind]; ok {
		kind = alias
	}
	switch {
	case kind == "MATCH" || kind == "RULE-SET" || kind == "SUB-RULE":
		c.skip(kind + " inside a rule set")
		return
	case !Types[kind]:
		c.skip("rule type " + kind)
		return
	case CommaPayload[kind]:
		// The payload is the rest of the line; a list's rules have no policy.
		value := strings.Join(items[1:], ",")
		if kind == "AND" || kind == "OR" || kind == "NOT" {
			value = protocolRule.ReplaceAllStringFunc(value, func(match string) string {
				return "(NETWORK," + strings.ToLower(protocolRule.FindStringSubmatch(match)[1]) + ")"
			})
			if reason := logicalProblem(value); reason != "" {
				c.skip(reason)
				return
			}
		}
		c.entries = append(c.entries, entry{kind: kind, value: value})
		return
	}
	value := items[1]
	if value == "" {
		c.skip("empty values")
		return
	}
	var params []string
	for _, item := range items[2:] {
		// Quantumult X lists name a policy after the value; options stay.
		switch item = strings.ToLower(item); item {
		case "no-resolve", "src":
			params = append(params, item)
		}
	}
	switch kind {
	case "DOMAIN-SUFFIX":
		if strings.HasPrefix(value, "+.") || strings.HasPrefix(value, ".") {
			value = strings.TrimPrefix(strings.TrimPrefix(value, "+"), ".")
		}
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		prefix, ok := cidr(value)
		if !ok {
			c.skip("invalid IP ranges")
			return
		}
		value = prefix
		if kind == "IP-CIDR" && strings.Contains(value, ":") {
			kind = "IP-CIDR6"
		}
	}
	c.entries = append(c.entries, entry{kind: kind, value: value, params: params})
}

// bare reads an entry without a type: a domain list's or an IP list's.
func (c *converter) bare(value string) {
	value = strings.Trim(value, `"'`)
	if prefix, ok := cidr(value); ok {
		kind := "IP-CIDR"
		if strings.Contains(prefix, ":") {
			kind = "IP-CIDR6"
		}
		c.entries = append(c.entries, entry{kind: kind, value: prefix})
		return
	}
	switch {
	case strings.HasPrefix(value, "+."):
		c.plus = true
		c.entries = append(c.entries, entry{kind: "DOMAIN-SUFFIX", value: value[2:]})
	case strings.HasPrefix(value, "*."):
		c.entries = append(c.entries, entry{kind: "DOMAIN-WILDCARD", value: value})
	case strings.HasPrefix(value, "."):
		c.dots = true
		c.entries = append(c.entries, entry{kind: subdomains, value: value[1:]})
	default:
		if !domainName(value) {
			c.skip("not domains or IP ranges")
			return
		}
		c.entries = append(c.entries, entry{kind: "DOMAIN", value: value})
	}
}

// singBox reads a sing-box source rule set: its rules' domain, IP, port and process fields.
func (c *converter) singBox(data []byte) error {
	value, err := model.Decode(data)
	if err != nil {
		return fmt.Errorf("not a sing-box rule set: %w", err)
	}
	config := model.AsObject(value)
	rules := model.AsList(config.Value("rules"))
	if config == nil || rules == nil {
		return errors.New("not a sing-box rule set")
	}
	kinds := map[string]string{
		"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "domain_keyword": "DOMAIN-KEYWORD",
		"domain_regex": "DOMAIN-REGEX", "ip_cidr": "IP-CIDR", "source_ip_cidr": "SRC-IP-CIDR",
		"port": "DST-PORT", "port_range": "DST-PORT", "source_port": "SRC-PORT", "source_port_range": "SRC-PORT",
		"process_name": "PROCESS-NAME", "process_path": "PROCESS-PATH", "process_path_regex": "PROCESS-PATH-REGEX",
		"package_name": "PROCESS-NAME", "network": "NETWORK",
	}
	// Fields of these groups match any of their values; a rule of several groups needs all.
	groups := map[string]string{"domain": "address", "domain_suffix": "address", "domain_keyword": "address",
		"domain_regex": "address", "ip_cidr": "address", "port": "port", "port_range": "port",
		"source_ip_cidr": "source", "source_port": "source port", "source_port_range": "source port"}
	for _, item := range rules {
		rule := model.AsObject(item)
		seen := map[string]bool{}
		for _, field := range rule {
			if group := or(groups[field.Key], field.Key); kinds[field.Key] != "" {
				seen[group] = true
			}
		}
		switch {
		case rule.String("type") == "logical" || model.AsBool(rule.Value("invert")):
			c.skip("logical or inverted sing-box rules")
			continue
		case len(seen) > 1:
			c.skip("sing-box rules that match several kinds of field at once")
			continue
		}
		for _, field := range rule {
			kind := kinds[field.Key]
			if kind == "" {
				c.skip("sing-box field " + field.Key)
				continue
			}
			for _, value := range model.AsStrings(field.Value) {
				switch field.Key {
				case "domain_suffix":
					if strings.HasPrefix(value, ".") {
						// sing-box's ".example.com" matches subdomains only.
						c.entries = append(c.entries, entry{kind: subdomains, value: value[1:]})
						c.plus = true
						continue
					}
				case "ip_cidr", "source_ip_cidr":
					prefix, ok := cidr(value)
					if !ok {
						c.skip("invalid IP ranges")
						continue
					}
					value = prefix
					if kind == "IP-CIDR" && strings.Contains(value, ":") {
						kind = "IP-CIDR6"
					}
				case "port_range", "source_port_range":
					value = strings.ReplaceAll(value, ":", "-")
				case "network":
					value = strings.ToLower(value)
				}
				c.entries = append(c.entries, entry{kind: kind, value: value})
				if len(c.entries) > MaxEntries {
					return ErrTooLarge
				}
			}
		}
	}
	return nil
}

// render writes the entries in the behavior they fit: domain or ipcidr lists when every entry
// is one and the provider declares it (or declares nothing), classical rules otherwise.
func (c *converter) render(declared string) *Content {
	domains, ips := true, true
	for _, e := range c.entries {
		switch e.kind {
		case "DOMAIN", "DOMAIN-SUFFIX", subdomains, "DOMAIN-WILDCARD":
			ips = false
		case "IP-CIDR", "IP-CIDR6":
			domains = false
			if len(e.params) > 0 && e.params[0] == "src" {
				domains, ips = false, false
			}
		default:
			domains, ips = false, false
		}
	}
	behavior := "classical"
	switch {
	case domains && (declared == "domain" || declared == ""):
		behavior = "domain"
	case ips && (declared == "ipcidr" || declared == ""):
		behavior = "ipcidr"
	}
	// A leading dot means the domain too in lists that never write "+.", as Surge's do.
	surge := c.dots && !c.plus
	var buffer bytes.Buffer
	for _, e := range c.entries {
		kind := e.kind
		if kind == subdomains && surge {
			kind = "DOMAIN-SUFFIX"
		}
		switch behavior {
		case "domain":
			switch kind {
			case "DOMAIN-SUFFIX":
				buffer.WriteString("+.")
			case subdomains:
				buffer.WriteString(".")
			}
			buffer.WriteString(e.value)
		case "ipcidr":
			buffer.WriteString(e.value)
		default:
			if kind == subdomains {
				kind = "DOMAIN-SUFFIX" // classical rules have no subdomains-only type
			}
			buffer.WriteString(strings.Join(append([]string{kind, e.value}, e.params...), ","))
		}
		buffer.WriteByte('\n')
	}
	return &Content{Behavior: behavior, Format: "text", Body: buffer.Bytes(), Entries: len(c.entries)}
}

// payload reads Clash's YAML "payload:" list, line by line so that large lists need no YAML
// tree; it returns false for anything else.
func payload(text []byte) ([]string, bool) {
	var lines []string
	header := false
	for raw := range strings.SplitSeq(string(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || line == "---" || line == "...":
		case !header && line == "payload:":
			header = true
		case !header:
			if strings.HasPrefix(line, "payload:") {
				return flowPayload(text)
			}
			return nil, false
		case strings.HasPrefix(line, "- ") || line == "-":
			item := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if index := strings.Index(item, " #"); index >= 0 && !strings.HasPrefix(item, "'") && !strings.HasPrefix(item, `"`) {
				item = strings.TrimSpace(item[:index])
			}
			lines = append(lines, unquote(item))
		default:
			return flowPayload(text)
		}
	}
	return lines, header
}

// flowPayload parses a payload YAML can write other ways (flow lists, block scalars), when it is
// small enough to parse whole.
func flowPayload(text []byte) ([]string, bool) {
	if len(text) > maxParsedYAML {
		return nil, false
	}
	value, err := model.Decode(text)
	if err != nil {
		return nil, false
	}
	config := model.AsObject(value)
	if _, ok := config.Get("payload"); !ok {
		return nil, false
	}
	return model.AsStrings(config.Value("payload")), true
}

func unquote(item string) string {
	if len(item) >= 2 && (item[0] == '\'' && item[len(item)-1] == '\'' || item[0] == '"' && item[len(item)-1] == '"') {
		item = item[1 : len(item)-1]
		if item != "" && strings.Contains(item, "''") {
			item = strings.ReplaceAll(item, "''", "'")
		}
	}
	return item
}

// cidr reads an IP range, or an address as the range of itself.
func cidr(value string) (string, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.String(), true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()).String(), true
	}
	return "", false
}

// domainName reports a plausible domain name: dotted labels of letters, digits, hyphens and
// underscores, as lists write them.
func domainName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r > 127:
		default:
			return false
		}
	}
	return strings.Contains(value, ".") && !strings.HasPrefix(value, ".") && !strings.Contains(value, "..")
}

// Surge's PROTOCOL rule, which mihomo writes as NETWORK, inside logical rules.
var protocolRule = regexp.MustCompile(`(?i)\(\s*PROTOCOL\s*,\s*(TCP|UDP)\s*\)`)

// logicalProblem checks a logical rule's payload, "((TYPE,value),…)": balanced parentheses and
// rule types mihomo knows.
func logicalProblem(value string) string {
	depth := 0
	for index, r := range value {
		switch r {
		case '(':
			if depth == 1 {
				kind, _, _ := strings.Cut(value[index+1:], ",")
				kind = strings.ToUpper(strings.TrimSpace(kind))
				if alias, ok := Aliases[kind]; ok {
					kind = alias
				}
				if !Types[kind] || kind == "MATCH" || kind == "RULE-SET" {
					return "logical rules with " + kind
				}
			}
			depth++
		case ')':
			if depth--; depth < 0 {
				return "malformed logical rules"
			}
		}
	}
	if depth != 0 || !strings.HasPrefix(strings.TrimSpace(value), "(") {
		return "malformed logical rules"
	}
	return ""
}

func sortWarnings(warnings []model.Warning) {
	for i := 1; i < len(warnings); i++ {
		for j := i; j > 0 && warnings[j].Detail < warnings[j-1].Detail; j-- {
			warnings[j], warnings[j-1] = warnings[j-1], warnings[j]
		}
	}
}

func or(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
