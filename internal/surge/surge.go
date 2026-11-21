// Package surge converts the line configs of Surge, Surfboard, Loon, Shadowrocket and
// Quantumult X: INI-like sections whose lines declare proxies, groups and rules.
package surge

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/ruleset"
)

var errNotAConfig = errors.New("not a line config")

// Sections each dialect knows, by lowercase name.
var (
	surgeSections   = set("general", "proxy", "proxy group", "rule", "host", "url rewrite", "header rewrite", "mitm", "script", "replica", "map local", "body rewrite", "keystore", "panel", "ssid setting", "snell server")
	loonSections    = set("remote proxy", "remote filter", "remote rule", "proxy chain", "plugin", "remote script")
	quantumultX     = set("server_local", "server_remote", "filter_local", "filter_remote", "policy", "rewrite_local", "rewrite_remote", "task_local", "dns", "http_backend")
	quantumultNodes = []string{"shadowsocks=", "vmess=", "vless=", "trojan=", "http=", "socks5=", "hysteria2="}
)

// Detect names the dialect of a line config, or returns "" for anything else. A config needs a
// section the dialects share or a Quantumult X proxy line; comments and sections name the
// dialect.
func Detect(text []byte) model.Format {
	var format, marker model.Format
	general := false
	for _, raw := range strings.Split(string(text), "\n") {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "#") || strings.HasPrefix(lower, ";") || strings.HasPrefix(lower, "//"):
			switch {
			case marker != "":
			case strings.Contains(lower, "shadowrocket"):
				marker = model.FormatShadowrocket
			case strings.Contains(lower, "surfboard"):
				marker = model.FormatSurfboard
			}
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			name := strings.TrimSpace(lower[1 : len(lower)-1])
			switch {
			case name == "panel":
				marker = model.FormatSurfboard
				format = model.FormatSurge
			case loonSections[name]:
				marker = model.FormatLoon
				format = model.FormatSurge
			case quantumultX[name]:
				format = model.FormatQuantumultX
			case surgeSections[name] || strings.HasPrefix(name, "wireguard "):
				if format == "" {
					format = model.FormatSurge
				}
				general = general || name == "general"
			}
		case general && (strings.HasPrefix(lower, "bypass-system") || strings.HasPrefix(lower, "private-ip-answer")):
			marker = model.FormatShadowrocket
		case format == "" && quantumultNode(lower):
			format = model.FormatQuantumultX
		}
	}
	if format == model.FormatSurge && marker != "" {
		return marker
	}
	return format
}

func quantumultNode(lower string) bool {
	for _, prefix := range quantumultNodes {
		if rest, ok := strings.CutPrefix(lower, prefix); ok && strings.Contains(rest, ":") {
			return true
		}
	}
	return false
}

type converter struct {
	result  *model.Result
	options model.Options
	format  model.Format
	// Names that mean a built-in policy: Surge's "name = direct" lines and Quantumult X's words.
	aliases map[string]string
	// WireGuard sections, by name, for Surge's section-name.
	wireguard map[string][]string
	names     map[string]bool
}

// Convert converts a line config of the given dialect.
func Convert(data []byte, format model.Format, options model.Options) (*model.Result, error) {
	if format == "" {
		return nil, errNotAConfig
	}
	c := &converter{
		result:    &model.Result{Format: format},
		options:   options,
		format:    format,
		aliases:   map[string]string{},
		wireguard: map[string][]string{},
		names:     map[string]bool{},
	}
	sections := c.sections(string(data))
	for _, name := range []string{"", "proxy", "server_local"} {
		for _, line := range sections[name] {
			c.node(line, name == "server_local" || name == "" && format == model.FormatQuantumultX)
		}
	}
	for _, line := range sections["proxy chain"] {
		c.chain(line)
	}
	for _, line := range sections["proxy group"] {
		c.group(line, false)
	}
	for _, line := range sections["policy"] {
		c.group(line, true)
	}
	for _, name := range []string{"remote rule", "filter_remote", "remote filter"} {
		for _, line := range sections[name] {
			c.remoteRules(name, line)
		}
	}
	for _, name := range []string{"rule", "rules", "filter_local"} {
		for _, line := range sections[name] {
			c.rule(line)
		}
	}
	c.quantumultProxy()
	return c.result, nil
}

// sections splits a config into its sections' lines, without comments and blank lines. Lines
// before any section are under "".
func (c *converter) sections(text string) map[string][]string {
	out := map[string][]string{}
	var order []string
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if name, ok := strings.CutPrefix(section, "wireguard "); ok {
			c.wireguard[name] = append(c.wireguard[name], line)
			continue
		}
		if out[section] == nil {
			order = append(order, section)
		}
		out[section] = append(out[section], line)
	}
	for _, name := range order {
		lines := out[name]
		switch name {
		case "", "proxy", "server_local", "proxy group", "policy", "rule", "rules", "filter_local",
			"remote rule", "filter_remote", "remote filter", "proxy chain":
		case "url rewrite", "header rewrite", "map local", "body rewrite", "script", "rewrite_local",
			"rewrite_remote", "plugin", "remote script":
			// They block and redirect requests, which mihomo's rules cannot.
			c.result.Warn(model.WarnUnsupportedRule, "section [%s]: %d lines", name, len(lines))
		case "remote proxy", "server_remote":
			for _, line := range lines {
				link, _, _ := strings.Cut(line, ",")
				if name, url, named := strings.Cut(link, "="); named && strings.Contains(url, "://") {
					link = name // Loon's "Name = url"
				}
				c.result.Warn(model.WarnUnsupportedProvider, "%s: a remote server list in the client's own format", label(strings.TrimSpace(link)))
			}
		}
	}
	return out
}

// chain turns Loon's "name = a, b, c" proxy chains into relay groups, which become
// dialer-proxy chains.
func (c *converter) chain(line string) {
	name, spec, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	var members []any
	for _, part := range fields(spec) {
		if !strings.Contains(part, "=") {
			members = append(members, c.policy(part))
		}
	}
	c.result.Groups = append(c.result.Groups, model.New("name", strings.TrimSpace(name), "type", "relay", "proxies", members))
}

// Group types, by the names each dialect uses.
var groupTypes = map[string]string{
	"select":                "select",
	"static":                "select",
	"url-test":              "url-test",
	"url":                   "url-test",
	"smart":                 "url-test",
	"url-latency-benchmark": "url-test",
	"fallback":              "fallback",
	"available":             "fallback",
	"load-balance":          "load-balance",
	"round-robin":           "load-balance",
	"dest-hash":             "load-balance",
}

// group converts "Name = type, a, b, key=value" (Surge, Loon) or Quantumult X's
// "type=Name, a, b, key=value".
func (c *converter) group(line string, quantumult bool) {
	key, spec, ok := strings.Cut(line, "=")
	if !ok {
		c.result.Warn(model.WarnUnsupportedGroup, "%s: not a group", label(line))
		return
	}
	parts := fields(spec)
	if len(parts) == 0 {
		return
	}
	name, kind := strings.TrimSpace(key), strings.ToLower(parts[0])
	if quantumult {
		name, kind = parts[0], strings.ToLower(strings.TrimSpace(key))
	}
	clash := groupTypes[kind]
	if clash == "" {
		c.result.Warn(model.WarnUnsupportedGroup, "%s: type %s", name, kind)
		return
	}
	group := model.Object{{Key: "name", Value: name}, {Key: "type", Value: clash}}
	var members []any
	for _, part := range parts[1:] {
		option, value, isOption := strings.Cut(part, "=")
		if !isOption {
			members = append(members, c.policy(part))
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch option = strings.ToLower(strings.TrimSpace(option)); option {
		case "url", "test-url":
			group.Set("url", value)
		case "interval", "check-interval", "update-interval":
			if n, err := strconv.Atoi(value); err == nil && option != "update-interval" {
				group.Set("interval", n)
			}
		case "tolerance":
			if n, err := strconv.Atoi(value); err == nil {
				group.Set("tolerance", n)
			}
		case "timeout":
			if n, err := strconv.Atoi(value); err == nil {
				group.Set("timeout", n*1000) // seconds to mihomo's milliseconds
			}
		case "hidden":
			if b, ok := model.Bool(value); ok && b {
				group.Set("hidden", true)
			}
		case "include-all-proxies":
			if b, ok := model.Bool(value); ok && b {
				group.Set("include-all-proxies", true)
			}
		case "policy-regex-filter", "server-tag-regex", "filter":
			group.Set("filter", value)
			if quantumult || option == "server-tag-regex" {
				group.Set("include-all-proxies", true)
			}
		case "policy-path", "resource-tag-regex", "include-other-group":
			c.result.Warn(model.WarnIgnoredOption, "%s: %s (a list in the client's own format)", name, option)
		}
	}
	switch kind {
	case "round-robin":
		group.Set("strategy", "round-robin")
	case "dest-hash":
		group.Set("strategy", "consistent-hashing")
	}
	if len(members) > 0 {
		group.InsertAfter("type", "proxies", members)
	}
	c.result.Groups = append(c.result.Groups, group)
}

// policy maps a group member or rule policy: built-ins in the case mihomo writes them, and
// names that mean one.
func (c *converter) policy(name string) string {
	name = strings.Trim(strings.TrimSpace(name), `"`)
	if alias, ok := c.aliases[name]; ok {
		return alias
	}
	switch upper := strings.ToUpper(name); upper {
	case "DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "REJECT-NO-DROP", "REJECT-200", "REJECT-IMG", "REJECT-DICT", "REJECT-ARRAY":
		return upper
	}
	return name
}

// rule converts a rule line. Surge's and Quantumult X's types are mihomo's under other names,
// which the normalization maps; rule sets named by URL become providers.
func (c *converter) rule(line string) {
	parts := fields(line)
	if len(parts) < 2 {
		return
	}
	kind := strings.ToUpper(parts[0])
	switch kind {
	case "FINAL", "MATCH":
		c.result.Rules = append(c.result.Rules, "MATCH,"+c.policy(parts[1]))
		return
	case "RULE-SET", "DOMAIN-SET":
		if len(parts) < 3 {
			break
		}
		source := parts[1]
		switch strings.ToUpper(source) {
		case "LAN":
			c.result.Rules = append(c.result.Rules, "GEOIP,lan,"+c.policy(parts[2])+",no-resolve")
			return
		case "SYSTEM":
			c.result.Warn(model.WarnUnsupportedRule, "%s: Apple's system rule set", line)
			return
		}
		behavior := "classical"
		if kind == "DOMAIN-SET" {
			behavior = "domain"
		}
		name := c.provider(source, behavior, 0)
		if name == "" {
			c.result.Warn(model.WarnUnsupportedRule, "%s: rule set %s is not a web URL", line, source)
			return
		}
		c.result.Rules = append(c.result.Rules, strings.Join(append([]string{"RULE-SET", name, c.policy(parts[2])}, parts[3:]...), ","))
		return
	case "PROTOCOL":
		switch strings.ToUpper(parts[1]) {
		case "TCP", "UDP":
			if len(parts) > 2 {
				c.result.Rules = append(c.result.Rules, "NETWORK,"+strings.ToLower(parts[1])+","+c.policy(parts[2]))
				return
			}
		}
	}
	if len(parts) >= 3 && !strings.HasPrefix(kind, "AND") && !strings.HasPrefix(kind, "OR") && !strings.HasPrefix(kind, "NOT") {
		parts[2] = c.policy(parts[2])
		parts[0] = kind
		c.result.Rules = append(c.result.Rules, strings.Join(parts, ","))
		return
	}
	// A logical rule: the policy is the last field.
	index := strings.LastIndex(line, ",")
	c.result.Rules = append(c.result.Rules, protocolRule.ReplaceAllStringFunc(line[:index], func(match string) string {
		return "(NETWORK," + strings.ToLower(match[strings.LastIndex(match, ",")+1:len(match)-1]) + ")"
	})+","+c.policy(line[index+1:]))
}

var protocolRule = regexp.MustCompile(`(?i)\(\s*PROTOCOL\s*,\s*(TCP|UDP)\s*\)`)

// remoteRules converts Loon's [Remote Rule] and Quantumult X's [filter_remote] lines:
// "url, policy=X, tag=Y, enabled=true" and "url, tag=Y, force-policy=X". Their lists carry the
// policy of each rule unless one is forced, and Quantumult X's are in its own format.
func (c *converter) remoteRules(section, line string) {
	parts := fields(line)
	if len(parts) == 0 {
		return
	}
	source := parts[0]
	options := map[string]string{}
	for _, part := range parts[1:] {
		if key, value, ok := strings.Cut(part, "="); ok {
			options[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	if enabled, ok := model.Bool(options["enabled"]); ok && !enabled && options["enabled"] != "" {
		return
	}
	policy := or(options["policy"], options["force-policy"])
	at := or(options["tag"], label(source))
	if policy == "" {
		c.result.Warn(model.WarnUnsupportedRuleSet, "%s: a list that names a policy per rule", at)
		return
	}
	if section == "filter_remote" && !c.options.ConvertsRuleSets {
		c.result.Warn(model.WarnUnsupportedRuleSet, "%s: a Quantumult X list, which mihomo cannot read", at)
		return
	}
	interval, _ := strconv.Atoi(options["update-interval"])
	name := c.provider(source, "classical", interval)
	if name == "" {
		c.result.Warn(model.WarnUnsupportedRuleSet, "%s: not a web URL", at)
		return
	}
	c.result.Rules = append(c.result.Rules, "RULE-SET,"+name+","+c.policy(policy))
}

// provider adds an http rule provider for a list and returns its name, or "".
func (c *converter) provider(source, behavior string, interval int) string {
	if !ruleset.WebURL(source) {
		return ""
	}
	for _, field := range c.result.RuleProviders {
		if model.AsObject(field.Value).String("url") == source {
			return field.Key
		}
	}
	u, _ := url.Parse(source)
	base := strings.TrimSuffix(path.Base(u.Path), path.Ext(u.Path))
	if base == "" || base == "." || base == "/" {
		base = u.Hostname()
	}
	name := base
	for n := 2; c.result.RuleProviders.Value(name) != nil; n++ {
		name = fmt.Sprintf("%s %d", base, n)
	}
	if interval == 0 {
		interval = 86400
	}
	c.result.RuleProviders.Set(name, model.New("type", "http", "behavior", behavior, "format", "text", "url", source, "interval", interval))
	return name
}

// quantumultProxy gives Quantumult X's built-in "proxy" policy a group when the config uses it
// without defining one: a select group of every proxy.
func (c *converter) quantumultProxy() {
	if c.format != model.FormatQuantumultX {
		return
	}
	used := false
	for _, rule := range c.result.Rules {
		if strings.EqualFold(rule[strings.LastIndex(rule, ",")+1:], "proxy") {
			used = true
		}
	}
	for _, group := range c.result.Groups {
		for _, member := range model.AsStrings(group.Value("proxies")) {
			used = used || strings.EqualFold(member, "proxy")
		}
		if strings.EqualFold(group.String("name"), "proxy") {
			return
		}
	}
	for _, p := range c.result.Proxies {
		if strings.EqualFold(p.String("name"), "proxy") {
			return
		}
	}
	if used {
		c.result.Groups = append(c.result.Groups, model.New("name", "proxy", "type", "select", "include-all-proxies", true))
	}
}

// fields splits a comma-separated line, keeping commas inside quotes and brackets, and trims
// each field and its quotes.
func fields(line string) []string {
	out := split(line)
	for index := range out {
		out[index] = trim(out[index])
	}
	return out
}

// split splits a comma-separated line, keeping commas inside quotes and brackets.
func split(line string) []string {
	var out []string
	depth, quoted, start := 0, false, 0
	for index, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case quoted:
		case r == '[' || r == '(' || r == '{':
			depth++
		case r == ']' || r == ')' || r == '}':
			depth--
		case r == ',' && depth == 0:
			out = append(out, line[start:index])
			start = index + 1
		}
	}
	return append(out, line[start:])
}

func trim(field string) string {
	field = strings.TrimSpace(field)
	if len(field) >= 2 && field[0] == '"' && field[len(field)-1] == '"' {
		return field[1 : len(field)-1]
	}
	return field
}

func label(text string) string {
	if u, err := url.Parse(text); err == nil && u.Host != "" {
		return u.Host + u.Path
	}
	if len(text) > 60 {
		return text[:57] + "..."
	}
	return text
}

func or(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func set(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, name := range names {
		out[name] = true
	}
	return out
}
