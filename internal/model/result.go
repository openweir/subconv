package model

import (
	"bytes"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Format names a subscription's format.
type Format string

const (
	FormatSingBox Format = "sing-box"
	FormatClash   Format = "clash"
	FormatLinks   Format = "links"
	// Surge, Surfboard and Loon configs and their [Proxy] lists.
	FormatSurge Format = "surge"
	// Quantumult X configs and their server_local lists.
	FormatQuantumultX Format = "quantumult-x"
	// Shadowsocks SIP008 JSON and SSD.
	FormatShadowsocks Format = "shadowsocks"
	// Xray and V2Ray JSON configs.
	FormatXray Format = "xray"
)

// Warning reports something the conversion left out or changed. Code is stable; Detail names
// the item.
type Warning struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Warning codes. A client should flag unsupported_rule and unsupported_rule_set: the routing
// differs from what the subscription meant.
const (
	// An outbound or proxy of a type OpenWeir mihomo has no counterpart for; it is left out.
	WarnUnsupportedProxy = "unsupported_proxy"
	// An option of a supported proxy that cannot be represented; the proxy is left out.
	WarnUnsupportedOption = "unsupported_option"
	// A proxy that is broken: no server, port or credentials, or a value mihomo refuses. It is
	// left out.
	WarnInvalidProxy = "invalid_proxy"
	// An option that was removed while the item it belongs to was kept: an option the client
	// decides (interface-name, routing-mark), a local file, or a value mihomo refuses.
	WarnIgnoredOption = "ignored_option"
	// A rule left out: a condition or action with no Clash counterpart, a malformed rule, or a
	// rule whose policy or rule set does not exist.
	WarnUnsupportedRule = "unsupported_rule"
	// A rule set mihomo cannot read or reach; the rules that use it are left out.
	WarnUnsupportedRuleSet = "unsupported_rule_set"
	// A proxy provider that cannot be used, such as a local file; groups stop using it.
	WarnUnsupportedProvider = "unsupported_provider"
	// A group of a type mihomo lacks, or a relay that cannot become a dialer-proxy chain; it is
	// left out and references to it are removed.
	WarnUnsupportedGroup = "unsupported_group"
	// A group member or dialer-proxy that names something left out or never defined; the
	// reference is removed.
	WarnUnknownReference = "unknown_reference"
	// Groups or dialer-proxy chains that refer to each other in a loop; one reference is
	// removed to break it.
	WarnCyclicReference = "cyclic_reference"
	// A group left with no members; it is left out and references to it are removed.
	WarnEmptyGroup = "empty_group"
	// An empty, duplicate or reserved name that was given a unique one.
	WarnRenamed = "renamed"
)

// Result holds the converted parts, ready to place in a mihomo config.
type Result struct {
	Format         Format    `json:"format"`
	Proxies        []Object  `json:"proxies"`
	ProxyProviders Object    `json:"proxy-providers,omitempty"`
	Groups         []Object  `json:"proxy-groups"`
	RuleProviders  Object    `json:"rule-providers"`
	Rules          []string  `json:"rules"`
	Warnings       []Warning `json:"warnings"`
}

// Warn records a warning.
func (r *Result) Warn(code, format string, args ...any) {
	r.Warnings = append(r.Warnings, Warning{code, fmt.Sprintf(format, args...)})
}

// YAML renders the parts as a mihomo config fragment.
func (r *Result) YAML() ([]byte, error) {
	document := New(
		"proxies", toAny(r.Proxies),
		"proxy-providers", r.ProxyProviders,
		"proxy-groups", toAny(r.Groups),
		"rule-providers", r.RuleProviders,
		"rules", r.Rules,
	)
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return buffer.Bytes(), encoder.Close()
}

func toAny(objects []Object) []any {
	out := make([]any, len(objects))
	for index, o := range objects {
		out[index] = o
	}
	return out
}

// Options adjust a conversion; the zero value is the default.
type Options struct {
	// ConvertsRuleSets says that the caller downloads rule providers itself and passes their
	// bodies through ConvertRuleSet. Rule sets whose content mihomo cannot read (sing-box source
	// JSON, Quantumult X filter lists) are then kept as http providers instead of left out.
	ConvertsRuleSets bool
}
