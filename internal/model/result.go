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
)

// Warning reports something the conversion left out. Code is stable; Detail names the item.
type Warning struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Warning codes.
const (
	// An outbound or proxy of a type OpenWeir mihomo has no counterpart for.
	WarnUnsupportedProxy = "unsupported_proxy"
	// An option of a supported proxy that cannot be represented; the proxy is left out.
	WarnUnsupportedOption = "unsupported_option"
	// A rule condition or action with no Clash counterpart; the rule is left out.
	WarnUnsupportedRule = "unsupported_rule"
	// A rule set mihomo cannot read; the rules that use it are left out.
	WarnUnsupportedRuleSet = "unsupported_rule_set"
	// A group or rule that names an outbound the conversion left out or never saw.
	WarnUnknownReference = "unknown_reference"
	// A group left with no members; it falls back to DIRECT.
	WarnEmptyGroup = "empty_group"
)

// Result holds the converted parts, ready to place in a mihomo config.
type Result struct {
	Format        Format    `json:"format"`
	Proxies       []Object  `json:"proxies"`
	Groups        []Object  `json:"proxy-groups"`
	RuleProviders Object    `json:"rule-providers"`
	Rules         []string  `json:"rules"`
	Warnings      []Warning `json:"warnings"`
}

// Warn records a warning.
func (r *Result) Warn(code, format string, args ...any) {
	r.Warnings = append(r.Warnings, Warning{code, fmt.Sprintf(format, args...)})
}

// YAML renders the parts as a mihomo config fragment.
func (r *Result) YAML() ([]byte, error) {
	document := New(
		"proxies", toAny(r.Proxies),
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
