// Package subconv converts subscriptions of any format into the OpenWeir subscription format,
// the Clash YAML the OpenWeir mihomo build reads: proxies, proxy groups, rule providers and rules.
//
// OpenWeir clients run the OpenWeir mihomo build (github.com/openweir/mihomo), which reads the
// Clash format plus native Naive, AnyTLS with REALITY and Nowhere NW3. Subscriptions arrive as
// sing-box JSON, Clash YAML or share links; Convert detects which and returns the Clash parts.
// The rest of a config (ports, DNS, TUN, the controller) is each client's own.
//
// The package does no I/O: bytes in, a Result out. Each format lives in its own package under
// internal/ (docs/architecture.md).
package subconv

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/openweir/subconv/internal/clash"
	"github.com/openweir/subconv/internal/links"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
	"github.com/openweir/subconv/internal/singbox"
	"go.yaml.in/yaml/v3"
)

type (
	// Format names a subscription's format.
	Format = model.Format
	// Result holds the converted parts; Result.YAML renders them.
	Result = model.Result
	// Warning reports something the conversion left out.
	Warning = model.Warning
	// Object is a mapping that keeps its keys in order.
	Object = model.Object
	// Field is one key of an Object.
	Field = model.Field
)

const (
	FormatSingBox = model.FormatSingBox
	FormatClash   = model.FormatClash
	FormatLinks   = model.FormatLinks
)

// Warning codes; see internal/model.
const (
	WarnUnsupportedProxy   = model.WarnUnsupportedProxy
	WarnUnsupportedOption  = model.WarnUnsupportedOption
	WarnUnsupportedRule    = model.WarnUnsupportedRule
	WarnUnsupportedRuleSet = model.WarnUnsupportedRuleSet
	WarnUnknownReference   = model.WarnUnknownReference
	WarnEmptyGroup         = model.WarnEmptyGroup
)

// ErrUnknownFormat is returned for input that is none of the formats.
var ErrUnknownFormat = errors.New("not a sing-box, Clash or share-link subscription")

// Detect returns the format of a subscription.
func Detect(data []byte) (Format, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trimmed) == 0 {
		return "", ErrUnknownFormat
	}
	if trimmed[0] == '{' {
		var probe struct {
			Outbounds json.RawMessage `json:"outbounds"`
			Endpoints json.RawMessage `json:"endpoints"`
			Proxies   json.RawMessage `json:"proxies"`
		}
		if json.Unmarshal(trimmed, &probe) == nil {
			switch {
			case probe.Outbounds != nil || probe.Endpoints != nil:
				return FormatSingBox, nil
			case probe.Proxies != nil:
				return FormatClash, nil
			}
		}
	}
	var probe map[string]any
	if yaml.Unmarshal(trimmed, &probe) == nil {
		if _, ok := probe["proxies"]; ok {
			return FormatClash, nil
		}
		if _, ok := probe["proxy-providers"]; ok {
			return FormatClash, nil
		}
	}
	if looksLikeLinks(trimmed) {
		return FormatLinks, nil
	}
	return "", ErrUnknownFormat
}

// Convert converts a subscription of any supported format.
func Convert(data []byte) (*Result, error) {
	format, err := Detect(data)
	if err != nil {
		return nil, err
	}
	var result *Result
	switch format {
	case FormatSingBox:
		result, err = singbox.Convert(data)
	case FormatClash:
		result, err = clash.Convert(data)
	default:
		result, err = links.Convert(data)
	}
	if err != nil {
		return nil, err
	}
	normalize.Result(result, model.Options{})
	return result, nil
}

func looksLikeLinks(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte("://")) {
			return true
		}
	}
	// Base64 of links, as most providers serve them.
	return isBase64(data)
}

func isBase64(data []byte) bool {
	for _, b := range data {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '+', b == '/', b == '=', b == '-', b == '_', b == '\r', b == '\n':
		default:
			return false
		}
	}
	return len(data) >= 16
}
