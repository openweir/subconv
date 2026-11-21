// Package subconv converts subscriptions of any format into the OpenWeir subscription format,
// the Clash YAML the OpenWeir mihomo build reads: proxies, proxy providers, proxy groups, rule
// providers and rules.
//
// OpenWeir clients run the OpenWeir mihomo build (github.com/openweir/mihomo), which reads the
// Clash format plus native Naive, AnyTLS with REALITY and Nowhere NW3. Subscriptions arrive in
// many formats; Convert detects which and returns the Clash parts, each item checked so that the
// config loads. The rest of a config (ports, DNS, TUN, the controller) is each client's own.
//
// The package does no I/O: bytes in, a Result out. Each format lives in its own package under
// internal/ (docs/architecture.md).
package subconv

import (
	"github.com/openweir/subconv/internal/clash"
	"github.com/openweir/subconv/internal/links"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
	"github.com/openweir/subconv/internal/singbox"
	"github.com/openweir/subconv/internal/surge"
)

type (
	// Format names a subscription's format.
	Format = model.Format
	// Result holds the converted parts; Result.YAML renders them.
	Result = model.Result
	// Warning reports something the conversion left out or changed.
	Warning = model.Warning
	// Object is a mapping that keeps its keys in order.
	Object = model.Object
	// Field is one key of an Object.
	Field = model.Field
	// Options adjust a conversion; the zero value is Convert's.
	Options = model.Options
)

// Formats Detect names; docs/conversion.md describes each.
const (
	FormatSingBox      = model.FormatSingBox
	FormatClash        = model.FormatClash
	FormatStash        = model.FormatStash
	FormatLinks        = model.FormatLinks
	FormatSurge        = model.FormatSurge
	FormatSurfboard    = model.FormatSurfboard
	FormatLoon         = model.FormatLoon
	FormatShadowrocket = model.FormatShadowrocket
	FormatQuantumultX  = model.FormatQuantumultX
	FormatSIP008       = model.FormatSIP008
	FormatSSD          = model.FormatSSD
	FormatXray         = model.FormatXray
)

// Warning codes; docs/conversion.md lists what each covers.
const (
	WarnUnsupportedProxy    = model.WarnUnsupportedProxy
	WarnUnsupportedOption   = model.WarnUnsupportedOption
	WarnInvalidProxy        = model.WarnInvalidProxy
	WarnIgnoredOption       = model.WarnIgnoredOption
	WarnUnsupportedRule     = model.WarnUnsupportedRule
	WarnUnsupportedRuleSet  = model.WarnUnsupportedRuleSet
	WarnUnsupportedProvider = model.WarnUnsupportedProvider
	WarnUnsupportedGroup    = model.WarnUnsupportedGroup
	WarnUnknownReference    = model.WarnUnknownReference
	WarnCyclicReference     = model.WarnCyclicReference
	WarnEmptyGroup          = model.WarnEmptyGroup
	WarnRenamed             = model.WarnRenamed
)

// Detect returns the format of a subscription. It fails with ErrUnknownFormat, which
// ErrEmpty, ErrWebPage and ErrMessage refine.
func Detect(data []byte) (Format, error) {
	format, _, err := detect(data, 0)
	return format, err
}

// Convert converts a subscription of any supported format.
func Convert(data []byte) (*Result, error) {
	return ConvertWith(data, Options{})
}

// ConvertWith converts a subscription with options.
func ConvertWith(data []byte, options Options) (*Result, error) {
	format, payload, err := detect(data, 0)
	if err != nil {
		return nil, err
	}
	var result *Result
	switch format {
	case FormatSingBox:
		result, err = singbox.Convert(payload, options)
	case FormatClash:
		result, err = clash.Convert(payload)
	case FormatSurge, FormatSurfboard, FormatLoon, FormatShadowrocket, FormatQuantumultX:
		result, err = surge.Convert(payload, format, options)
	default:
		result, err = links.Convert(payload)
	}
	if err != nil {
		return nil, err
	}
	normalize.Result(result, options)
	return result, nil
}
