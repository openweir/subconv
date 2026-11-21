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
	"github.com/openweir/subconv/internal/shadowsocks"
	"github.com/openweir/subconv/internal/singbox"
	"github.com/openweir/subconv/internal/surge"
	"github.com/openweir/subconv/internal/xray"
	"github.com/openweir/subconv/rules"
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
	// RuleStats count a subscription's rules and how many converted.
	RuleStats = model.RuleStats
	// TemplateUse reports the routing template Build applied.
	TemplateUse = model.TemplateUse
)

// Options adjust a conversion; the zero value is Convert's.
type Options struct {
	// ConvertsRuleSets says that the caller downloads rule providers itself and passes their
	// bodies through ConvertRuleSet. Rule sets whose content mihomo cannot read (sing-box source
	// JSON, Quantumult X filter lists) are then kept as http providers instead of left out.
	ConvertsRuleSets bool

	// The rest is Build's.

	// Rules chooses the routing: RulesAuto (the default), RulesTemplate or RulesSubscription.
	Rules string
	// Client gets the routing template from the rules branch; nil is a rules.Client with the
	// default hosts and http.DefaultClient, without a cache. The caller's client carries its
	// routing, cache and MinVersion.
	Client *rules.Client
	// Head puts the OpenWeir default head (Head) in front of the parts, making a complete
	// config.
	Head bool
}

func (o Options) model() model.Options {
	return model.Options{ConvertsRuleSets: o.ConvertsRuleSets}
}

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
	WarnInvalidCredential   = model.WarnInvalidCredential
	WarnIgnoredOption       = model.WarnIgnoredOption
	WarnUnsupportedRule     = model.WarnUnsupportedRule
	WarnUnsupportedRuleSet  = model.WarnUnsupportedRuleSet
	WarnUnsupportedProvider = model.WarnUnsupportedProvider
	WarnUnsupportedGroup    = model.WarnUnsupportedGroup
	WarnUnknownReference    = model.WarnUnknownReference
	WarnCyclicReference     = model.WarnCyclicReference
	WarnEmptyGroup          = model.WarnEmptyGroup
	WarnRenamed             = model.WarnRenamed
	WarnLocalProvider       = model.WarnLocalProvider
	WarnTemplateApplied     = model.WarnTemplateApplied
	WarnTemplateUnavailable = model.WarnTemplateUnavailable
)

// Why Build applied the routing template (TemplateUse.Reason).
const (
	TemplateRequested = model.TemplateRequested
	TemplateNoRules   = model.TemplateNoRules
	TemplateNoMatch   = model.TemplateNoMatch
	TemplateDropped   = model.TemplateDropped
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
	result, err := convert(format, payload, options.model())
	if err != nil {
		return nil, err
	}
	normalize.Result(result, options.model())
	return result, nil
}

// convert hands a detected body to its format's package.
func convert(format Format, payload []byte, options model.Options) (*Result, error) {
	switch format {
	case FormatSingBox:
		return singbox.Convert(payload, options)
	case FormatClash, FormatStash:
		return clash.Convert(payload)
	case FormatSurge, FormatSurfboard, FormatLoon, FormatShadowrocket, FormatQuantumultX:
		return surge.Convert(payload, format, options)
	case FormatSIP008:
		return shadowsocks.ConvertSIP008(payload)
	case FormatSSD:
		return shadowsocks.ConvertSSD(payload)
	case FormatXray:
		return xray.Convert(payload)
	default:
		return links.Convert(payload)
	}
}
