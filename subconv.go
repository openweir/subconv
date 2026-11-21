// Package subconv converts subscriptions of any format into the OpenWeir subscription format,
// the Clash YAML the OpenWeir mihomo build reads: proxies, proxy providers, proxy groups, rule
// providers and rules.
//
// OpenWeir clients run the OpenWeir mihomo build (github.com/openweir/mihomo), which reads the
// Clash format plus native Naive, AnyTLS with REALITY and Nowhere NW3. Subscriptions arrive in
// many formats; Convert detects which and returns the Clash parts, each item checked so that the
// config loads. The rest of a config (ports, DNS, TUN, the controller) is each client's own.
//
// Converting does no I/O: bytes in, a Result out. Build makes a config to run of the parts, with
// the routing template it gets through the caller's rules.Client when the subscription's own
// routing is missing or too lossy. What the package does lives under internal/, each format in
// its own package (docs/architecture.md).
package subconv

import (
	"github.com/openweir/subconv/internal/convert"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/ruleset"
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

var (
	// ErrUnknownFormat is returned for input that is none of the formats.
	ErrUnknownFormat = convert.ErrUnknownFormat
	// ErrEmpty is returned for an empty body.
	ErrEmpty = convert.ErrEmpty
	// ErrWebPage is returned for an HTML page, which servers send for errors, logins and
	// challenges instead of a subscription.
	ErrWebPage = convert.ErrWebPage
	// ErrMessage is returned for a short text or JSON message instead of a subscription, such
	// as an expired token's; the error includes the message.
	ErrMessage = convert.ErrMessage
)

// Detect returns the format of a subscription. It fails with ErrUnknownFormat, which
// ErrEmpty, ErrWebPage and ErrMessage refine.
func Detect(data []byte) (Format, error) {
	format, _, err := convert.Detect(data)
	return format, err
}

// Convert converts a subscription of any supported format.
func Convert(data []byte) (*Result, error) {
	return ConvertWith(data, Options{})
}

// ConvertWith converts a subscription with options.
func ConvertWith(data []byte, options Options) (*Result, error) {
	return convert.Subscription(data, options.model())
}

// RuleSet is a rule provider's content in a form mihomo reads: Behavior and Format are what
// the provider must declare for Body, which may differ from what it declared.
type RuleSet = ruleset.Content

var (
	// ErrRuleSetTooLarge is returned for a rule set over 32 MiB or 250,000 entries.
	ErrRuleSetTooLarge = ruleset.ErrTooLarge
	// ErrNoRules is returned for a rule set with no entry mihomo can use.
	ErrNoRules = ruleset.ErrNoRules
)

// ConvertRuleSet converts the content of a rule provider a client downloaded: Clash's YAML
// payload or text list, MRS (which passes through), Surge and Loon lists, Quantumult X filter
// lists, or sing-box source JSON. behavior and format are what the provider declares; they are
// hints, and the content decides. Invalid entries are skipped and counted.
func ConvertRuleSet(data []byte, behavior, format string) (*RuleSet, error) {
	return convert.RuleSet(data, behavior, format)
}

// ConvertProxies converts the content of a proxy provider a client downloaded, in any format
// Convert reads, into its proxies, each repaired or left out on its own. Groups and rules in the
// content are not the provider's and are ignored; a dialer-proxy stays as written, since it
// names the config the provider joins.
func ConvertProxies(data []byte) (*Result, error) {
	return convert.Proxies(data)
}
