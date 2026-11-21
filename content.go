package subconv

import (
	"errors"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
	"github.com/openweir/subconv/internal/ruleset"
)

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
	content, err := ruleset.Convert(data, behavior, format)
	if errors.Is(err, ruleset.ErrWebPage) {
		return nil, &inputError{kind: ErrWebPage}
	}
	return content, err
}

// ConvertProxies converts the content of a proxy provider a client downloaded, in any format
// Convert reads, into its proxies, each repaired or left out on its own. Groups and rules in the
// content are not the provider's and are ignored; a dialer-proxy stays as written, since it
// names the config the provider joins.
func ConvertProxies(data []byte) (*Result, error) {
	format, payload, err := detect(data, 0)
	if err != nil {
		return nil, err
	}
	result, err := convert(format, payload, model.Options{})
	if err != nil {
		return nil, err
	}
	normalize.Proxies(result)
	return result, nil
}
