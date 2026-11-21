package subconv

import (
	"context"
	"errors"
	"fmt"

	"github.com/openweir/subconv/internal/build"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/rules"
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

// Routing choices for Options.Rules.
const (
	// RulesAuto uses the subscription's rules unless it has none, its final rule did not
	// survive, or more than a tenth of its rules were left out; then the routing template.
	RulesAuto = ""
	// RulesTemplate always uses the routing template.
	RulesTemplate = "template"
	// RulesSubscription never does.
	RulesSubscription = "subscription"
)

// ErrUnknownRules is returned for an Options.Rules that is none of the Rules* choices.
var ErrUnknownRules = errors.New("unknown routing choice")

// Head is the OpenWeir default head: the settings of a complete config before its proxies,
// exactly as the OpenWeir panel's template writes them (api-edge's
// resources/subscriptions/openweir.liquid.txt). Build puts it in front of the converted parts
// when Options.Head is set.
const Head = build.Head

// Build converts a subscription into a config a client runs: Convert's parts, with the routing
// template from the rules branch (package rules) in place of the subscription's groups, rule
// providers and rules when Options.Rules asks for it or the subscription's own routing is
// missing or too lossy, and with the OpenWeir default head when Options.Head is set.
//
// Result.Template says whether and why the template was applied, as does a template_applied
// warning. When the template is needed but unavailable (rules.ErrNoTemplate, or a template
// that fails rules.Validate), Build returns the plain conversion with a template_unavailable
// warning. It fails when the subscription does not convert and when ctx ends.
func Build(ctx context.Context, data []byte, options Options) (*Result, error) {
	result, err := ConvertWith(data, options)
	if err != nil {
		return nil, err
	}
	if options.Head {
		result.Head = Head
	}
	reason, err := templateReason(options.Rules, result.RuleStats)
	if err != nil || reason == "" {
		return result, err
	}
	client := options.Client
	if client == nil {
		client = &rules.Client{}
	}
	template, err := client.Template(ctx)
	switch {
	case errors.Is(err, rules.ErrNoTemplate):
		result.Warn(model.WarnTemplateUnavailable, "%v", err)
		return result, nil
	case err != nil:
		return nil, err
	}
	if err := build.Apply(result, template, options.model()); err != nil {
		result.Warn(model.WarnTemplateUnavailable, "%v", err)
		return result, nil
	}
	result.Template = &TemplateUse{Version: template.Version, Reason: reason, Cached: template.Origin == rules.FromCache}
	result.Warn(model.WarnTemplateApplied, "%s", reason)
	return result, nil
}

// templateReason decides whether to apply the template, and why.
func templateReason(choice string, stats RuleStats) (string, error) {
	switch choice {
	case RulesSubscription:
		return "", nil
	case RulesTemplate:
		return TemplateRequested, nil
	case RulesAuto:
		return build.Reason(stats), nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownRules, choice)
}
