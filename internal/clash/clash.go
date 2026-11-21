// Package clash reads Clash and mihomo configs, and Stash's, which share the format. It takes
// the parts as they are; internal/normalize repairs them.
package clash

import (
	"errors"
	"fmt"

	"github.com/openweir/subconv/internal/model"
)

var errNotAConfig = errors.New("not a Clash config")

// Convert takes a Clash, mihomo or Stash config's proxies, proxy providers, groups, rule
// providers and rules.
func Convert(data []byte) (*model.Result, error) {
	value, err := model.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("clash: %w", err)
	}
	config := model.AsObject(value)
	if config == nil {
		return nil, fmt.Errorf("clash: %w", errNotAConfig)
	}
	result := &model.Result{Format: model.FormatClash}
	for index, item := range model.AsList(config.Value("proxies")) {
		if proxy := model.AsObject(item); proxy != nil {
			result.Proxies = append(result.Proxies, proxy)
		} else {
			result.Warn(model.WarnInvalidProxy, "proxy %d: not a mapping", index+1)
		}
	}
	result.ProxyProviders = model.AsObject(config.Value("proxy-providers"))
	for index, item := range model.AsList(config.Value("proxy-groups")) {
		if group := model.AsObject(item); group != nil {
			result.Groups = append(result.Groups, group)
		} else {
			result.Warn(model.WarnUnsupportedGroup, "group %d: not a mapping", index+1)
		}
	}
	result.RuleProviders = model.AsObject(config.Value("rule-providers"))
	for _, item := range model.AsList(config.Value("rules")) {
		if rule, ok := model.Text(item); ok && rule != "" {
			result.Rules = append(result.Rules, rule)
		}
	}
	return result, nil
}
