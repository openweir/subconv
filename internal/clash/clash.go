// Package clash takes the parts of a Clash or mihomo config, which OpenWeir mihomo reads natively.
package clash

import (
	"errors"
	"fmt"

	"github.com/openweir/subconv/internal/model"
)

var errNotAConfig = errors.New("not a Clash config")

// Convert takes a Clash or mihomo config's parts as they are: OpenWeir mihomo reads them
// natively, and the client validates the whole config when it loads it.
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
	for _, item := range model.AsList(config.Value("proxies")) {
		if proxy := model.AsObject(item); proxy != nil {
			result.Proxies = append(result.Proxies, proxy)
		}
	}
	for _, item := range model.AsList(config.Value("proxy-groups")) {
		if group := model.AsObject(item); group != nil {
			result.Groups = append(result.Groups, group)
		}
	}
	result.RuleProviders = model.AsObject(config.Value("rule-providers"))
	result.Rules = model.AsStrings(config.Value("rules"))
	return result, nil
}
