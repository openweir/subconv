// Package convert is what the root package's Convert, ConvertProxies and ConvertRuleSet do:
// it detects a body's format (detect.go), hands the body to the format's package and
// normalizes the result.
package convert

import (
	"errors"

	"github.com/openweir/subconv/internal/clash"
	"github.com/openweir/subconv/internal/links"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/normalize"
	"github.com/openweir/subconv/internal/ruleset"
	"github.com/openweir/subconv/internal/shadowsocks"
	"github.com/openweir/subconv/internal/singbox"
	"github.com/openweir/subconv/internal/surge"
	"github.com/openweir/subconv/internal/xray"
)

// Subscription converts a subscription of any format into the parts of a config mihomo loads.
func Subscription(data []byte, options model.Options) (*model.Result, error) {
	result, err := parts(data, options)
	if err != nil {
		return nil, err
	}
	normalize.Result(result, options)
	return result, nil
}

// Proxies converts a proxy provider's content of any format into its proxies alone.
func Proxies(data []byte) (*model.Result, error) {
	result, err := parts(data, model.Options{})
	if err != nil {
		return nil, err
	}
	normalize.Proxies(result)
	return result, nil
}

// RuleSet converts a rule provider's content; a web page fails as a subscription's would.
func RuleSet(data []byte, behavior, format string) (*ruleset.Content, error) {
	content, err := ruleset.Convert(data, behavior, format)
	if errors.Is(err, ruleset.ErrWebPage) {
		return nil, &inputError{kind: ErrWebPage}
	}
	return content, err
}

// parts detects a body's format and hands it to the format's package.
func parts(data []byte, options model.Options) (*model.Result, error) {
	format, payload, err := Detect(data)
	if err != nil {
		return nil, err
	}
	switch format {
	case model.FormatSingBox:
		return singbox.Convert(payload, options)
	case model.FormatClash, model.FormatStash:
		return clash.Convert(payload)
	case model.FormatSurge, model.FormatSurfboard, model.FormatLoon, model.FormatShadowrocket, model.FormatQuantumultX:
		return surge.Convert(payload, format, options)
	case model.FormatSIP008:
		return shadowsocks.ConvertSIP008(payload)
	case model.FormatSSD:
		return shadowsocks.ConvertSSD(payload)
	case model.FormatXray:
		return xray.Convert(payload)
	default:
		return links.Convert(payload)
	}
}
