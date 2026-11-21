// Package shadowsocks converts Shadowsocks's own subscription formats: SIP008's JSON server
// list, the configs of shadowsocks-windows and Outline, and ShadowsocksD's ssd:// links.
package shadowsocks

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openweir/subconv/internal/body"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

var errNoServers = errors.New("no Shadowsocks servers")

// IsSIP008 reports a decoded JSON value that lists Shadowsocks servers: SIP008's
// {"servers": […]}, shadowsocks-windows's {"configs": […]}, or a bare list of servers.
func IsSIP008(value any) bool {
	for _, item := range servers(value) {
		if server := model.AsObject(item); server.String("server") != "" && server.String("method") != "" {
			return true
		}
	}
	return false
}

func servers(value any) []any {
	if config := model.AsObject(value); config != nil {
		if list := model.AsList(config.Value("servers")); list != nil {
			return list // SIP008
		}
		return model.AsList(config.Value("configs")) // shadowsocks-windows
	}
	if list, ok := value.([]any); ok {
		return list
	}
	return nil
}

// IsSSD reports an ssd:// subscription.
func IsSSD(text []byte) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(text))), "ssd://")
}

// ConvertSIP008 converts a SIP008 (or shadowsocks-windows) server list.
func ConvertSIP008(data []byte) (*model.Result, error) {
	value, err := model.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("sip008: %w", err)
	}
	list := servers(value)
	result := &model.Result{Format: model.FormatSIP008}
	for index, item := range list {
		server := model.AsObject(item)
		name := or(server.String("remarks"), server.String("name"), fmt.Sprintf("server %d", index+1))
		p, reason := build(name, server.String("server"), server.Value("server_port"), server.String("method"),
			server.String("password"), server.String("plugin"), or(server.String("plugin_opts"), server.String("plugin_options")))
		if p == nil {
			result.Warn(model.WarnUnsupportedOption, "%s: %s", name, reason)
			continue
		}
		result.Proxies = append(result.Proxies, p)
	}
	if len(list) == 0 {
		return nil, errNoServers
	}
	return result, nil
}

// ConvertSSD converts ssd://base64(JSON): an airport's defaults and its servers, each of which
// may override them.
func ConvertSSD(data []byte) (*model.Result, error) {
	text := strings.TrimSpace(string(data))
	decoded, err := body.Base64(text[len("ssd://"):])
	if err != nil {
		return nil, fmt.Errorf("ssd: %w", err)
	}
	value, err := model.Decode(decoded)
	config := model.AsObject(value)
	if err != nil || config == nil {
		return nil, fmt.Errorf("ssd: %w", errNoServers)
	}
	result := &model.Result{Format: model.FormatSSD}
	list := model.AsList(config.Value("servers"))
	for index, item := range list {
		server := model.AsObject(item)
		get := func(key string) any {
			if value, set := server.Get(key); set && !model.Empty(value) {
				return value
			}
			return config.Value(key)
		}
		text := func(key string) string { s, _ := model.Text(get(key)); return s }
		name := or(server.String("remarks"), fmt.Sprintf("%s %d", config.String("airport"), index+1))
		p, reason := build(name, server.String("server"), get("port"), text("encryption"), text("password"),
			text("plugin"), text("plugin_options"))
		if p == nil {
			result.Warn(model.WarnUnsupportedOption, "%s: %s", name, reason)
			continue
		}
		result.Proxies = append(result.Proxies, p)
	}
	if len(list) == 0 {
		return nil, errNoServers
	}
	return result, nil
}

func build(name, server string, port any, method, password, plugin, options string) (model.Object, string) {
	portNumber, _ := model.Int(port)
	out := proxy.Merge(proxy.Base(name, server, portNumber), model.New(
		"type", "ss",
		"cipher", method,
		"password", password,
		"udp", true,
	))
	fields, reason := proxy.ShadowsocksPlugin(plugin, proxy.PluginOptions(options))
	if reason != "" {
		return nil, reason
	}
	return proxy.Merge(out, fields), ""
}

func or(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
