// Package singbox converts sing-box configs (1.11 and later, with endpoints) into OpenWeir mihomo
// proxies, groups, rule providers and rules.
package singbox

import (
	"errors"
	"github.com/openweir/subconv/internal/model"

	"fmt"
	"slices"
	"time"
)

var errNotAConfig = errors.New("not a sing-box config")

// Clash's built-in policies, which proxies and groups may not be named.
var builtIn = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}

const defaultTestURL = "https://www.gstatic.com/generate_204"

type singBox struct {
	result *model.Result
	// The Clash name of each sing-box tag: a proxy or group name, DIRECT or REJECT. A tag the
	// conversion left out maps to "".
	names map[string]string
	// Tags of dns outbounds, which only route DNS: rules sending to them are dropped quietly.
	dns   map[string]bool
	first string // the first outbound, sing-box's final when route.final is unset
}

// Convert converts a sing-box config.
func Convert(data []byte) (*model.Result, error) {
	value, err := model.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("sing-box: %w", err)
	}
	config := model.AsObject(value)
	if config == nil {
		return nil, fmt.Errorf("sing-box: %w", errNotAConfig)
	}
	c := &singBox{
		result: &model.Result{Format: model.FormatSingBox},
		names:  map[string]string{},
		dns:    map[string]bool{},
	}
	var groups []model.Object
	// Endpoints (sing-box 1.11) carry WireGuard and Tailscale; they are outbounds to the router.
	for _, item := range append(model.AsList(config.Value("outbounds")), model.AsList(config.Value("endpoints"))...) {
		outbound := model.AsObject(item)
		tag := outbound.String("tag")
		if outbound == nil || tag == "" {
			continue
		}
		if c.first == "" {
			c.first = tag
		}
		switch kind := outbound.String("type"); kind {
		case "direct":
			c.names[tag] = "DIRECT"
		case "block":
			c.names[tag] = "REJECT"
		case "dns":
			c.dns[tag] = true
		case "selector", "urltest", "loadbalance":
			c.names[tag] = tag
			groups = append(groups, outbound)
		default:
			if slices.Contains(builtIn, tag) {
				c.result.Warn(model.WarnUnsupportedProxy, "%s: the name is one of Clash's built-in policies", tag)
				c.names[tag] = ""
				continue
			}
			proxy, reason := c.proxy(outbound)
			if proxy == nil {
				code := model.WarnUnsupportedOption
				if reason == "" {
					code, reason = model.WarnUnsupportedProxy, "type "+kind
				}
				c.result.Warn(code, "%s: %s", tag, reason)
				c.names[tag] = ""
				continue
			}
			c.names[tag] = tag
			c.result.Proxies = append(c.result.Proxies, proxy)
		}
	}
	// Detours name other outbounds, known only once all are read.
	for index, proxy := range c.result.Proxies {
		if detour := proxy.String("dialer-proxy"); detour != "" {
			name := c.names[detour]
			if name == "" || name == "DIRECT" {
				if name == "" {
					c.result.Warn(model.WarnUnknownReference, "%s: detour %s", proxy.String("name"), detour)
				}
				c.result.Proxies[index] = withoutKey(proxy, "dialer-proxy")
				continue
			}
			c.result.Proxies[index].Set("dialer-proxy", name)
		}
	}
	for _, group := range groups {
		c.result.Groups = append(c.result.Groups, c.group(group))
	}
	c.route(model.AsObject(config.Value("route")))
	return c.result, nil
}

func (c *singBox) group(outbound model.Object) model.Object {
	tag := outbound.String("tag")
	var members []any
	for _, member := range model.AsStrings(outbound.Value("outbounds")) {
		name, known := c.names[member]
		switch {
		case !known:
			c.result.Warn(model.WarnUnknownReference, "%s: member %s", tag, member)
		case name != "" && !slices.Contains(members, any(name)):
			members = append(members, name)
		}
	}
	if len(members) == 0 {
		c.result.Warn(model.WarnEmptyGroup, "%s: no members left; using DIRECT", tag)
		members = []any{"DIRECT"}
	}
	switch outbound.String("type") {
	case "selector":
		// Clash's select starts on its first member.
		if name := c.names[outbound.String("default")]; name != "" {
			if index := slices.Index(members, any(name)); index > 0 {
				members = append([]any{name}, slices.Delete(members, index, index+1)...)
			}
		}
		return model.New("name", tag, "type", "select", "proxies", members)
	case "urltest":
		return model.New(
			"name", tag,
			"type", "url-test",
			"proxies", members,
			"url", or(outbound.String("url"), defaultTestURL),
			"interval", seconds(outbound.String("interval"), 180),
			"tolerance", model.AsInt(outbound.Value("tolerance")),
		)
	default: // libbox's loadbalance: consistent hashing with health checks
		return model.New(
			"name", tag,
			"type", "load-balance",
			"proxies", members,
			"strategy", "consistent-hashing",
			"url", or(outbound.String("url"), defaultTestURL),
			"interval", seconds(outbound.String("interval"), 180),
		)
	}
}

// target returns the Clash policy of a rule's outbound, and whether to keep the rule.
func (c *singBox) target(tag string) (string, bool) {
	if c.dns[tag] {
		return "", false
	}
	name, known := c.names[tag]
	if !known || name == "" {
		c.result.Warn(model.WarnUnknownReference, "rule target %s", tag)
		return "", false
	}
	return name, true
}

func seconds(duration string, fallback int) int {
	if parsed, err := time.ParseDuration(duration); err == nil && parsed > 0 {
		return max(1, int(parsed/time.Second))
	}
	return fallback
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func withoutKey(o model.Object, key string) model.Object {
	out := make(model.Object, 0, len(o))
	for _, field := range o {
		if field.Key != key {
			out = append(out, field)
		}
	}
	return out
}
