// Package singbox converts sing-box configs (1.11 and later, with endpoints) into OpenWeir mihomo
// proxies, groups, rule providers and rules.
package singbox

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openweir/subconv/internal/model"
)

var errNotAConfig = errors.New("not a sing-box config")

// Clash's built-in policies, which proxies and groups may not be named.
var builtIn = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}

const defaultTestURL = "https://www.gstatic.com/generate_204"

type singBox struct {
	options model.Options
	result  *model.Result
	// The Clash name of each sing-box tag: a proxy or group name, DIRECT or REJECT. A tag the
	// conversion left out maps to "".
	names map[string]string
	// Tags of dns outbounds, which only route DNS: rules sending to them are dropped quietly.
	dns map[string]bool
	// ShadowTLS outbounds by tag, which the proxies that dial through them absorb.
	shadowTLS map[string]model.Object
	first     string // the first outbound, sing-box's final when route.final is unset
}

// Convert converts a sing-box config.
func Convert(data []byte, options model.Options) (*model.Result, error) {
	value, err := model.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("sing-box: %w", err)
	}
	config := model.AsObject(value)
	if config == nil {
		return nil, fmt.Errorf("sing-box: %w", errNotAConfig)
	}
	c := &singBox{
		options:   options,
		result:    &model.Result{Format: model.FormatSingBox},
		names:     map[string]string{},
		dns:       map[string]bool{},
		shadowTLS: map[string]model.Object{},
	}
	// Endpoints (sing-box 1.11) carry WireGuard and Tailscale; they are outbounds to the router.
	var outbounds []model.Object
	for _, item := range append(model.AsList(config.Value("outbounds")), model.AsList(config.Value("endpoints"))...) {
		if outbound := model.AsObject(item); outbound != nil && outbound.String("tag") != "" {
			outbounds = append(outbounds, outbound)
			if outbound.String("type") == "shadowtls" {
				c.shadowTLS[outbound.String("tag")] = outbound
			}
		}
	}
	used := map[string]bool{}
	var groups []model.Object
	for _, outbound := range outbounds {
		tag := outbound.String("tag")
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
		case "shadowtls":
			c.names[tag] = ""
		case "selector", "urltest", "loadbalance":
			c.names[tag] = tag
			groups = append(groups, outbound)
		default:
			if slices.Contains(builtIn, tag) {
				c.result.Warn(model.WarnUnsupportedProxy, "%s: the name is one of Clash's built-in policies", tag)
				c.names[tag] = ""
				continue
			}
			used[outbound.String("detour")] = true
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
	for _, outbound := range outbounds {
		if tag := outbound.String("tag"); c.shadowTLS[tag] != nil && !used[tag] {
			c.result.Warn(model.WarnUnsupportedProxy, "%s: ShadowTLS on its own; mihomo adds it to the proxy that dials through it", tag)
		}
	}
	// Detours name other outbounds, known only once all are read.
	for index, proxy := range c.result.Proxies {
		if detour := proxy.String("dialer-proxy"); detour != "" {
			name, known := c.names[detour]
			switch {
			case name == "DIRECT":
				c.result.Proxies[index].Delete("dialer-proxy")
			case known && name != "":
				c.result.Proxies[index].Set("dialer-proxy", name)
			}
			// An unknown or left-out detour stays as written; the normalization reports it.
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
			members = append(members, member) // the normalization reports it
		case name != "" && !slices.Contains(members, any(name)):
			members = append(members, name)
		}
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
		tolerance := 50 // sing-box's default
		if value, set := outbound.Get("tolerance"); set {
			tolerance = model.AsInt(value)
		}
		return model.New(
			"name", tag,
			"type", "url-test",
			"proxies", members,
			"url", or(outbound.String("url"), defaultTestURL),
			"interval", seconds(outbound.String("interval"), 180),
			"tolerance", tolerance,
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

// target returns the Clash policy of a rule's outbound, or a reason to leave the rule out; ""
// and "" for rules sending to a dns outbound, which only routes DNS.
func (c *singBox) target(tag string) (string, string) {
	if c.dns[tag] {
		return "", ""
	}
	name, known := c.names[tag]
	switch {
	case !known:
		return "", "outbound " + tag + " does not exist"
	case name == "":
		return "", "outbound " + tag + " was left out"
	}
	return name, ""
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
