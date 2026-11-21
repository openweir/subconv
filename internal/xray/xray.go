// Package xray converts Xray and V2Ray JSON configs: their outbounds with stream settings,
// balancers, and routing rules.
package xray

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

var errNotAConfig = errors.New("not an Xray config")

// Is reports a decoded config whose outbounds are Xray's: a protocol and settings.
func Is(value any) bool {
	for _, item := range model.AsList(model.AsObject(value).Value("outbounds")) {
		if outbound := model.AsObject(item); outbound.String("protocol") != "" {
			return true
		}
	}
	return false
}

type converter struct {
	result *model.Result
	// The Clash names of each outbound tag; a tag may stand for several servers.
	names map[string][]string
	first string
}

// Convert converts an Xray or V2Ray config.
func Convert(data []byte) (*model.Result, error) {
	value, err := model.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	config := model.AsObject(value)
	if config == nil {
		return nil, fmt.Errorf("xray: %w", errNotAConfig)
	}
	c := &converter{result: &model.Result{Format: model.FormatXray}, names: map[string][]string{}}
	for index, item := range model.AsList(config.Value("outbounds")) {
		c.outbound(index, model.AsObject(item))
	}
	for index, p := range c.result.Proxies {
		if detour := p.String("dialer-proxy"); detour != "" {
			if name := c.policy(detour); name != "" && name != "DIRECT" {
				c.result.Proxies[index].Set("dialer-proxy", name)
			} else if name == "DIRECT" {
				c.result.Proxies[index].Delete("dialer-proxy")
			}
		}
	}
	routing := model.AsObject(config.Value("routing"))
	c.balancers(model.AsList(routing.Value("balancers")))
	c.rules(model.AsList(routing.Value("rules")))
	return c.result, nil
}

func (c *converter) outbound(index int, o model.Object) {
	tag := o.String("tag")
	if tag == "" {
		tag = fmt.Sprintf("%s %d", o.String("protocol"), index+1)
	}
	if c.first == "" {
		c.first = tag
	}
	settings := model.AsObject(o.Value("settings"))
	switch kind := o.String("protocol"); kind {
	case "freedom":
		c.names[tag] = []string{"DIRECT"}
		return
	case "blackhole":
		c.names[tag] = []string{"REJECT"}
		return
	case "dns", "loopback":
		return
	case "vmess", "vless":
		for _, server := range model.AsList(settings.Value("vnext")) {
			server := model.AsObject(server)
			for _, user := range model.AsList(server.Value("users")) {
				user := model.AsObject(user)
				fields := model.New("type", kind, "uuid", user.String("id"), "udp", true)
				if kind == "vmess" {
					fields = proxy.Merge(fields, model.New("alterId", model.AsInt(user.Value("alterId")), "cipher", or(user.String("security"), "auto")))
				} else {
					fields = proxy.Merge(fields, model.New("flow", user.String("flow"), "encryption", none(user.String("encryption"))))
				}
				c.add(tag, o, server.String("address"), server.Value("port"), fields)
			}
		}
		if vless := settings.String("address"); vless != "" { // Xray's flat VLESS settings
			fields := model.New("type", kind, "uuid", settings.String("id"), "flow", settings.String("flow"), "encryption", none(settings.String("encryption")), "udp", true)
			c.add(tag, o, vless, settings.Value("port"), fields)
		}
	case "trojan", "shadowsocks", "socks", "http":
		for _, server := range model.AsList(settings.Value("servers")) {
			server := model.AsObject(server)
			var fields model.Object
			switch kind {
			case "trojan":
				fields = model.New("type", "trojan", "password", server.String("password"), "udp", true)
			case "shadowsocks":
				fields = model.New("type", "ss", "cipher", server.String("method"), "password", server.String("password"),
					"udp", true, "udp-over-tcp", model.AsBool(server.Value("uot")))
			case "socks", "http":
				user := model.AsObject(first(model.AsList(server.Value("users"))))
				fields = model.New("type", map[string]string{"socks": "socks5", "http": "http"}[kind],
					"username", user.String("user"), "password", user.String("pass"))
				if kind == "socks" {
					fields.Set("udp", true)
				}
			}
			c.add(tag, o, server.String("address"), server.Value("port"), fields)
		}
	case "wireguard":
		var ip, ipv6 string
		for _, address := range model.AsStrings(settings.Value("address")) {
			address, _, _ = strings.Cut(address, "/")
			if strings.Contains(address, ":") {
				ipv6 = or(ipv6, address)
			} else {
				ip = or(ip, address)
			}
		}
		peer := model.AsObject(first(model.AsList(settings.Value("peers"))))
		host, port := splitEndpoint(peer.String("endpoint"))
		fields := model.New(
			"type", "wireguard",
			"ip", ip,
			"ipv6", ipv6,
			"private-key", settings.String("secretKey"),
			"public-key", peer.String("publicKey"),
			"pre-shared-key", peer.String("preSharedKey"),
			"allowed-ips", model.AsStrings(peer.Value("allowedIPs")),
			"reserved", model.AsList(settings.Value("reserved")),
			"mtu", model.AsInt(settings.Value("mtu")),
			"udp", true,
		)
		if len(model.AsList(settings.Value("peers"))) > 1 {
			c.result.Warn(model.WarnIgnoredOption, "%s: peers after the first", tag)
		}
		c.add(tag, o, host, port, fields)
	case "hysteria":
		// Xray's Hysteria 2: the server and its auth in settings, the rest in stream settings.
		fields := model.New("type", "hysteria2", "password", settings.String("password"))
		c.add(tag, o, settings.String("address"), settings.Value("port"), fields)
	default:
		c.result.Warn(model.WarnUnsupportedProxy, "%s: protocol %s", tag, kind)
	}
}

// add completes a proxy with an outbound's stream settings, mux and proxy settings.
func (c *converter) add(tag string, o model.Object, server string, port any, fields model.Object) {
	name := tag
	if count := len(c.names[tag]); count > 0 {
		// Several servers under one tag: number them all, and the tag names their group.
		if count == 1 {
			for index, p := range c.result.Proxies {
				if p.String("name") == tag {
					c.result.Proxies[index].Set("name", tag+" 1")
				}
			}
			c.names[tag][0] = tag + " 1"
		}
		name = fmt.Sprintf("%s %d", tag, count+1)
	}
	portNumber, _ := model.Int(port)
	out := proxy.Merge(proxy.Base(name, server, portNumber), fields)
	out, reason := stream(out, model.AsObject(o.Value("streamSettings")))
	if out == nil {
		c.result.Warn(model.WarnUnsupportedOption, "%s: %s", name, reason)
		return
	}
	if mux := model.AsObject(o.Value("mux")); model.AsBool(mux.Value("enabled")) && model.AsInt(mux.Value("concurrency")) >= 0 {
		c.result.Warn(model.WarnIgnoredOption, "%s: mux (Xray's own multiplexing)", name)
	}
	if detour := model.AsObject(o.Value("proxySettings")).String("tag"); detour != "" {
		out.Set("dialer-proxy", detour)
	}
	if model.AsBool(model.AsObject(model.AsObject(o.Value("streamSettings")).Value("sockopt")).Value("tcpFastOpen")) {
		out.Set("tfo", true)
	}
	c.names[tag] = append(c.names[tag], name)
	c.result.Proxies = append(c.result.Proxies, out)
}

// stream maps streamSettings: the transport and TLS or REALITY.
func stream(out, s model.Object) (model.Object, string) {
	kind := out.String("type")
	security := s.String("security")
	switch security {
	case "", "none":
	case "tls", "xtls":
		tls := model.AsObject(or2(s.Value("tlsSettings"), s.Value("xtlsSettings")))
		nameKey := "sni"
		if kind == "vmess" || kind == "vless" {
			nameKey = "servername"
			out.Set("tls", true)
		} else if kind == "http" || kind == "socks5" {
			out.Set("tls", true)
		}
		out = proxy.Merge(out, model.New(
			nameKey, tls.String("serverName"),
			"alpn", model.AsStrings(tls.Value("alpn")),
			"skip-cert-verify", model.AsBool(tls.Value("allowInsecure")),
			"client-fingerprint", tls.String("fingerprint"),
		))
		if pins := model.AsStrings(tls.Value("pinnedPeerCertificateChainSha256")); len(pins) > 0 {
			if sum, err := base64.StdEncoding.DecodeString(pins[0]); err == nil {
				out.Set("fingerprint", hex.EncodeToString(sum))
			}
		}
		if ech := tls.String("echConfigList"); ech != "" {
			config := ""
			if _, err := base64.StdEncoding.DecodeString(ech); err == nil {
				config = ech
			}
			out.Set("ech-opts", model.New("enable", true, "config", config))
		}
	case "reality":
		reality := model.AsObject(s.Value("realitySettings"))
		nameKey := "sni"
		if kind == "vmess" || kind == "vless" {
			nameKey = "servername"
			out.Set("tls", true)
		}
		out = proxy.Merge(out, model.New(
			nameKey, reality.String("serverName"),
			"client-fingerprint", or(reality.String("fingerprint"), "chrome"),
			"reality-opts", model.New("public-key", or(reality.String("publicKey"), reality.String("password")), "short-id", reality.String("shortId")),
		))
	default:
		return nil, "security " + security
	}
	switch network := or(s.String("network"), "tcp"); network {
	case "tcp", "raw":
		settings := model.AsObject(or2(s.Value("tcpSettings"), s.Value("rawSettings")))
		header := model.AsObject(settings.Value("header"))
		if header.String("type") == "http" {
			request := model.AsObject(header.Value("request"))
			headers := model.Object{}
			for _, field := range model.AsObject(request.Value("headers")) {
				headers = append(headers, model.Field{Key: field.Key, Value: model.AsStrings(field.Value)})
			}
			out = proxy.Merge(out, model.New("network", "http", "http-opts", model.New(
				"method", request.String("method"),
				"path", model.AsStrings(request.Value("path")),
				"headers", headers,
			)))
		}
	case "ws", "websocket":
		ws := model.AsObject(s.Value("wsSettings"))
		headers := model.Object{}
		for _, field := range model.AsObject(ws.Value("headers")) {
			text, _ := model.Text(field.Value)
			headers = append(headers, model.Field{Key: field.Key, Value: text})
		}
		if host := ws.String("host"); host != "" {
			headers.Set("Host", host)
		}
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New("path", ws.String("path"), "headers", headers)))
	case "httpupgrade":
		upgrade := model.AsObject(s.Value("httpupgradeSettings"))
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", upgrade.String("path"),
			"headers", model.New("Host", upgrade.String("host")),
			"v2ray-http-upgrade", true,
		)))
	case "grpc", "gun":
		grpc := model.AsObject(s.Value("grpcSettings"))
		out = proxy.Merge(out, model.New("network", "grpc", "grpc-opts", model.New("grpc-service-name", grpc.String("serviceName"))))
	case "h2", "http":
		h2 := model.AsObject(s.Value("httpSettings"))
		out = proxy.Merge(out, model.New("network", "h2", "h2-opts", model.New(
			"host", model.AsStrings(h2.Value("host")),
			"path", h2.String("path"),
		)))
	case "xhttp", "splithttp":
		if kind != "vless" {
			return nil, "XHTTP on " + kind
		}
		x := model.AsObject(or2(s.Value("xhttpSettings"), s.Value("splithttpSettings")))
		if model.AsObject(x.Value("extra")) != nil {
			return nil, "XHTTP extra settings"
		}
		out = proxy.Merge(out, model.New("network", "xhttp", "xhttp-opts", model.New(
			"path", x.String("path"),
			"host", x.String("host"),
			"mode", x.String("mode"),
		)))
	case "hysteria":
		h := model.AsObject(s.Value("hysteriaSettings"))
		out = proxy.Merge(out, model.New(
			"password", or(out.String("password"), h.String("auth")),
			"up", h.String("up"),
			"down", h.String("down"),
		))
	default:
		return nil, "transport " + network
	}
	return out, ""
}

// balancers become groups: leastPing a url-test, the others load-balance. Their selectors
// match outbound tags by prefix.
func (c *converter) balancers(list []any) {
	for _, item := range list {
		b := model.AsObject(item)
		tag := b.String("tag")
		var members []any
		for _, prefix := range model.AsStrings(b.Value("selector")) {
			for _, p := range c.result.Proxies {
				if name := p.String("name"); strings.HasPrefix(name, prefix) && !contains(members, name) {
					members = append(members, name)
				}
			}
		}
		strategy := model.AsObject(b.Value("strategy")).String("type")
		var group model.Object
		switch strategy {
		case "leastPing", "leastLoad":
			group = model.New("name", tag, "type", "url-test", "proxies", members)
		case "roundRobin":
			group = model.New("name", tag, "type", "load-balance", "proxies", members, "strategy", "round-robin")
		default: // random
			group = model.New("name", tag, "type", "load-balance", "proxies", members)
		}
		if fallback := b.String("fallbackTag"); fallback != "" {
			group = model.New("name", tag, "type", "fallback", "proxies", append(members, c.policy(fallback)))
		}
		c.names[tag] = []string{tag}
		c.result.Groups = append(c.result.Groups, group)
	}
}

// rules converts routing rules: the fields of a rule all match, the values of a field any.
func (c *converter) rules(list []any) {
	for index, item := range list {
		rule := model.AsObject(item)
		target := or(rule.String("outboundTag"), rule.String("balancerTag"))
		policy := c.policy(target)
		if policy == "" {
			c.result.Warn(model.WarnUnsupportedRule, "rule %d: outbound %s does not exist", index+1, target)
			continue
		}
		var groups [][]string
		problem := ""
		for _, field := range rule {
			var atoms []string
			switch field.Key {
			case "type", "outboundTag", "balancerTag", "ruleTag", "domainMatcher":
				continue
			case "domain", "domains":
				for _, value := range model.AsStrings(field.Value) {
					atom, ok := domain(value)
					if !ok {
						problem = "domain " + value
					}
					atoms = append(atoms, atom)
				}
			case "ip":
				for _, value := range model.AsStrings(field.Value) {
					atoms = append(atoms, ip(value, false))
				}
			case "source", "sourceIP":
				for _, value := range model.AsStrings(field.Value) {
					atoms = append(atoms, ip(value, true))
				}
			case "port", "sourcePort":
				kind := "DST-PORT"
				if field.Key == "sourcePort" {
					kind = "SRC-PORT"
				}
				text, _ := model.Text(field.Value)
				for part := range strings.SplitSeq(text, ",") {
					if part = strings.TrimSpace(part); part != "" {
						atoms = append(atoms, kind+","+part)
					}
				}
			case "network":
				text, _ := model.Text(field.Value)
				for part := range strings.SplitSeq(text, ",") {
					if part = strings.TrimSpace(part); part != "" {
						atoms = append(atoms, "NETWORK,"+strings.ToLower(part))
					}
				}
			case "process":
				for _, value := range model.AsStrings(field.Value) {
					atoms = append(atoms, "PROCESS-NAME,"+value)
				}
			default:
				problem = "a rule with " + field.Key
			}
			if problem != "" {
				break
			}
			if len(atoms) > 0 {
				groups = append(groups, atoms)
			}
		}
		switch {
		case problem != "":
			c.result.Warn(model.WarnUnsupportedRule, "rule %d to %s: %s", index+1, policy, problem)
		case len(groups) == 0:
		case len(groups) == 1:
			for _, atom := range groups[0] {
				c.result.Rules = append(c.result.Rules, withPolicy(atom, policy))
			}
		default:
			parts := make([]string, len(groups))
			for i, atoms := range groups {
				parts[i] = anyOf(atoms)
			}
			c.result.Rules = append(c.result.Rules, logical("AND", parts)+","+policy)
		}
	}
	// Xray sends what no rule matches to its first outbound.
	if final := c.policy(c.first); final != "" {
		c.result.Rules = append(c.result.Rules, "MATCH,"+final)
	}
}

// policy returns the Clash policy of an outbound or balancer tag: the proxy, or for a tag of
// several servers a select group of them.
func (c *converter) policy(tag string) string {
	names := c.names[tag]
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	members := make([]any, len(names))
	for index, name := range names {
		members[index] = name
	}
	c.result.Groups = append(c.result.Groups, model.New("name", tag, "type", "select", "proxies", members))
	c.names[tag] = []string{tag}
	return tag
}

// domain converts Xray's domain matchers: "domain:" a suffix, "full:" a domain, "keyword:" and a
// plain value a keyword, "regexp:" a regexp, "geosite:" a GeoSite category.
func domain(value string) (string, bool) {
	kind, rest, prefixed := strings.Cut(value, ":")
	if !prefixed {
		return "DOMAIN-KEYWORD," + value, true
	}
	switch kind {
	case "domain":
		return "DOMAIN-SUFFIX," + rest, true
	case "full":
		return "DOMAIN," + rest, true
	case "keyword":
		return "DOMAIN-KEYWORD," + rest, true
	case "regexp":
		return "DOMAIN-REGEX," + rest, true
	case "geosite":
		return "GEOSITE," + rest, true
	}
	return "", false
}

// ip converts Xray's IP matchers: ranges and GeoIP categories, "private" mihomo's built-in lan.
func ip(value string, source bool) string {
	if category, ok := strings.CutPrefix(value, "geoip:"); ok {
		if category == "private" {
			category = "lan"
		}
		if source {
			return "SRC-GEOIP," + category
		}
		return "GEOIP," + category + ",no-resolve"
	}
	if source {
		return "SRC-IP-CIDR," + value
	}
	kind := "IP-CIDR"
	if strings.Contains(value, ":") {
		kind = "IP-CIDR6"
	}
	if !strings.Contains(value, "/") {
		bits := "32"
		if kind == "IP-CIDR6" {
			bits = "128"
		}
		value += "/" + bits
	}
	return kind + "," + value + ",no-resolve"
}

func withPolicy(atom, policy string) string {
	if base, found := strings.CutSuffix(atom, ",no-resolve"); found {
		return base + "," + policy + ",no-resolve"
	}
	return atom + "," + policy
}

func anyOf(atoms []string) string {
	if len(atoms) == 1 {
		return atoms[0]
	}
	return logical("OR", atoms)
}

func logical(mode string, parts []string) string {
	wrapped := make([]string, len(parts))
	for index, part := range parts {
		wrapped[index] = "(" + part + ")"
	}
	return mode + ",(" + strings.Join(wrapped, ",") + ")"
}

func splitEndpoint(endpoint string) (string, int) {
	index := strings.LastIndex(endpoint, ":")
	if index < 0 {
		return endpoint, 0
	}
	port, _ := strconv.Atoi(endpoint[index+1:])
	return strings.Trim(endpoint[:index], "[]"), port
}

func first(list []any) any {
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

func contains(list []any, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

func none(value string) string {
	if value == "none" {
		return ""
	}
	return value
}

func or(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func or2(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
