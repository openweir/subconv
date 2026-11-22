package surge

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

// node is a proxy line taken apart: Surge's and Loon's "Name = type, server, port, ..." or
// Quantumult X's "type=server:port, ..., tag=Name".
type node struct {
	name, kind, server string
	port               int
	// Values without a key after the port, as Loon writes method, password and UUID.
	args []string
	opts map[string]string
}

func (n node) opt(keys ...string) string {
	for _, key := range keys {
		if value, ok := n.opts[key]; ok && value != "" {
			return value
		}
	}
	return ""
}

func (n node) flag(keys ...string) bool {
	b, _ := model.Bool(n.opt(keys...))
	return b
}

func (n node) set(keys ...string) bool {
	for _, key := range keys {
		if _, ok := n.opts[key]; ok {
			return true
		}
	}
	return false
}

// arg returns the positional value at index, or the first option of keys.
func (n node) arg(index int, keys ...string) string {
	if value := n.opt(keys...); value != "" {
		return value
	}
	if index < len(n.args) {
		return n.args[index]
	}
	return ""
}

// node converts a proxy line and adds it, or warns why it cannot.
func (c *converter) node(line string, quantumult bool) {
	n, ok := parseNode(line, quantumult)
	if !ok {
		c.result.Warn(model.WarnInvalidProxy, "%s: not a proxy line", label(line))
		return
	}
	switch n.kind {
	case "direct":
		c.aliases[n.name] = "DIRECT"
		return
	case "reject", "reject-tinygif", "reject-drop", "reject-no-drop":
		c.aliases[n.name] = "REJECT"
		return
	}
	p, reason := c.proxy(n)
	if p == nil {
		code := model.WarnUnsupportedOption
		if reason == "" {
			code, reason = model.WarnUnsupportedProxy, "type "+n.kind
		}
		c.result.Warn(code, "%s: %s", n.name, reason)
		return
	}
	c.result.Proxies = append(c.result.Proxies, p)
}

func parseNode(line string, quantumult bool) (node, bool) {
	key, spec, ok := strings.Cut(line, "=")
	if !ok {
		return node{}, false
	}
	parts := split(spec)
	n := node{opts: map[string]string{}}
	var rest []string
	if quantumult {
		n.kind = strings.ToLower(strings.TrimSpace(key))
		host, port, err := net.SplitHostPort(trim(parts[0]))
		if err != nil {
			return node{}, false
		}
		n.server = host
		n.port, _ = strconv.Atoi(port)
		rest = parts[1:]
	} else {
		n.name = trim(key)
		n.kind = strings.ToLower(trim(parts[0]))
		if len(parts) >= 3 && !strings.Contains(parts[1], "=") {
			n.server = trim(parts[1])
			n.port, _ = strconv.Atoi(trim(parts[2]))
			rest = parts[3:]
		} else {
			rest = parts[1:]
		}
	}
	for _, part := range rest {
		part = strings.TrimSpace(part)
		option, value, isOption := strings.Cut(part, "=")
		// A quoted value, or Base64 with its padding, is positional: Loon's method, password and UUID.
		if !isOption || strings.HasPrefix(part, `"`) || !optionName.MatchString(strings.TrimSpace(option)) || strings.Trim(value, "=") == "" {
			n.args = append(n.args, trim(part))
			continue
		}
		n.opts[strings.ToLower(strings.TrimSpace(option))] = trim(value)
	}
	if quantumult {
		n.name = n.opt("tag")
		if n.name == "" {
			n.name = net.JoinHostPort(n.server, strconv.Itoa(n.port))
		}
	}
	return n, true
}

// proxy builds a mihomo proxy from a line, or returns a reason (or "" for a type mihomo lacks).
func (c *converter) proxy(n node) (model.Object, string) {
	base := proxy.Base(n.name, n.server, n.port)
	udp := !(n.set("udp-relay", "udp") && !n.flag("udp-relay", "udp"))
	var out model.Object
	switch n.kind {
	case "ss", "shadowsocks":
		if n.opt("ssr-protocol", "protocol") != "" {
			return c.shadowsocksR(n, base, udp)
		}
		out = proxy.Merge(base, model.New(
			"type", "ss",
			"cipher", n.arg(0, "encrypt-method", "method"),
			"password", n.arg(1, "password"),
			"udp", udp,
		))
		switch obfs := n.opt("obfs", "obfs-name"); obfs {
		case "":
		case "http", "tls":
			out = proxy.Merge(out, model.New("plugin", "obfs", "plugin-opts", model.New("mode", obfs, "host", n.opt("obfs-host"))))
		case "ws", "wss":
			out = proxy.Merge(out, model.New("plugin", "v2ray-plugin", "plugin-opts", model.New(
				"mode", "websocket", "tls", obfs == "wss", "host", n.opt("obfs-host"), "path", n.opt("obfs-uri"))))
		default:
			return nil, "obfs " + obfs
		}
		if password := n.opt("shadow-tls-password"); password != "" {
			if _, set := out.Get("plugin"); set {
				return nil, "obfs inside ShadowTLS"
			}
			out = proxy.Merge(out, model.New("plugin", "shadow-tls", "plugin-opts", shadowTLS(n)))
		}
	case "shadowsocksr", "ssr":
		return c.shadowsocksR(n, base, udp)
	case "vmess":
		uuid := n.opt("username", "password", "uuid")
		cipher := n.opt("encrypt-method", "method")
		if uuid == "" && len(n.args) >= 2 {
			cipher, uuid = n.args[0], n.args[1] // Loon: method, UUID
		} else if uuid == "" {
			uuid = n.arg(0)
		}
		out = proxy.Merge(base, model.New(
			"type", "vmess",
			"uuid", uuid,
			"alterId", number(n.opt("alterid")),
			"cipher", or(strings.ToLower(cipher), "auto"),
			"udp", udp,
		))
		out = c.stream(n, out, "servername")
	case "vless":
		out = proxy.Merge(base, model.New(
			"type", "vless",
			"uuid", n.arg(0, "username", "password", "uuid"),
			"flow", n.opt("flow", "vless-flow"),
			"udp", udp,
		))
		out = c.stream(n, out, "servername")
	case "trojan":
		out = proxy.Merge(base, model.New("type", "trojan", "password", n.arg(0, "password"), "udp", udp))
		out = c.stream(n, out, "sni")
	case "http", "https":
		out = proxy.Merge(base, model.New(
			"type", "http",
			"username", n.arg(0, "username"),
			"password", n.arg(1, "password"),
			"tls", n.kind == "https" || n.flag("over-tls", "tls"),
			"sni", n.opt("sni", "tls-name", "tls-host"),
			"skip-cert-verify", insecure(n),
		))
	case "socks5", "socks5-tls":
		out = proxy.Merge(base, model.New(
			"type", "socks5",
			"username", n.arg(0, "username"),
			"password", n.arg(1, "password"),
			"tls", n.kind == "socks5-tls" || n.flag("over-tls", "tls"),
			"skip-cert-verify", insecure(n),
			"udp", udp,
		))
	case "snell":
		version, _ := strconv.Atoi(or(n.opt("version"), "4"))
		out = proxy.Merge(base, model.New(
			"type", "snell",
			"psk", n.arg(0, "psk"),
			"password", n.opt("password"), // not Snell's; the normalization reports it as for Clash
			"userkey", n.opt("userkey"),
			"version", version,
			"reuse", n.flag("reuse"),
			"udp", version >= 3,
		))
		if mode := n.opt("mode"); version == 6 && mode != "" && mode != "default" {
			out.Set("mode", mode)
		}
		if obfs := n.opt("obfs"); obfs != "" && obfs != "none" {
			if version >= 6 {
				return nil, "Snell v6 has no obfs"
			}
			out.Set("obfs-opts", model.New("mode", obfs, "host", n.opt("obfs-host")))
		} else if n.opt("shadow-tls-password") != "" {
			out.Set("obfs-opts", append(model.Object{{Key: "mode", Value: "shadow-tls"}}, shadowTLS(n)...))
		}
	case "hysteria2":
		out = proxy.Merge(base, model.New(
			"type", "hysteria2",
			"password", n.arg(0, "password", "auth"),
			"ports", strings.ReplaceAll(strings.ReplaceAll(n.opt("port-hopping"), ";", ","), ":", "-"),
			"hop-interval", number(n.opt("port-hopping-interval")),
			"up", mbps(n.opt("upload-bandwidth")),
			"down", mbps(n.opt("download-bandwidth")),
			"sni", n.opt("sni", "tls-name", "tls-host"),
			"skip-cert-verify", insecure(n),
			"alpn", list(n.opt("alpn")),
		))
		if password := n.opt("salamander-password", "obfs-password"); password != "" {
			out = proxy.Merge(out, model.New("obfs", "salamander", "obfs-password", password))
		}
	case "tuic", "tuic-v5":
		out = proxy.Merge(base, model.New(
			"type", "tuic",
			"token", n.opt("token"),
			"uuid", n.opt("uuid"),
			"password", n.opt("password"),
			"sni", n.opt("sni", "tls-name"),
			"alpn", list(n.opt("alpn")),
			"skip-cert-verify", insecure(n),
			"congestion-controller", n.opt("congestion-controller", "congestion-control"),
			"udp-relay-mode", n.opt("udp-relay-mode"),
			"udp", true,
		))
	case "anytls":
		out = proxy.Merge(base, model.New(
			"type", "anytls",
			"password", n.arg(0, "password"),
			"sni", n.opt("sni", "tls-name"),
			"skip-cert-verify", insecure(n),
			"udp", true,
		))
	case "ssh":
		out = proxy.Merge(base, model.New("type", "ssh", "username", n.arg(0, "username"), "password", n.arg(1, "password")))
	case "wireguard":
		return c.wireguardNode(n)
	default:
		return nil, ""
	}
	if fingerprint := n.opt("server-cert-fingerprint-sha256"); fingerprint != "" {
		out.Set("fingerprint", fingerprint)
	}
	if n.flag("tfo", "fast-open") {
		out.Set("tfo", true)
	}
	if dialer := n.opt("underlying-proxy"); dialer != "" {
		out.Set("dialer-proxy", c.policy(dialer))
	}
	return out, ""
}

func (c *converter) shadowsocksR(n node, base model.Object, udp bool) (model.Object, string) {
	return proxy.Merge(base, model.New(
		"type", "ssr",
		"cipher", n.arg(0, "encrypt-method", "method"),
		"password", n.arg(1, "password"),
		"protocol", n.opt("ssr-protocol", "protocol"),
		"protocol-param", n.opt("ssr-protocol-param", "protocol-param"),
		"obfs", n.opt("obfs"),
		"obfs-param", n.opt("obfs-host", "obfs-param"),
		"udp", udp,
	)), ""
}

// stream adds TLS and the WebSocket or HTTP transport of VMess, VLESS and Trojan, in each
// dialect's words.
func (c *converter) stream(n node, out model.Object, nameKey string) model.Object {
	obfs := strings.ToLower(n.opt("obfs"))
	transport := strings.ToLower(n.opt("transport"))
	ws := n.flag("ws") || transport == "ws" || obfs == "ws" || obfs == "wss"
	secure := n.flag("tls", "over-tls") || obfs == "wss" || obfs == "over-tls" ||
		out.String("type") == "trojan" && !(n.set("over-tls", "tls") && !n.flag("over-tls", "tls"))
	if n.opt("public-key", "reality-base64-pubkey") != "" {
		secure = true
	}
	if secure {
		if out.String("type") != "trojan" {
			out.Set("tls", true)
		}
		host := n.opt("sni", "tls-name", "tls-host")
		if host == "" && (obfs == "over-tls" || obfs == "wss") {
			host = n.opt("obfs-host") // Quantumult X's server name
		}
		out = proxy.Merge(out, model.New(
			nameKey, host,
			"skip-cert-verify", insecure(n),
			"alpn", list(n.opt("alpn")),
		))
	}
	if key := n.opt("public-key", "reality-base64-pubkey"); key != "" {
		out = proxy.Merge(out, model.New(
			"client-fingerprint", "chrome",
			"reality-opts", model.New("public-key", key, "short-id", n.opt("short-id", "reality-hex-shortid")),
		))
	}
	switch {
	case ws:
		path := or(n.opt("ws-path", "path", "obfs-uri"), "/")
		headers := model.Object{}
		for header := range strings.SplitSeq(n.opt("ws-headers"), "|") {
			if key, value, ok := strings.Cut(header, ":"); ok {
				headers.Set(strings.TrimSpace(key), strings.TrimSpace(value))
			}
		}
		if host := n.opt("host", "obfs-host"); host != "" && headers.Value("Host") == nil {
			headers.Set("Host", host)
		}
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New("path", path, "headers", headers)))
	case transport == "http" || obfs == "http":
		out = proxy.Merge(out, model.New("network", "http", "http-opts", model.New(
			"path", []string{or(n.opt("path", "obfs-uri"), "/")},
			"headers", model.New("Host", list(n.opt("host", "obfs-host"))),
		)))
	case transport == "grpc":
		out = proxy.Merge(out, model.New("network", "grpc", "grpc-opts", model.New("grpc-service-name", n.opt("service-name", "path"))))
	}
	if password := n.opt("shadow-tls-password"); password != "" {
		if out.String("type") != "trojan" {
			out.Set("tls", true)
		}
		out = proxy.Merge(out, model.New(nameKey, n.opt("shadow-tls-sni"), "shadow-tls-opts", model.New(
			"password", password, "version", number(n.opt("shadow-tls-version")))))
	}
	return out
}

// shadowTLS returns Surge's ShadowTLS options as mihomo's plugin options.
func shadowTLS(n node) model.Object {
	version, _ := strconv.Atoi(or(n.opt("shadow-tls-version"), "3"))
	return model.New("host", n.opt("shadow-tls-sni"), "password", n.opt("shadow-tls-password"), "version", version)
}

// wireguardNode converts Surge's "wireguard, section-name=X" with its [WireGuard X] section, and
// Loon's single-line WireGuard.
func (c *converter) wireguardNode(n node) (model.Object, string) {
	opts := n.opts
	var peers []map[string]string
	if section := n.opt("section-name"); section != "" {
		lines, ok := c.wireguard[strings.ToLower(section)]
		if !ok {
			return nil, "no [WireGuard " + section + "] section"
		}
		opts = map[string]string{}
		for _, line := range lines {
			key, value, _ := strings.Cut(line, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "peer" {
				peers = append(peers, peerOptions(value))
			} else {
				opts[key] = trim(value)
			}
		}
	} else {
		for _, peer := range splitPeers(n.opt("peers")) {
			peers = append(peers, peerOptions(peer))
		}
	}
	if len(peers) == 0 {
		return nil, "no WireGuard peer"
	}
	var entries []any
	for _, peer := range peers {
		host, port, err := net.SplitHostPort(peer["endpoint"])
		if err != nil {
			return nil, "WireGuard endpoint " + peer["endpoint"]
		}
		portNumber, _ := strconv.Atoi(port)
		entries = append(entries, model.New(
			"server", host,
			"port", portNumber,
			"public-key", peer["public-key"],
			"pre-shared-key", peer["preshared-key"],
			"allowed-ips", list(or(peer["allowed-ips"], "0.0.0.0/0, ::/0")),
			"reserved", reserved(peer["client-id"], peer["reserved"]),
		))
	}
	get := func(keys ...string) string {
		for _, key := range keys {
			if value := opts[key]; value != "" {
				return value
			}
		}
		return ""
	}
	if len(entries) == 1 {
		peer := model.AsObject(entries[0])
		return model.New(
			"name", n.name,
			"type", "wireguard",
			"server", peer.Value("server"),
			"port", peer.Value("port"),
			"ip", get("self-ip", "interface-ip"),
			"ipv6", get("self-ip-v6", "interface-ipv6"),
			"private-key", get("private-key"),
			"public-key", peer.Value("public-key"),
			"pre-shared-key", peer.Value("pre-shared-key"),
			"allowed-ips", peer.Value("allowed-ips"),
			"reserved", peer.Value("reserved"),
			"mtu", number(get("mtu")),
			"udp", true,
		), ""
	}
	out := model.New(
		"name", n.name,
		"type", "wireguard",
		"ip", get("self-ip", "interface-ip"),
		"ipv6", get("self-ip-v6", "interface-ipv6"),
		"private-key", get("private-key"),
		"peers", entries,
		"mtu", number(get("mtu")),
		"udp", true,
	)
	return out, ""
}

// peerOptions reads "(public-key = x, allowed-ips = "…", endpoint = host:port)" or Loon's
// "{public-key=x, …}".
func peerOptions(text string) map[string]string {
	text = strings.TrimSpace(text)
	text = strings.Trim(text, "(){}")
	out := map[string]string{}
	for _, part := range fields(text) {
		if key, value, ok := strings.Cut(part, "="); ok {
			out[strings.ToLower(strings.TrimSpace(key))] = trim(value)
		}
	}
	return out
}

// splitPeers splits Loon's "[{…},{…}]".
func splitPeers(text string) []string {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(strings.TrimSuffix(text, "]"), "[")
	var out []string
	for _, part := range fields(text) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// reserved reads WireGuard's reserved bytes from Surge's client-id "1/2/3" or Loon's "[1,2,3]".
func reserved(values ...string) []any {
	for _, value := range values {
		value = strings.Trim(value, "[] ")
		if value == "" {
			continue
		}
		var out []any
		for part := range strings.SplitSeq(strings.ReplaceAll(value, "/", ","), ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}

var optionName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

func insecure(n node) bool {
	if n.set("tls-verification") {
		return !n.flag("tls-verification")
	}
	return n.flag("skip-cert-verify", "allow-insecure", "insecure")
}

// number reads a numeric option; 0, which leaves it out, when it is none.
func number(value string) int {
	n, _ := model.Int(value)
	return n
}

func mbps(value string) string {
	if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
		return strconv.Itoa(n) + " Mbps"
	}
	return ""
}

func list(text string) []string {
	var out []string
	for part := range strings.SplitSeq(strings.ReplaceAll(text, ";", ","), ",") {
		if part = strings.Trim(strings.TrimSpace(part), `"`); part != "" {
			out = append(out, part)
		}
	}
	return out
}
