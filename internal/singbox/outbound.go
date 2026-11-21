package singbox

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

// Protocols whose mihomo proxies take ech-opts.
var echTypes = map[string]bool{"vmess": true, "vless": true, "trojan": true, "anytls": true, "hysteria": true,
	"hysteria2": true, "tuic": true, "naive": true}

// proxy converts a sing-box outbound into an OpenWeir mihomo proxy. It returns nil and a reason
// when an option cannot be represented, or nil and "" when the type has no counterpart.
func (c *singBox) proxy(o model.Object) (model.Object, string) {
	tag := o.String("tag")
	base := proxy.Base(tag, o.String("server"), model.AsInt(o.Value("server_port")))
	tls := model.AsObject(o.Value("tls"))
	// ShadowTLS wraps the proxy that dials through it: its server, its TLS.
	shadow := c.shadowTLS[o.String("detour")]
	if shadow != nil {
		base = proxy.Base(tag, shadow.String("server"), model.AsInt(shadow.Value("server_port")))
	}
	var out model.Object
	reason := ""
	switch o.String("type") {
	case "shadowsocks":
		out, reason = shadowsocks(base, o)
	case "vmess":
		out = proxy.Merge(base, model.New(
			"type", "vmess",
			"uuid", o.String("uuid"),
			"alterId", model.AsInt(o.Value("alter_id")),
			"cipher", or(o.String("security"), "auto"),
			"udp", o.String("network") != "tcp",
			"xudp", o.String("packet_encoding") == "xudp",
			"packet-addr", o.String("packet_encoding") == "packetaddr",
			"global-padding", model.AsBool(o.Value("global_padding")),
			"authenticated-length", model.AsBool(o.Value("authenticated_length")),
		))
		if out, reason = c.withStream(out, tls, o.Value("transport"), "servername"); out != nil {
			out = withMux(out, o)
		}
	case "vless":
		out = proxy.Merge(base, model.New(
			"type", "vless",
			"uuid", o.String("uuid"),
			"flow", o.String("flow"),
			"udp", o.String("network") != "tcp",
			"packet-encoding", o.String("packet_encoding"),
			"encryption", o.String("encryption"),
		))
		if out, reason = c.withStream(out, tls, o.Value("transport"), "servername"); out != nil {
			out = withMux(out, o)
		}
	case "trojan":
		out = proxy.Merge(base, model.New(
			"type", "trojan",
			"password", o.String("password"),
			"udp", o.String("network") != "tcp",
		))
		if out, reason = c.withStream(out, tls, o.Value("transport"), "sni"); out != nil {
			out = withMux(out, o)
		}
	case "hysteria2":
		out = proxy.Merge(base, model.New(
			"type", "hysteria2",
			"password", o.String("password"),
			"ports", proxy.PortRanges(model.AsStrings(o.Value("server_ports"))),
			"hop-interval", seconds(o.String("hop_interval"), 0),
			"up", mbps(o.Value("up_mbps")),
			"down", mbps(o.Value("down_mbps")),
		))
		if obfs := model.AsObject(o.Value("obfs")); obfs.String("type") == "salamander" {
			out = proxy.Merge(out, model.New("obfs", "salamander", "obfs-password", obfs.String("password")))
		}
		out, reason = c.withTLS(out, tls, "sni", false)
	case "hysteria":
		out = proxy.Merge(base, model.New(
			"type", "hysteria",
			"auth-str", o.String("auth_str"),
			"auth", o.String("auth"), // Base64, as mihomo reads it
			"up", or(o.String("up"), mbps(o.Value("up_mbps"))),
			"down", or(o.String("down"), mbps(o.Value("down_mbps"))),
			"obfs", o.String("obfs"),
			"ports", proxy.PortRanges(model.AsStrings(o.Value("server_ports"))),
			"hop-interval", seconds(o.String("hop_interval"), 0),
			"recv-window-conn", model.AsInt(o.Value("recv_window_conn")),
			"recv-window", model.AsInt(o.Value("recv_window")),
			"disable-mtu-discovery", model.AsBool(o.Value("disable_mtu_discovery")),
		))
		out, reason = c.withTLS(out, tls, "sni", false)
	case "tuic":
		out = proxy.Merge(base, model.New(
			"type", "tuic",
			"uuid", o.String("uuid"),
			"password", o.String("password"),
			"congestion-controller", o.String("congestion_control"),
			"udp-relay-mode", o.String("udp_relay_mode"),
			"udp-over-stream", model.AsBool(o.Value("udp_over_stream")),
			"reduce-rtt", model.AsBool(o.Value("zero_rtt_handshake")),
			"heartbeat-interval", milliseconds(o.String("heartbeat")),
			"disable-sni", model.AsBool(tls.Value("disable_sni")),
		))
		out, reason = c.withTLS(out, tls, "sni", false)
	case "anytls":
		out = proxy.Merge(base, model.New(
			"type", "anytls",
			"password", o.String("password"),
			"udp", true,
			"idle-session-check-interval", seconds(o.String("idle_session_check_interval"), 0),
			"idle-session-timeout", seconds(o.String("idle_session_timeout"), 0),
			"min-idle-session", model.AsInt(o.Value("min_idle_session")),
		))
		out, reason = c.withTLS(out, tls, "sni", true)
	case "naive":
		// OpenWeir mihomo's native Naive; Cronet verifies the server and negotiates ALPN itself.
		if model.AsBool(tls.Value("insecure")) {
			return nil, "Naive cannot skip certificate verification"
		}
		overTCP, version := udpOverTCP(o.Value("udp_over_tcp"))
		out = proxy.Merge(base, model.New(
			"type", "naive",
			"username", o.String("username"),
			"password", o.String("password"),
			"sni", tls.String("server_name"),
			"headers", singleValues(model.AsObject(o.Value("extra_headers"))),
			"insecure-concurrency", model.AsInt(o.Value("insecure_concurrency")),
			"quic", model.AsBool(o.Value("quic")),
			"quic-congestion-control", o.String("quic_congestion_control"),
			"udp", overTCP,
			"udp-over-tcp", overTCP,
			"udp-over-tcp-version", version,
		))
		if ech := model.AsObject(tls.Value("ech")); model.AsBool(ech.Value("enabled")) {
			out.Set("ech-opts", c.echOptions(tag, ech))
		}
	case "http":
		out = proxy.Merge(base, model.New(
			"type", "http",
			"username", o.String("username"),
			"password", o.String("password"),
			"tls", model.AsBool(tls.Value("enabled")),
			"headers", singleValues(model.AsObject(o.Value("headers"))),
		))
		out, reason = c.withTLS(out, tls, "sni", false)
	case "socks":
		if version := o.String("version"); version != "" && version != "5" {
			return nil, "SOCKS" + version + " (mihomo speaks SOCKS5)"
		}
		out = proxy.Merge(base, model.New(
			"type", "socks5",
			"username", o.String("username"),
			"password", o.String("password"),
			"udp", o.String("network") != "tcp",
		))
	case "wireguard":
		out, reason = c.wireguard(base, o)
	case "snell":
		version := model.AsInt(o.Value("version"))
		if version == 0 {
			version = 4
		}
		out = proxy.Merge(base, model.New(
			"type", "snell",
			"psk", o.String("psk"),
			"userkey", o.String("userkey"),
			"version", version,
			"udp", version >= 3,
		))
		if mode := o.String("mode"); version == 6 && mode != "" && mode != "default" {
			out.Set("mode", mode)
		}
		if obfs := o.String("obfs_mode"); obfs != "" {
			if version >= 6 {
				return nil, "Snell v6 has no obfs"
			}
			out.Set("obfs-opts", model.New("mode", obfs, "host", o.String("obfs_host")))
		}
	case "ssh":
		key := strings.Join(model.AsStrings(o.Value("private_key")), "\n")
		if key == "" && o.String("password") == "" && o.String("private_key_path") != "" {
			return nil, "the private key is a local file"
		}
		out = proxy.Merge(base, model.New(
			"type", "ssh",
			"username", or(o.String("user"), "root"),
			"password", o.String("password"),
			"private-key", key,
			"private-key-passphrase", o.String("private_key_passphrase"),
			"host-key", model.AsStrings(o.Value("host_key")),
			"host-key-algorithms", model.AsStrings(o.Value("host_key_algorithms")),
		))
	case "tailscale":
		out = model.New(
			"name", tag,
			"type", "tailscale",
			"hostname", o.String("hostname"),
			"auth-key", o.String("auth_key"),
			"control-url", o.String("control_url"),
			"ephemeral", model.AsBool(o.Value("ephemeral")),
			"accept-routes", model.AsBool(o.Value("accept_routes")),
			"exit-node", o.String("exit_node"),
			"exit-node-allow-lan-access", model.AsBool(o.Value("exit_node_allow_lan_access")),
			"udp", true,
		)
		return out, ""
	default:
		return nil, ""
	}
	if out == nil {
		return nil, reason
	}
	if shadow != nil {
		if out, reason = c.overShadowTLS(out, o, shadow); out == nil {
			return nil, reason
		}
		o = shadow // dial options are the ShadowTLS outbound's
	}
	if port, _ := out.Get("port"); model.AsInt(port) == 0 && out.String("type") != "wireguard" && out.String("ports") == "" {
		return nil, "no server port"
	}
	if detour := o.String("detour"); detour != "" {
		out.Set("dialer-proxy", detour)
	}
	if model.AsBool(o.Value("tcp_fast_open")) && out.String("type") != "naive" {
		out.Set("tfo", true)
	}
	if model.AsBool(o.Value("tcp_multi_path")) {
		out.Set("mptcp", true)
	}
	return out, ""
}

// overShadowTLS gives a proxy the ShadowTLS layer it dials through: mihomo's shadow-tls plugin
// for Shadowsocks, obfs for Snell, and shadow-tls-opts, which replaces TLS, for the others.
func (c *singBox) overShadowTLS(out, o, shadow model.Object) (model.Object, string) {
	tls := model.AsObject(shadow.Value("tls"))
	version := model.AsInt(shadow.Value("version"))
	if version == 0 {
		version = 1
	}
	options := model.New(
		"host", tls.String("server_name"),
		"password", shadow.String("password"),
		"version", version,
		"alpn", model.AsStrings(tls.Value("alpn")),
		"skip-cert-verify", model.AsBool(tls.Value("insecure")),
	)
	fingerprint := ""
	if utls := model.AsObject(tls.Value("utls")); model.AsBool(utls.Value("enabled")) {
		fingerprint = or(utls.String("fingerprint"), "chrome")
	}
	switch kind := out.String("type"); kind {
	case "ss":
		if _, set := out.Get("plugin"); set {
			return nil, "a Shadowsocks plugin inside ShadowTLS"
		}
		out = proxy.Merge(out, model.New("client-fingerprint", fingerprint, "plugin", "shadow-tls", "plugin-opts", options))
	case "snell":
		if _, set := out.Get("obfs-opts"); set {
			return nil, "Snell obfs inside ShadowTLS"
		}
		out = proxy.Merge(out, model.New("client-fingerprint", fingerprint, "obfs-opts",
			append(model.Object{{Key: "mode", Value: "shadow-tls"}}, options...)))
	case "vmess", "vless", "trojan", "anytls":
		if model.AsBool(model.AsObject(o.Value("tls")).Value("enabled")) {
			return nil, "TLS inside ShadowTLS"
		}
		nameKey := "sni"
		if kind == "vmess" || kind == "vless" {
			nameKey = "servername"
			out.Set("tls", true)
		}
		out = proxy.Merge(out, model.New(
			nameKey, tls.String("server_name"),
			"skip-cert-verify", model.AsBool(tls.Value("insecure")),
			"client-fingerprint", fingerprint,
			"shadow-tls-opts", model.New("password", shadow.String("password"), "version", version),
		))
	default:
		return nil, kind + " over ShadowTLS"
	}
	return out, ""
}

func shadowsocks(base, o model.Object) (model.Object, string) {
	overTCP, version := udpOverTCP(o.Value("udp_over_tcp"))
	out := proxy.Merge(base, model.New(
		"type", "ss",
		"cipher", o.String("method"),
		"password", o.String("password"),
		"udp", o.String("network") != "tcp",
		"udp-over-tcp", overTCP,
		"udp-over-tcp-version", version,
	))
	plugin, reason := proxy.ShadowsocksPlugin(o.String("plugin"), proxy.PluginOptions(o.String("plugin_opts")))
	if reason != "" {
		return nil, reason
	}
	out = proxy.Merge(out, plugin)
	return withMux(out, o), ""
}

// udpOverTCP reads sing-box's udp_over_tcp: a boolean, or an object with enabled and version.
func udpOverTCP(value any) (bool, int) {
	if o := model.AsObject(value); o != nil {
		return model.AsBool(o.Value("enabled")), model.AsInt(o.Value("version"))
	}
	return model.AsBool(value), 0
}

func (c *singBox) wireguard(base, o model.Object) (model.Object, string) {
	tag := o.String("tag")
	peers := model.AsList(o.Value("peers"))
	var ip, ipv6 string
	for _, prefix := range model.AsStrings(or2(o.Value("address"), o.Value("local_address"))) {
		address, _, _ := strings.Cut(prefix, "/")
		switch {
		case strings.Contains(address, ":") && ipv6 == "":
			ipv6 = address
		case !strings.Contains(address, ":") && ip == "":
			ip = address
		default:
			c.result.Warn(model.WarnIgnoredOption, "%s: address %s (mihomo takes one IPv4 and one IPv6 address)", tag, prefix)
		}
	}
	peer := func(p model.Object) model.Object {
		reserved := model.AsList(p.Value("reserved"))
		if len(reserved) == 0 {
			reserved = model.AsList(o.Value("reserved"))
		}
		port := model.AsInt(p.Value("port"))
		if port == 0 {
			port = model.AsInt(p.Value("server_port"))
		}
		return model.New(
			"server", or(p.String("address"), p.String("server")),
			"port", port,
			"public-key", or(p.String("public_key"), o.String("peer_public_key")),
			"pre-shared-key", or(p.String("pre_shared_key"), o.String("pre_shared_key")),
			"allowed-ips", model.AsStrings(p.Value("allowed_ips")),
			"reserved", reserved,
		)
	}
	out := proxy.Merge(base, model.New("type", "wireguard"))
	if len(peers) > 1 {
		var list []any
		keepalive := 0
		for _, item := range peers {
			keepalive = max(keepalive, model.AsInt(model.AsObject(item).Value("persistent_keepalive_interval")))
			p := peer(model.AsObject(item))
			if len(model.AsStrings(p.Value("allowed-ips"))) == 0 {
				p.Set("allowed-ips", []string{"0.0.0.0/0", "::/0"})
			}
			list = append(list, p)
		}
		return proxy.Merge(out, model.New(
			"ip", ip,
			"ipv6", ipv6,
			"private-key", o.String("private_key"),
			"peers", list,
			"persistent-keepalive", keepalive,
			"mtu", model.AsInt(o.Value("mtu")),
			"workers", model.AsInt(o.Value("workers")),
			"udp", true,
		)), ""
	}
	// sing-box 1.11 endpoints keep the server in the peer; older outbounds at the top.
	single := o
	if len(peers) == 1 {
		single = model.AsObject(peers[0])
	}
	fields := peer(single)
	server := or(fields.String("server"), o.String("server"))
	port := model.AsInt(fields.Value("port"))
	if port == 0 {
		port = model.AsInt(o.Value("server_port"))
	}
	if server == "" || port == 0 {
		return nil, "no WireGuard peer address"
	}
	return proxy.Merge(out, model.New(
		"server", server,
		"port", port,
		"ip", ip,
		"ipv6", ipv6,
		"private-key", o.String("private_key"),
		"public-key", fields.Value("public-key"),
		"pre-shared-key", fields.Value("pre-shared-key"),
		"allowed-ips", fields.Value("allowed-ips"),
		"reserved", fields.Value("reserved"),
		"persistent-keepalive", model.AsInt(single.Value("persistent_keepalive_interval")),
		"mtu", model.AsInt(o.Value("mtu")),
		"workers", model.AsInt(o.Value("workers")),
		"udp", true,
	)), ""
}

// withStream adds TLS and the V2Ray transport, which VMess, VLESS and Trojan share.
func (c *singBox) withStream(out, tls model.Object, transport any, nameKey string) (model.Object, string) {
	out, reason := c.withTLS(out, tls, nameKey, true)
	if out == nil {
		return nil, reason
	}
	t := model.AsObject(transport)
	switch kind := t.String("type"); kind {
	case "":
	case "ws":
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", t.String("path"),
			"headers", singleValues(model.AsObject(t.Value("headers"))),
			"max-early-data", model.AsInt(t.Value("max_early_data")),
			"early-data-header-name", t.String("early_data_header_name"),
		)))
	case "httpupgrade":
		headers := singleValues(model.AsObject(t.Value("headers")))
		if host := t.String("host"); host != "" {
			headers.Set("Host", host)
		}
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", t.String("path"),
			"headers", headers,
			"v2ray-http-upgrade", true,
		)))
	case "grpc":
		out = proxy.Merge(out, model.New("network", "grpc", "grpc-opts", model.New(
			"grpc-service-name", t.String("service_name"),
		)))
	case "http":
		hosts := model.AsStrings(t.Value("host"))
		if _, secure := out.Get("tls"); secure || out.String("type") == "trojan" {
			out = proxy.Merge(out, model.New("network", "h2", "h2-opts", model.New(
				"host", hosts,
				"path", t.String("path"),
			)))
		} else {
			headers := model.Object{}
			for _, field := range model.AsObject(t.Value("headers")) {
				headers = append(headers, model.Field{Key: field.Key, Value: model.AsStrings(field.Value)})
			}
			if len(hosts) > 0 {
				headers.Set("Host", hosts)
			}
			out = proxy.Merge(out, model.New("network", "http", "http-opts", model.New(
				"method", t.String("method"),
				"path", []string{or(t.String("path"), "/")},
				"headers", headers,
			)))
		}
	case "xhttp":
		// OpenWeir's extended JSON; mihomo has XHTTP for VLESS only.
		if out.String("type") != "vless" {
			return nil, "XHTTP on " + out.String("type")
		}
		out = proxy.Merge(out, model.New("network", "xhttp", "xhttp-opts", model.New(
			"path", t.String("path"),
			"host", t.String("host"),
			"mode", t.String("mode"),
		)))
	default:
		return nil, "transport " + kind
	}
	return out, ""
}

// withTLS adds the TLS options. VMess, VLESS and HTTP take a "tls" switch, and VMess and VLESS
// name the server "servername"; the other protocols always use TLS and name it "sni".
func (c *singBox) withTLS(out, tls model.Object, nameKey string, fingerprints bool) (model.Object, string) {
	if !model.AsBool(tls.Value("enabled")) {
		return out, ""
	}
	tag, kind := out.String("name"), out.String("type")
	switch kind {
	case "vmess", "vless", "http":
		out.Set("tls", true)
	}
	out = proxy.Merge(out, model.New(
		nameKey, tls.String("server_name"),
		"alpn", model.AsStrings(tls.Value("alpn")),
		"skip-cert-verify", model.AsBool(tls.Value("insecure")),
	))
	if ech := model.AsObject(tls.Value("ech")); model.AsBool(ech.Value("enabled")) {
		if !echTypes[kind] {
			return nil, "TLS ECH on " + kind
		}
		out.Set("ech-opts", c.echOptions(tag, ech))
	}
	if certificate := strings.Join(model.AsStrings(tls.Value("certificate")), "\n"); certificate != "" {
		// mihomo pins a certificate of the chain by its SHA-256: the server's own, or a CA the
		// server sends.
		if fingerprint := certificateHash(certificate); fingerprint != "" {
			out.Set("fingerprint", fingerprint)
		}
	}
	if cert := strings.Join(model.AsStrings(tls.Value("client_certificate")), "\n"); cert != "" {
		out = proxy.Merge(out, model.New("certificate", cert, "private-key", strings.Join(model.AsStrings(tls.Value("client_key")), "\n")))
	}
	for _, key := range []string{"certificate_path", "client_certificate_path", "client_key_path"} {
		if tls.String(key) != "" {
			c.result.Warn(model.WarnIgnoredOption, "%s: tls %s is a local file", tag, key)
		}
	}
	if tls.Value("certificate_public_key_sha256") != nil {
		c.result.Warn(model.WarnIgnoredOption, "%s: tls certificate_public_key_sha256 (mihomo pins whole certificates)", tag)
	}
	if model.AsBool(tls.Value("disable_sni")) && kind != "tuic" {
		c.result.Warn(model.WarnIgnoredOption, "%s: tls disable_sni", tag)
	}
	if utls := model.AsObject(tls.Value("utls")); fingerprints && model.AsBool(utls.Value("enabled")) {
		out.Set("client-fingerprint", or(utls.String("fingerprint"), "chrome"))
	}
	if reality := model.AsObject(tls.Value("reality")); model.AsBool(reality.Value("enabled")) {
		if !fingerprints {
			return nil, "REALITY on " + kind
		}
		if _, set := out.Get("client-fingerprint"); !set {
			out.Set("client-fingerprint", "chrome")
		}
		out.Set("reality-opts", model.New(
			"public-key", reality.String("public_key"),
			"short-id", reality.String("short_id"),
		))
	}
	return out, ""
}

// echOptions maps sing-box's ECH: configs in PEM, or none, which both read from DNS.
func (c *singBox) echOptions(tag string, ech model.Object) model.Object {
	config := ""
	if block, _ := pem.Decode([]byte(strings.Join(model.AsStrings(ech.Value("config")), "\n"))); block != nil {
		config = base64.StdEncoding.EncodeToString(block.Bytes)
	}
	if config == "" && ech.String("config_path") != "" {
		c.result.Warn(model.WarnIgnoredOption, "%s: tls ech config_path is a local file; the ECH config comes from DNS", tag)
	}
	return model.New("enable", true, "config", config, "query-server-name", ech.String("query_server_name"))
}

// certificateHash returns the SHA-256 of a PEM certificate's DER, in hex, as mihomo's
// fingerprint takes it.
func certificateHash(text string) string {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// withMux maps sing-box multiplex onto mihomo's smux.
func withMux(out, o model.Object) model.Object {
	mux := model.AsObject(o.Value("multiplex"))
	if !model.AsBool(mux.Value("enabled")) {
		return out
	}
	brutal := model.AsObject(mux.Value("brutal"))
	return proxy.Merge(out, model.New("smux", model.New(
		"enabled", true,
		"protocol", mux.String("protocol"),
		"max-connections", model.AsInt(mux.Value("max_connections")),
		"min-streams", model.AsInt(mux.Value("min_streams")),
		"max-streams", model.AsInt(mux.Value("max_streams")),
		"padding", model.AsBool(mux.Value("padding")),
		"brutal-opts", model.New(
			"enabled", model.AsBool(brutal.Value("enabled")),
			"up", mbps(brutal.Value("up_mbps")),
			"down", mbps(brutal.Value("down_mbps")),
		),
	)))
}

// singleValues turns sing-box's header lists into the single values mihomo takes.
func singleValues(headers model.Object) model.Object {
	out := model.Object{}
	for _, field := range headers {
		if values := model.AsStrings(field.Value); len(values) > 0 {
			out = append(out, model.Field{Key: field.Key, Value: values[0]})
		}
	}
	return out
}

func mbps(value any) string {
	if speed := model.AsInt(value); speed > 0 {
		return strconv.Itoa(speed) + " Mbps"
	}
	return ""
}

func milliseconds(duration string) int {
	if duration == "" {
		return 0
	}
	if strings.HasSuffix(duration, "ms") {
		value, _ := strconv.Atoi(strings.TrimSuffix(duration, "ms"))
		return value
	}
	return seconds(duration, 0) * 1000
}

func or2(values ...any) any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
