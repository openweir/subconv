package singbox

import (
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"

	"strconv"
	"strings"
)

// proxy converts a sing-box outbound into an OpenWeir mihomo proxy. It returns nil and a reason
// when an option cannot be represented, or nil and "" when the type has no counterpart.
func (c *singBox) proxy(o model.Object) (model.Object, string) {
	base := proxy.Base(o.String("tag"), o.String("server"), model.AsInt(o.Value("server_port")))
	tls := model.AsObject(o.Value("tls"))
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
			"global-padding", model.AsBool(o.Value("global_padding")),
			"authenticated-length", model.AsBool(o.Value("authenticated_length")),
		))
		if out, reason = withStream(out, tls, o.Value("transport"), "servername"); out != nil {
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
		if out, reason = withStream(out, tls, o.Value("transport"), "servername"); out != nil {
			out = withMux(out, o)
		}
	case "trojan":
		out = proxy.Merge(base, model.New(
			"type", "trojan",
			"password", o.String("password"),
			"udp", o.String("network") != "tcp",
		))
		if out, reason = withStream(out, tls, o.Value("transport"), "sni"); out != nil {
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
		out, reason = withTLS(out, tls, "sni", false)
	case "hysteria":
		out = proxy.Merge(base, model.New(
			"type", "hysteria",
			"auth-str", or(o.String("auth_str"), o.String("auth")),
			"up", mbps(o.Value("up_mbps")),
			"down", mbps(o.Value("down_mbps")),
			"obfs", o.String("obfs"),
			"ports", proxy.PortRanges(model.AsStrings(o.Value("server_ports"))),
		))
		out, reason = withTLS(out, tls, "sni", false)
	case "tuic":
		out = proxy.Merge(base, model.New(
			"type", "tuic",
			"uuid", o.String("uuid"),
			"password", o.String("password"),
			"congestion-controller", o.String("congestion_control"),
			"udp-relay-mode", o.String("udp_relay_mode"),
			"reduce-rtt", model.AsBool(o.Value("zero_rtt_handshake")),
			"heartbeat-interval", milliseconds(o.String("heartbeat")),
		))
		out, reason = withTLS(out, tls, "sni", false)
	case "anytls":
		out = proxy.Merge(base, model.New("type", "anytls", "password", o.String("password"), "udp", true))
		out, reason = withTLS(out, tls, "sni", true)
	case "naive":
		// OpenWeir mihomo's native Naive; Cronet verifies the server and negotiates ALPN itself.
		if model.AsBool(tls.Value("insecure")) {
			return nil, "Naive cannot skip certificate verification"
		}
		out = proxy.Merge(base, model.New(
			"type", "naive",
			"username", o.String("username"),
			"password", o.String("password"),
			"sni", tls.String("server_name"),
			"quic", model.AsBool(o.Value("quic")),
			"quic-congestion-control", o.String("quic_congestion_control"),
		))
	case "http":
		out = proxy.Merge(base, model.New(
			"type", "http",
			"username", o.String("username"),
			"password", o.String("password"),
			"tls", model.AsBool(tls.Value("enabled")),
			"sni", tls.String("server_name"),
			"skip-cert-verify", model.AsBool(tls.Value("insecure")),
		))
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
		out, reason = wireguard(base, o)
	case "snell":
		version := model.AsInt(o.Value("version"))
		if version == 0 {
			version = 4
		}
		out = proxy.Merge(base, model.New(
			"type", "snell",
			"psk", o.String("psk"),
			"version", version,
			"udp", version >= 3,
		))
		if mode := o.String("mode"); version == 6 && mode != "" && mode != "default" {
			out.Set("mode", mode)
		}
		if obfs := o.String("obfs_mode"); obfs != "" {
			out.Set("obfs-opts", model.New("mode", obfs, "host", o.String("obfs_host")))
		}
	case "ssh":
		out = proxy.Merge(base, model.New(
			"type", "ssh",
			"username", o.String("user"),
			"password", o.String("password"),
			"private-key", strings.Join(model.AsStrings(o.Value("private_key")), "\n"),
			"private-key-passphrase", o.String("private_key_passphrase"),
			"host-key", model.AsStrings(o.Value("host_key")),
		))
	default:
		return nil, ""
	}
	if out == nil {
		return nil, reason
	}
	if port, _ := out.Get("port"); model.AsInt(port) == 0 && out.String("type") != "wireguard" {
		return nil, "no server port"
	}
	if detour := o.String("detour"); detour != "" {
		out.Set("dialer-proxy", detour)
	}
	if fastOpen := model.AsBool(o.Value("tcp_fast_open")); fastOpen {
		out.Set("tfo", true)
	}
	return out, ""
}

func shadowsocks(base, o model.Object) (model.Object, string) {
	out := proxy.Merge(base, model.New(
		"type", "ss",
		"cipher", o.String("method"),
		"password", o.String("password"),
		"udp", o.String("network") != "tcp",
		"udp-over-tcp", model.AsBool(o.Value("udp_over_tcp")),
	))
	plugin, reason := proxy.ShadowsocksPlugin(o.String("plugin"), proxy.PluginOptions(o.String("plugin_opts")))
	if reason != "" {
		return nil, reason
	}
	out = proxy.Merge(out, plugin)
	return withMux(out, o), ""
}

func wireguard(base, o model.Object) (model.Object, string) {
	peers := model.AsList(o.Value("peers"))
	if len(peers) > 1 {
		return nil, "more than one WireGuard peer"
	}
	// sing-box 1.11 endpoints keep the server in the peer; older outbounds at the top.
	peer := o
	if len(peers) == 1 {
		peer = model.AsObject(peers[0])
	}
	server := or(peer.String("address"), o.String("server"))
	port := model.AsInt(peer.Value("port"))
	if port == 0 {
		port = model.AsInt(o.Value("server_port"))
	}
	var ip, ipv6 string
	for _, prefix := range model.AsStrings(or2(o.Value("address"), o.Value("local_address"))) {
		address, _, _ := strings.Cut(prefix, "/")
		if strings.Contains(address, ":") {
			ipv6 = or(ipv6, address)
		} else {
			ip = or(ip, address)
		}
	}
	reserved := model.AsList(peer.Value("reserved"))
	if len(reserved) == 0 {
		reserved = model.AsList(o.Value("reserved"))
	}
	out := proxy.Merge(base, model.New(
		"type", "wireguard",
		"server", server,
		"port", port,
		"ip", ip,
		"ipv6", ipv6,
		"private-key", o.String("private_key"),
		"public-key", or(peer.String("public_key"), o.String("peer_public_key")),
		"pre-shared-key", or(peer.String("pre_shared_key"), o.String("pre_shared_key")),
		"allowed-ips", model.AsStrings(peer.Value("allowed_ips")),
		"reserved", reserved,
		"mtu", model.AsInt(o.Value("mtu")),
		"udp", true,
	))
	if server == "" || port == 0 {
		return nil, "no WireGuard peer address"
	}
	return out, ""
}

// withStream adds TLS and the V2Ray transport, which VMess, VLESS and Trojan share.
func withStream(out, tls model.Object, transport any, nameKey string) (model.Object, string) {
	out, reason := withTLS(out, tls, nameKey, true)
	if out == nil {
		return nil, reason
	}
	t := model.AsObject(transport)
	switch kind := t.String("type"); kind {
	case "":
	case "ws":
		headers := model.AsObject(t.Value("headers"))
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", t.String("path"),
			"headers", headers,
			"max-early-data", model.AsInt(t.Value("max_early_data")),
			"early-data-header-name", t.String("early_data_header_name"),
		)))
	case "httpupgrade":
		headers := model.New("Host", t.String("host"))
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
			paths := []string{or(t.String("path"), "/")}
			out = proxy.Merge(out, model.New("network", "http", "http-opts", model.New(
				"method", t.String("method"),
				"path", paths,
				"headers", model.New("Host", hosts),
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

// withTLS adds the TLS options. VMess and VLESS take a "tls" switch and "servername"; the other
// protocols always use TLS and name the server "sni".
func withTLS(out, tls model.Object, nameKey string, fingerprints bool) (model.Object, string) {
	if !model.AsBool(tls.Value("enabled")) {
		return out, ""
	}
	if ech := model.AsObject(tls.Value("ech")); model.AsBool(ech.Value("enabled")) {
		return nil, "TLS ECH"
	}
	switch out.String("type") {
	case "vmess", "vless":
		out.Set("tls", true)
	}
	out = proxy.Merge(out, model.New(
		nameKey, tls.String("server_name"),
		"alpn", model.AsStrings(tls.Value("alpn")),
		"skip-cert-verify", model.AsBool(tls.Value("insecure")),
	))
	if utls := model.AsObject(tls.Value("utls")); fingerprints && model.AsBool(utls.Value("enabled")) {
		out.Set("client-fingerprint", or(utls.String("fingerprint"), "chrome"))
	}
	if reality := model.AsObject(tls.Value("reality")); model.AsBool(reality.Value("enabled")) {
		if !fingerprints {
			return nil, "REALITY on " + out.String("type")
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

// withMux maps sing-box multiplex onto mihomo's smux.
func withMux(out, o model.Object) model.Object {
	mux := model.AsObject(o.Value("multiplex"))
	if !model.AsBool(mux.Value("enabled")) {
		return out
	}
	return proxy.Merge(out, model.New("smux", model.New(
		"enabled", true,
		"protocol", mux.String("protocol"),
		"max-connections", model.AsInt(mux.Value("max_connections")),
		"min-streams", model.AsInt(mux.Value("min_streams")),
		"max-streams", model.AsInt(mux.Value("max_streams")),
		"padding", model.AsBool(mux.Value("padding")),
	)))
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
