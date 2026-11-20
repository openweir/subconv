package singbox

import (
	"github.com/openweir/subconv/internal/model"

	"strconv"
	"strings"
)

// proxy converts a sing-box outbound into an OpenWeir mihomo proxy. It returns nil and a reason
// when an option cannot be represented, or nil and "" when the type has no counterpart.
func (c *singBox) proxy(o model.Object) (model.Object, string) {
	// Every proxy starts name, type, server, port; merge fills the type in its place.
	base := model.Object{
		{Key: "name", Value: o.String("tag")},
		{Key: "type", Value: ""},
		{Key: "server", Value: o.String("server")},
		{Key: "port", Value: model.AsInt(o.Value("server_port"))},
	}
	tls := model.AsObject(o.Value("tls"))
	var out model.Object
	reason := ""
	switch o.String("type") {
	case "shadowsocks":
		out, reason = shadowsocks(base, o)
	case "vmess":
		out = merge(base, model.New(
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
		out = merge(base, model.New(
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
		out = merge(base, model.New(
			"type", "trojan",
			"password", o.String("password"),
			"udp", o.String("network") != "tcp",
		))
		if out, reason = withStream(out, tls, o.Value("transport"), "sni"); out != nil {
			out = withMux(out, o)
		}
	case "hysteria2":
		out = merge(base, model.New(
			"type", "hysteria2",
			"password", o.String("password"),
			"ports", portRanges(model.AsStrings(o.Value("server_ports"))),
			"hop-interval", seconds(o.String("hop_interval"), 0),
			"up", mbps(o.Value("up_mbps")),
			"down", mbps(o.Value("down_mbps")),
		))
		if obfs := model.AsObject(o.Value("obfs")); obfs.String("type") == "salamander" {
			out = merge(out, model.New("obfs", "salamander", "obfs-password", obfs.String("password")))
		}
		out, reason = withTLS(out, tls, "sni", false)
	case "hysteria":
		out = merge(base, model.New(
			"type", "hysteria",
			"auth-str", or(o.String("auth_str"), o.String("auth")),
			"up", mbps(o.Value("up_mbps")),
			"down", mbps(o.Value("down_mbps")),
			"obfs", o.String("obfs"),
			"ports", portRanges(model.AsStrings(o.Value("server_ports"))),
		))
		out, reason = withTLS(out, tls, "sni", false)
	case "tuic":
		out = merge(base, model.New(
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
		out = merge(base, model.New("type", "anytls", "password", o.String("password"), "udp", true))
		out, reason = withTLS(out, tls, "sni", true)
	case "naive":
		// OpenWeir mihomo's native Naive; Cronet verifies the server and negotiates ALPN itself.
		if model.AsBool(tls.Value("insecure")) {
			return nil, "Naive cannot skip certificate verification"
		}
		out = merge(base, model.New(
			"type", "naive",
			"username", o.String("username"),
			"password", o.String("password"),
			"sni", tls.String("server_name"),
			"quic", model.AsBool(o.Value("quic")),
			"quic-congestion-control", o.String("quic_congestion_control"),
		))
	case "http":
		out = merge(base, model.New(
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
		out = merge(base, model.New(
			"type", "socks5",
			"username", o.String("username"),
			"password", o.String("password"),
			"udp", o.String("network") != "tcp",
		))
	case "wireguard":
		out, reason = wireguard(base, o)
	case "ssh":
		out = merge(base, model.New(
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
	out := merge(base, model.New(
		"type", "ss",
		"cipher", o.String("method"),
		"password", o.String("password"),
		"udp", o.String("network") != "tcp",
		"udp-over-tcp", model.AsBool(o.Value("udp_over_tcp")),
	))
	switch plugin := o.String("plugin"); plugin {
	case "":
	case "obfs-local":
		options := pluginOptions(o.String("plugin_opts"))
		out = merge(out, model.New("plugin", "obfs", "plugin-opts", model.New(
			"mode", options["obfs"],
			"host", options["obfs-host"],
		)))
	case "v2ray-plugin":
		options := pluginOptions(o.String("plugin_opts"))
		mode := or(options["mode"], "websocket")
		if mode != "websocket" {
			return nil, "v2ray-plugin mode " + mode
		}
		_, tls := options["tls"]
		_, mux := options["mux"]
		out = merge(out, model.New("plugin", "v2ray-plugin", "plugin-opts", model.New(
			"mode", "websocket",
			"tls", tls,
			"host", options["host"],
			"path", options["path"],
			"mux", mux && options["mux"] != "0",
		)))
	default:
		return nil, "plugin " + plugin
	}
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
	out := merge(base, model.New(
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
		out = merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", t.String("path"),
			"headers", headers,
			"max-early-data", model.AsInt(t.Value("max_early_data")),
			"early-data-header-name", t.String("early_data_header_name"),
		)))
	case "httpupgrade":
		headers := model.New("Host", t.String("host"))
		out = merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", t.String("path"),
			"headers", headers,
			"v2ray-http-upgrade", true,
		)))
	case "grpc":
		out = merge(out, model.New("network", "grpc", "grpc-opts", model.New(
			"grpc-service-name", t.String("service_name"),
		)))
	case "http":
		hosts := model.AsStrings(t.Value("host"))
		if _, secure := out.Get("tls"); secure || out.String("type") == "trojan" {
			out = merge(out, model.New("network", "h2", "h2-opts", model.New(
				"host", hosts,
				"path", t.String("path"),
			)))
		} else {
			paths := []string{or(t.String("path"), "/")}
			out = merge(out, model.New("network", "http", "http-opts", model.New(
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
		out = merge(out, model.New("network", "xhttp", "xhttp-opts", model.New(
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
	out = merge(out, model.New(
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
	return merge(out, model.New("smux", model.New(
		"enabled", true,
		"protocol", mux.String("protocol"),
		"max-connections", model.AsInt(mux.Value("max_connections")),
		"min-streams", model.AsInt(mux.Value("min_streams")),
		"max-streams", model.AsInt(mux.Value("max_streams")),
		"padding", model.AsBool(mux.Value("padding")),
	)))
}

// merge sets the fields of extra on base, keeping base's order for keys it has.
func merge(base, extra model.Object) model.Object {
	out := make(model.Object, 0, len(base)+len(extra))
	for _, field := range base {
		if value, set := extra.Get(field.Key); set {
			out = append(out, model.Field{Key: field.Key, Value: value})
		} else if !model.Empty(field.Value) {
			out = append(out, field)
		}
	}
	for _, field := range extra {
		if _, set := out.Get(field.Key); !set {
			out = append(out, field)
		}
	}
	return out
}

func pluginOptions(text string) map[string]string {
	options := map[string]string{}
	for part := range strings.SplitSeq(text, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
		if key != "" {
			options[key] = value
		}
	}
	return options
}

// portRanges turns sing-box's "1000:2000" into mihomo's "1000-2000", comma separated.
func portRanges(ranges []string) string {
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, strings.ReplaceAll(r, ":", "-"))
	}
	return strings.Join(out, ",")
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
