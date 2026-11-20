// Package links converts share-link subscriptions, one link per line and often Base64 encoded
// as a whole, into OpenWeir mihomo proxies.
//
// The forms follow the common clients' (v2rayN's VMess JSON, Xray's VLESS and Trojan
// parameters, SIP002 Shadowsocks) and the OpenWeir panel's links (api-edge links.ts): Naive as
// naive+https and naive+quic, Mieru as mierus, Nowhere NW3 as nowhere, and Snell in the form
// Shadowrocket imports. A links subscription has proxies only; groups and rules are the
// client's.
package links

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

var errNoLinks = errors.New("no share links")

// Convert converts a share-link subscription.
func Convert(data []byte) (*model.Result, error) {
	text := string(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	if !strings.Contains(text, "://") {
		decoded, err := decodeBase64(text)
		if err != nil {
			return nil, errNoLinks
		}
		text = string(decoded)
	}
	result := &model.Result{Format: model.FormatLinks}
	found := false
	var lines []string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(strings.ToLower(line), "mieru://"); ok && !strings.Contains(rest, "@") {
			expanded, reason := mieruProfiles(line)
			if expanded == nil {
				found = true
				// The payload holds the credentials; name the scheme only.
				result.Warn(model.WarnUnsupportedOption, "mieru: %s", reason)
			}
			lines = append(lines, expanded...)
			continue
		}
		lines = append(lines, line)
	}
	for _, line := range lines {
		scheme, _, ok := strings.Cut(line, "://")
		if !ok || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		found = true
		p, reason := parse(strings.ToLower(scheme), line)
		if p == nil {
			code := model.WarnUnsupportedOption
			if reason == "" {
				code, reason = model.WarnUnsupportedProxy, "scheme "+scheme
			}
			result.Warn(code, "%s: %s", label(line), reason)
			continue
		}
		result.Proxies = append(result.Proxies, p)
	}
	if !found {
		return nil, errNoLinks
	}
	proxy.UniqueNames(result.Proxies, "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL")
	return result, nil
}

// parse converts one link; nil and "" mean an unknown scheme, nil and a reason an option that
// cannot be represented.
func parse(scheme, line string) (model.Object, string) {
	switch scheme {
	case "vmess":
		return vmess(line)
	case "ss":
		return shadowsocks(line)
	case "ssr":
		return shadowsocksR(line)
	case "snell":
		return snell(line)
	}
	u, err := url.Parse(line)
	if err != nil || u.Hostname() == "" {
		return nil, "not a valid link"
	}
	port, _ := strconv.Atoi(u.Port())
	name := fragment(u)
	if name == "" {
		name = u.Hostname()
	}
	q := query(u)
	base := proxy.Base(name, u.Hostname(), port)
	var out model.Object
	reason := ""
	switch scheme {
	case "vless":
		out = proxy.Merge(base, model.New(
			"type", "vless",
			"uuid", u.User.Username(),
			"flow", q.Get("flow"),
			"udp", true,
			"encryption", noneEmpty(q.Get("encryption")),
		))
		out, reason = stream(out, q, "servername", "")
	case "trojan":
		out = proxy.Merge(base, model.New("type", "trojan", "password", u.User.Username(), "udp", true))
		out, reason = stream(out, q, "sni", "tls")
	case "hysteria2", "hy2":
		out = proxy.Merge(base, model.New(
			"type", "hysteria2",
			"password", userinfo(u),
			"ports", proxy.PortRanges(strings.Split(q.Get("mport"), ",")),
			"sni", q.Get("sni"),
			"skip-cert-verify", flag(q, "insecure", "allowInsecure"),
			"alpn", list(q.Get("alpn")),
			"obfs", q.Get("obfs"),
			"obfs-password", q.Get("obfs-password"),
		))
	case "hysteria":
		out = proxy.Merge(base, model.New(
			"type", "hysteria",
			"auth-str", or(q.Get("auth"), q.Get("auth_str")),
			"protocol", q.Get("protocol"),
			"up", mbps(q.Get("upmbps")),
			"down", mbps(q.Get("downmbps")),
			"obfs", q.Get("obfsParam"),
			"sni", q.Get("peer"),
			"skip-cert-verify", flag(q, "insecure"),
			"alpn", list(q.Get("alpn")),
			"ports", proxy.PortRanges(strings.Split(q.Get("mport"), ",")),
		))
	case "tuic":
		password, _ := u.User.Password()
		out = proxy.Merge(base, model.New(
			"type", "tuic",
			"uuid", u.User.Username(),
			"password", password,
			"sni", q.Get("sni"),
			"alpn", list(q.Get("alpn")),
			"congestion-controller", q.Get("congestion_control"),
			"udp-relay-mode", q.Get("udp_relay_mode"),
			"skip-cert-verify", flag(q, "allow_insecure", "insecure"),
		))
	case "anytls":
		out = proxy.Merge(base, model.New("type", "anytls", "password", userinfo(u), "udp", true))
		if q.Get("security") == "reality" {
			out, reason = stream(out, q, "sni", "")
		} else {
			out = proxy.Merge(out, model.New(
				"sni", q.Get("sni"),
				"skip-cert-verify", flag(q, "insecure", "allowInsecure"),
				"client-fingerprint", q.Get("fp"),
			))
		}
	case "naive+https", "naive+quic", "naive":
		// OpenWeir mihomo's native Naive; Cronet verifies the server itself.
		password, _ := u.User.Password()
		out = proxy.Merge(base, model.New(
			"type", "naive",
			"username", u.User.Username(),
			"password", password,
			"sni", q.Get("sni"),
			"quic", scheme == "naive+quic",
		))
	case "socks5", "socks", "socks5h":
		user, password := credentials(u)
		out = proxy.Merge(base, model.New("type", "socks5", "username", user, "password", password, "udp", true))
	case "http", "https":
		user, password := credentials(u)
		out = proxy.Merge(base, model.New(
			"type", "http",
			"username", user,
			"password", password,
			"tls", scheme == "https",
			"sni", q.Get("sni"),
		))
	case "mierus", "mieru":
		password, _ := u.User.Password()
		ports := q.Get("port")
		out = proxy.Merge(base, model.New(
			"name", or(q.Get("profile"), name),
			"type", "mieru",
			"transport", strings.ToUpper(or(q.Get("protocol"), "TCP")),
			"username", u.User.Username(),
			"password", password,
			"multiplexing", or(q.Get("multiplexing"), "MULTIPLEXING_LOW"),
			"handshake-mode", q.Get("handshake-mode"),
			"traffic-pattern", q.Get("traffic-pattern"),
			"udp", true,
		))
		if strings.ContainsAny(ports, "-,") {
			out = proxy.Merge(out, model.New("port-range", ports))
		} else if number, err := strconv.Atoi(ports); err == nil {
			out.Set("port", number)
		}
	case "nowhere":
		out = proxy.Merge(base, model.New(
			"type", "nowhere",
			"password", u.User.Username(),
			"network", or(q.Get("net"), "tcp"),
			"udp", true,
			"sni", q.Get("sni"),
			"pin", q.Get("pin"),
		))
		// Morph defaults to on, so an explicit off must be written.
		out.Set("morph", q.Get("morph") != "0")
	case "wireguard", "wg":
		out = proxy.Merge(base, model.New(
			"type", "wireguard",
			"private-key", userinfo(u),
			"public-key", or(q.Get("publickey"), q.Get("publicKey")),
			"pre-shared-key", or(q.Get("presharedkey"), q.Get("preSharedKey")),
			"mtu", atoi(q.Get("mtu")),
			"udp", true,
		))
		for _, address := range list(q.Get("address")) {
			ip, _, _ := strings.Cut(address, "/")
			if strings.Contains(ip, ":") {
				out.Set("ipv6", ip)
			} else {
				out.Set("ip", ip)
			}
		}
		if reserved := list(q.Get("reserved")); len(reserved) > 0 {
			values := make([]any, 0, len(reserved))
			for _, value := range reserved {
				values = append(values, atoi(value))
			}
			out.Set("reserved", values)
		}
	case "tg":
		return nil, "a Telegram proxy, which only Telegram uses"
	default:
		return nil, ""
	}
	if out == nil {
		return nil, reason
	}
	return finish(out, q)
}

// stream adds the Xray share-link transport and security parameters of VLESS and Trojan (and
// AnyTLS with REALITY). security defaults to fallback when absent.
func stream(out model.Object, q url.Values, nameKey, fallback string) (model.Object, string) {
	security := or(q.Get("security"), fallback)
	switch security {
	case "none", "":
	case "tls", "xtls", "reality":
		if out.String("type") == "vless" {
			out.Set("tls", true)
		}
		out = proxy.Merge(out, model.New(
			nameKey, or(q.Get("sni"), q.Get("peer")),
			"alpn", list(q.Get("alpn")),
			"skip-cert-verify", flag(q, "allowInsecure", "insecure"),
			"client-fingerprint", q.Get("fp"),
		))
		if security == "reality" {
			if _, set := out.Get("client-fingerprint"); !set {
				out.Set("client-fingerprint", "chrome")
			}
			out.Set("reality-opts", model.New("public-key", q.Get("pbk"), "short-id", q.Get("sid")))
		}
	default:
		return nil, "security " + security
	}
	host, path := q.Get("host"), q.Get("path")
	switch kind := or(q.Get("type"), "tcp"); kind {
	case "tcp", "raw":
		if q.Get("headerType") == "http" {
			out = proxy.Merge(out, model.New("network", "http", "http-opts", model.New(
				"path", []string{or(path, "/")},
				"headers", model.New("Host", list(host)),
			)))
		}
	case "ws":
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", path,
			"headers", model.New("Host", host),
		)))
	case "httpupgrade":
		out = proxy.Merge(out, model.New("network", "ws", "ws-opts", model.New(
			"path", path,
			"headers", model.New("Host", host),
			"v2ray-http-upgrade", true,
		)))
	case "grpc":
		out = proxy.Merge(out, model.New("network", "grpc", "grpc-opts", model.New(
			"grpc-service-name", q.Get("serviceName"),
		)))
	case "h2", "http":
		out = proxy.Merge(out, model.New("network", "h2", "h2-opts", model.New(
			"host", list(host),
			"path", path,
		)))
	case "xhttp", "splithttp":
		if out.String("type") != "vless" {
			return nil, "XHTTP on " + out.String("type")
		}
		if q.Get("extra") != "" {
			return nil, "XHTTP extra settings"
		}
		out = proxy.Merge(out, model.New("network", "xhttp", "xhttp-opts", model.New(
			"path", path,
			"host", host,
			"mode", q.Get("mode"),
		)))
	default:
		return nil, "transport " + kind
	}
	return out, ""
}

// finish adds the options any link may carry and checks the result.
func finish(out model.Object, q url.Values) (model.Object, string) {
	if q.Get("udp") == "1" {
		out.Set("udp", true)
	}
	// Naive's Cronet opens its own connections; fast open is not its option.
	if (q.Get("tfo") == "1" || q.Get("fastopen") == "1") && out.String("type") != "naive" {
		out.Set("tfo", true)
	}
	if port, _ := out.Get("port"); model.AsInt(port) == 0 {
		if _, ranged := out.Get("port-range"); !ranged {
			return nil, "no port"
		}
	}
	return out, ""
}

// vmess reads v2rayN's Base64 JSON.
func vmess(line string) (model.Object, string) {
	data, err := decodeBase64(strings.TrimPrefix(line, line[:len("vmess://")]))
	if err != nil {
		return nil, "not v2rayN's Base64 JSON"
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		return nil, "not v2rayN's Base64 JSON"
	}
	text := func(key string) string {
		switch value := v[key].(type) {
		case string:
			return value
		case float64:
			return strconv.Itoa(int(value))
		}
		return ""
	}
	out := proxy.Merge(proxy.Base(or(text("ps"), text("add")), text("add"), atoi(text("port"))), model.New(
		"type", "vmess",
		"uuid", text("id"),
		"alterId", atoi(text("aid")),
		"cipher", or(text("scy"), "auto"),
		"udp", true,
	))
	q := url.Values{}
	q.Set("type", or(text("net"), "tcp"))
	q.Set("headerType", text("type"))
	q.Set("host", text("host"))
	q.Set("path", text("path"))
	q.Set("serviceName", text("path"))
	q.Set("security", text("tls"))
	q.Set("sni", text("sni"))
	q.Set("alpn", text("alpn"))
	q.Set("fp", text("fp"))
	q.Set("allowInsecure", text("allowInsecure"))
	if text("tls") != "" && text("tls") != "none" {
		out.Set("tls", true)
	}
	out, reason := stream(out, q, "servername", "")
	if out == nil {
		return nil, reason
	}
	return finish(out, url.Values{})
}

// shadowsocks reads SIP002, with Base64 or percent-encoded userinfo, and the legacy form that
// encodes the whole "method:password@host:port".
func shadowsocks(line string) (model.Object, string) {
	rest := line[len("ss://"):]
	name := ""
	if index := strings.Index(rest, "#"); index >= 0 {
		name, _ = url.PathUnescape(rest[index+1:])
		rest = rest[:index]
	}
	if !strings.Contains(rest, "@") {
		decoded, err := decodeBase64(strings.SplitN(rest, "?", 2)[0])
		if err != nil {
			return nil, "not a SIP002 link"
		}
		rest = string(decoded)
	}
	u, err := url.Parse("ss://" + rest)
	if err != nil || u.Hostname() == "" {
		return nil, "not a SIP002 link"
	}
	method, password := u.User.Username(), ""
	if pass, set := u.User.Password(); set {
		password = pass
	} else if decoded, err := decodeBase64(method); err == nil {
		method, password, _ = strings.Cut(string(decoded), ":")
	}
	port, _ := strconv.Atoi(u.Port())
	out := proxy.Merge(proxy.Base(or(name, u.Hostname()), u.Hostname(), port), model.New(
		"type", "ss",
		"cipher", method,
		"password", password,
		"udp", true,
	))
	q := query(u)
	if plugin := q.Get("plugin"); plugin != "" {
		kind, options, _ := strings.Cut(plugin, ";")
		fields, reason := proxy.ShadowsocksPlugin(kind, proxy.PluginOptions(options))
		if reason != "" {
			return nil, reason
		}
		out = proxy.Merge(out, fields)
	}
	return finish(out, q)
}

// shadowsocksR reads ssr://base64url(host:port:protocol:method:obfs:base64(password)/?params).
func shadowsocksR(line string) (model.Object, string) {
	decoded, err := decodeBase64(line[len("ssr://"):])
	if err != nil {
		return nil, "not an SSR link"
	}
	main, params, _ := strings.Cut(string(decoded), "/?")
	parts := strings.Split(main, ":")
	if len(parts) < 6 {
		return nil, "not an SSR link"
	}
	// The host may be IPv6 and contain colons: the last five fields are fixed.
	n := len(parts)
	host := strings.Join(parts[:n-5], ":")
	password, _ := decodeBase64(parts[n-1])
	q, _ := url.ParseQuery(params)
	text := func(key string) string {
		value, _ := decodeBase64(q.Get(key))
		return string(value)
	}
	out := proxy.Merge(proxy.Base(or(text("remarks"), host), host, atoi(parts[n-5])), model.New(
		"type", "ssr",
		"cipher", parts[n-3],
		"password", string(password),
		"protocol", parts[n-4],
		"protocol-param", text("protoparam"),
		"obfs", parts[n-2],
		"obfs-param", text("obfsparam"),
		"udp", true,
	))
	return finish(out, url.Values{})
}

// snell reads the form Shadowrocket imports, which the OpenWeir panel writes:
// snell://base64(method:psk)@host:port?[plugin=obfs-local;obfs=…&]version=…[&mode=…].
func snell(line string) (model.Object, string) {
	u, err := url.Parse(line)
	if err != nil || u.Hostname() == "" {
		return nil, "not a Snell link"
	}
	psk := u.User.Username()
	if decoded, err := decodeBase64(psk); err == nil {
		_, key, found := strings.Cut(string(decoded), ":")
		if found {
			psk = key
		}
	}
	q := query(u)
	port, _ := strconv.Atoi(u.Port())
	version := atoi(or(q.Get("version"), "4"))
	out := proxy.Merge(proxy.Base(or(fragment(u), u.Hostname()), u.Hostname(), port), model.New(
		"type", "snell",
		"psk", psk,
		"userkey", q.Get("userkey"),
		"version", version,
		"udp", version >= 3,
	))
	if mode := q.Get("mode"); version == 6 && mode != "" && mode != "default" {
		out.Set("mode", mode)
	}
	obfs := q.Get("obfs")
	if plugin := q.Get("plugin"); plugin != "" {
		_, options, _ := strings.Cut(plugin, ";")
		obfs = or(proxy.PluginOptions(options)["obfs"], obfs)
	}
	if obfs != "" {
		if version >= 6 {
			return nil, "Snell v6 has no obfs"
		}
		out = proxy.Merge(out, model.New("obfs-opts", model.New("mode", obfs, "host", q.Get("obfs-host"))))
	}
	return finish(out, q)
}

// query parses a link's query on "&" alone. url.Query drops pairs with a ";", which SIP003
// plugin options ("plugin=obfs-local;obfs=http") are full of.
func query(u *url.URL) url.Values {
	values := url.Values{}
	for pair := range strings.SplitSeq(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key, errKey := url.QueryUnescape(key)
		value, errValue := url.QueryUnescape(value)
		if errKey == nil && errValue == nil {
			values.Add(key, value)
		}
	}
	return values
}

func decodeBase64(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	text = strings.NewReplacer("\r", "", "\n", "", " ", "").Replace(text)
	text = strings.TrimRight(text, "=")
	if strings.ContainsAny(text, "-_") {
		return base64.RawURLEncoding.DecodeString(text)
	}
	return base64.RawStdEncoding.DecodeString(text)
}

func fragment(u *url.URL) string {
	if u.Fragment != "" {
		return u.Fragment
	}
	name, _ := url.PathUnescape(u.RawFragment)
	return name
}

// userinfo returns a link's whole userinfo, which some schemes use as one secret.
func userinfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	if password, set := u.User.Password(); set {
		return u.User.Username() + ":" + password
	}
	return u.User.Username()
}

// credentials reads user:password, or Base64 of it as some SOCKS links write.
func credentials(u *url.URL) (string, string) {
	if u.User == nil {
		return "", ""
	}
	if password, set := u.User.Password(); set {
		return u.User.Username(), password
	}
	if decoded, err := decodeBase64(u.User.Username()); err == nil && bytes.Contains(decoded, []byte(":")) {
		user, password, _ := strings.Cut(string(decoded), ":")
		return user, password
	}
	return u.User.Username(), ""
}

func label(line string) string {
	if index := strings.LastIndex(line, "#"); index >= 0 {
		if name, err := url.PathUnescape(line[index+1:]); err == nil && name != "" {
			return name
		}
	}
	if u, err := url.Parse(line); err == nil && u.Host != "" {
		return net.JoinHostPort(u.Hostname(), u.Port())
	}
	if len(line) > 40 {
		return line[:40] + "…"
	}
	return line
}

func flag(q url.Values, keys ...string) bool {
	for _, key := range keys {
		if value := q.Get(key); value == "1" || value == "true" {
			return true
		}
	}
	return false
}

func list(text string) []string {
	var out []string
	for part := range strings.SplitSeq(text, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func noneEmpty(value string) string {
	if value == "none" {
		return ""
	}
	return value
}

func mbps(value string) string {
	if speed := atoi(value); speed > 0 {
		return fmt.Sprintf("%d Mbps", speed)
	}
	return ""
}

func atoi(text string) int {
	value, _ := strconv.Atoi(strings.TrimSpace(text))
	return value
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
