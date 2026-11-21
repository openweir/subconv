package proxy

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/openweir/subconv/internal/model"
)

// Problem says why a proxy is left out: Code is a model.Warn* code.
type Problem struct {
	Code, Reason string
}

// Normalize checks a mihomo proxy and repairs what mihomo would refuse but means one thing:
// the spellings older Clash versions and other clients write, numbers and booleans written as
// strings, legacy fields and missing defaults. Valid fields keep their value and place. It
// returns the proxy and the options it removed, or a Problem when the proxy must be left out.
func Normalize(p model.Object) (model.Object, []string, *Problem) {
	n := &normalizer{p: p.Clone()}
	if problem := n.run(); problem != nil {
		return nil, n.removed, problem
	}
	return n.p, n.removed, nil
}

type normalizer struct {
	p       model.Object
	removed []string
}

func invalid(reason string) *Problem { return &Problem{model.WarnInvalidProxy, reason} }

// Types holds every proxy type OpenWeir mihomo builds (adapter/parser.go), with the aliases
// other clients write.
var typeAliases = map[string]string{
	"shadowsocks":  "ss",
	"shadowsocksr": "ssr",
	"socks":        "socks5",
	"socks5h":      "socks5",
	"hy2":          "hysteria2",
	"hy":           "hysteria",
	"wg":           "wireguard",
	"https":        "http",
}

var types = set("ss ssr socks5 http naive nowhere vmess vless vless-reverse snell trojan hysteria hysteria2 " +
	"wireguard tuic shadowquic gost-relay direct dns reject rematch ssh mieru anytls sudoku masque " +
	"trusttunnel openvpn tailscale zerotier easytier")

// Types without a server of their own.
var serverless = set("direct dns reject rematch vless-reverse tailscale zerotier easytier")

// What each type requires besides name, server and port.
var credentials = map[string][]string{
	"ss":          {"cipher", "password"},
	"ssr":         {"cipher", "password", "obfs", "protocol"},
	"vmess":       {"uuid", "alterId", "cipher"},
	"vless":       {"uuid"},
	"trojan":      {"password"},
	"snell":       {"psk"},
	"nowhere":     {"password"},
	"anytls":      {"password"},
	"hysteria":    {"up", "down"},
	"mieru":       {"username", "password", "transport"},
	"ssh":         {"username"},
	"wireguard":   {"private-key"},
	"masque":      {"private-key", "public-key"},
	"sudoku":      {"key"},
	"openvpn":     {"ca"},
	"zerotier":    {"network", "seed", "world"},
	"shadowquic":  {},
	"gost-relay":  {},
	"trusttunnel": {},
}

// Field types, by mihomo's key. A value of another type is converted when it means one thing.
var (
	boolKeys = set("udp tfo mptcp tls skip-cert-verify xudp packet-addr global-padding authenticated-length " +
		"reduce-rtt fast-open disable-sni udp-over-tcp udp-over-stream reuse quic morph disable-mtu-discovery " +
		"ephemeral remote-dns-resolve disable-reuse accept-routes exit-node-allow-lan-access zero-rtt")
	intKeys = set("port alterId version mtu heartbeat-interval request-timeout max-udp-relay-packet-size " +
		"max-open-streams cwnd recv-window recv-window-conn workers persistent-keepalive udp-over-tcp-version " +
		"udp-over-stream-version idle-session-check-interval idle-session-timeout min-idle-session udp-mtu " +
		"handshake-timeout setup-timeout obfs-min-packet-size obfs-max-packet-size insecure-concurrency " +
		"refresh-server-ip-interval max-datagram-frame-size up-speed down-speed keep-alive-interval")
	textKeys = set("name type server password uuid cipher username psk userkey sni servername flow encryption " +
		"packet-encoding network client-fingerprint fingerprint obfs obfs-password auth auth-str up down ports " +
		"protocol obfs-param protocol-param private-key public-key pre-shared-key ip ipv6 congestion-controller " +
		"udp-relay-mode token transport multiplexing handshake-mode traffic-pattern port-range plugin mode pin " +
		"ip-version dialer-proxy key")
	listKeys = set("alpn allowed-ips host-key host-key-algorithms dns")
)

// mihomo matches keys without case and with "_" as "-"; canonical spells them as it writes them.
var canonical = func() map[string]string {
	out := map[string]string{}
	for _, keys := range []map[string]bool{boolKeys, intKeys, textKeys, listKeys} {
		for key := range keys {
			out[strings.ToLower(key)] = key
		}
	}
	for _, key := range strings.Fields("plugin-opts obfs-opts ws-opts h2-opts http-opts grpc-opts xhttp-opts " +
		"reality-opts ech-opts shadow-tls-opts restls-opts jls-opts smux peers amnezia-wg-option ss-opts " +
		"realm-opts certificate name-cert-verify headers interface-name routing-mark") {
		out[key] = key
	}
	return out
}()

// Other spellings of mihomo's keys.
var keyAliases = map[string]string{
	"alter-id":            "alterId",
	"aid":                 "alterId",
	"allow-insecure":      "skip-cert-verify",
	"allowinsecure":       "skip-cert-verify",
	"insecure":            "skip-cert-verify",
	"tls-skip-verify":     "skip-cert-verify",
	"obfs-pass":           "obfs-password",
	"obfs-param":          "obfs-param",
	"obfsparam":           "obfs-param",
	"protocolparam":       "protocol-param",
	"protoparam":          "protocol-param",
	"method":              "cipher",
	"encrypt-method":      "cipher",
	"server-port":         "port",
	"fast-open":           "fast-open",
	"udp-relay":           "udp",
	"publickey":           "public-key",
	"privatekey":          "private-key",
	"presharedkey":        "pre-shared-key",
	"preshared-key":       "pre-shared-key",
	"allowedips":          "allowed-ips",
	"congestion-control":  "congestion-controller",
	"heartbeat":           "heartbeat-interval",
	"hopinterval":         "hop-interval",
	"mport":               "ports",
	"server-ports":        "ports",
	"auth_str":            "auth-str",
	"authstr":             "auth-str",
	"service-name":        "grpc-service-name",
	"servicename":         "grpc-service-name",
	"client_fingerprint":  "client-fingerprint",
	"clientfingerprint":   "client-fingerprint",
	"dialerproxy":         "dialer-proxy",
	"udp-over-tcp-enable": "udp-over-tcp",
}

func (n *normalizer) remove(key, why string) {
	if _, set := n.p.Get(key); set {
		n.p.Delete(key)
		n.removed = append(n.removed, key+" "+why)
	}
}

func (n *normalizer) run() *Problem {
	if problem := n.keys(); problem != nil {
		return problem
	}
	kind := n.p.String("type")
	if problem := n.values(kind); problem != nil {
		return problem
	}
	n.legacy(kind)
	n.local(kind)
	if problem := n.typed(kind); problem != nil {
		return problem
	}
	return n.required(kind)
}

// keys canonicalizes key spellings and the type.
func (n *normalizer) keys() *Problem {
	for _, field := range append(model.Object(nil), n.p...) {
		folded := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(field.Key)), "_", "-")
		target := canonical[folded]
		if alias, ok := keyAliases[folded]; ok {
			target = alias
		}
		if target == "" || target == field.Key {
			continue
		}
		if _, taken := n.p.Get(target); taken {
			n.p.Delete(field.Key) // the canonical spelling wins
			continue
		}
		n.p.Rename(field.Key, target)
	}
	text, _ := model.Text(n.p.Value("type"))
	kind := strings.ToLower(strings.TrimSpace(text))
	if kind == "" {
		return invalid("no type")
	}
	if kind == "https" {
		n.p.Set("tls", true)
	}
	if alias, ok := typeAliases[kind]; ok {
		kind = alias
	}
	if !types[kind] {
		return &Problem{model.WarnUnsupportedProxy, "type " + kind}
	}
	n.p.Set("type", kind)
	return nil
}

// values converts each known key to the type mihomo decodes it into.
func (n *normalizer) values(kind string) *Problem {
	for index := 0; index < len(n.p); index++ {
		key, value := n.p[index].Key, n.p[index].Value
		switch {
		case key == "hop-interval":
			// Seconds; Hysteria 2 also takes a range of them as a string.
			if seconds, ok := duration(value); ok {
				n.p[index].Value = seconds
			} else if text, ok := value.(string); !ok || kind != "hysteria2" || text == "" {
				n.remove(key, "is not a number of seconds")
				index--
			}
		case boolKeys[key]:
			if b, ok := model.Bool(value); ok {
				n.p[index].Value = b
			} else {
				n.remove(key, "is not a boolean")
				index--
			}
		case key == "heartbeat-interval":
			// Milliseconds; sing-box-style durations are converted.
			if i, ok := model.Int(value); ok {
				n.p[index].Value = i
			} else if d, err := time.ParseDuration(text(value)); err == nil && d > 0 {
				n.p[index].Value = int(d / time.Millisecond)
			} else {
				n.remove(key, "is not a number")
				index--
			}
		case intKeys[key]:
			if i, ok := model.Int(value); ok {
				n.p[index].Value = i
			} else if seconds, ok := duration(value); ok && key != "port" {
				n.p[index].Value = seconds
			} else if key == "port" {
				return invalid("port " + describe(value))
			} else {
				n.remove(key, "is not a number")
				index--
			}
		case textKeys[key]:
			if text, ok := model.Text(value); ok {
				n.p[index].Value = text
			} else if key == "name" {
				n.p[index].Value = "" // named later, among the others
			} else if value == nil {
				n.p.Delete(key)
				index--
			} else if key == "server" {
				return invalid("server " + describe(value))
			} else {
				n.remove(key, "is not text")
				index--
			}
		case listKeys[key]:
			n.p[index].Value = strings_(value)
		}
	}
	return nil
}

// local removes the options a subscription must not set: the client's own interface and
// routing mark, and files on the client's disk.
func (n *normalizer) local(kind string) {
	for _, key := range []string{"interface-name", "routing-mark"} {
		n.remove(key, "is the client's setting")
	}
	keyed := kind == "wireguard" || kind == "masque"
	n.p = stripFiles(n.p, func(key string) {
		n.removed = append(n.removed, key+" is a local file")
	}, keyed, 0)
	if kind == "tailscale" {
		n.remove("state-dir", "is the client's setting")
	}
}

func stripFiles(o model.Object, removed func(string), keyed bool, depth int) model.Object {
	out := o[:0:0]
	for _, field := range o {
		key := field.Key
		text, isText := field.Value.(string)
		switch {
		case strings.HasSuffix(key, "-path") || strings.HasSuffix(key, "-file") || key == "path-in-bundle":
			removed(key)
			continue
		case (key == "certificate" || key == "private-key" || key == "ca") && isText && text != "" &&
			!strings.Contains(text, "-----BEGIN") && !(depth == 0 && keyed && key == "private-key"):
			removed(key)
			continue
		}
		if nested, ok := field.Value.(model.Object); ok && depth < 8 {
			field.Value = stripFiles(nested, removed, false, depth+1)
		}
		out = append(out, field)
	}
	return out
}

// legacy rewrites the fields older Clash versions and other clients write into mihomo's.
func (n *normalizer) legacy(kind string) {
	p := &n.p
	// The server may carry the port, or brackets around IPv6.
	if server := strings.TrimSpace(p.String("server")); server != "" {
		if host, port, ok := splitHostPort(server); ok {
			server = host
			if _, set := p.Get("port"); !set {
				p.InsertAfter("server", "port", port)
			}
		}
		p.Set("server", strings.TrimSuffix(strings.TrimPrefix(server, "["), "]"))
	}
	// Clash wrote ws-path and ws-headers (and VLESS ws-headers) before ws-opts.
	if path, headers := p.Value("ws-path"), p.Value("ws-headers"); path != nil || headers != nil {
		if _, set := p.Get("ws-opts"); !set && (kind == "vmess" || kind == "vless" || kind == "trojan") {
			opts := model.New("path", text(path), "headers", model.AsObject(headers))
			p.Set("ws-opts", opts)
			if _, set := p.Get("network"); !set {
				p.Set("network", "ws")
			}
		}
		p.Delete("ws-path")
		p.Delete("ws-headers")
	}
	if network := strings.ToLower(p.String("network")); network != "" {
		p.Set("network", network)
	}
	// Some clients put the uTLS fingerprint where mihomo expects a certificate's.
	if fingerprint := strings.ToLower(p.String("fingerprint")); utls[fingerprint] {
		if _, set := p.Get("client-fingerprint"); !set {
			p.Rename("fingerprint", "client-fingerprint")
			p.Set("client-fingerprint", fingerprint)
		} else {
			p.Delete("fingerprint")
		}
	}
	if fingerprint := p.String("client-fingerprint"); fingerprint != "" {
		p.Set("client-fingerprint", strings.ToLower(fingerprint))
	}
	// VMess and VLESS name the TLS server "servername", the others "sni".
	switch kind {
	case "vmess", "vless":
		if _, set := p.Get("servername"); !set {
			p.Rename("sni", "servername")
		}
		p.Delete("sni")
	default:
		if _, set := p.Get("sni"); !set {
			p.Rename("servername", "sni")
		}
		p.Delete("servername")
	}
	if alpn := strings_(p.Value("alpn")); alpn != nil {
		p.Set("alpn", alpn)
	}
	if reality := model.AsObject(p.Value("reality-opts")); reality != nil {
		reality = renameKeys(reality, map[string]string{"publickey": "public-key", "public-key": "public-key", "pbk": "public-key", "shortid": "short-id", "short-id": "short-id", "sid": "short-id"})
		if id, ok := model.Text(reality.Value("short-id")); ok {
			reality.Set("short-id", id)
		}
		p.Set("reality-opts", reality)
		if _, set := p.Get("client-fingerprint"); !set {
			p.Set("client-fingerprint", "chrome") // REALITY needs a uTLS fingerprint
		}
	}
	n.transport()
}

// transport repairs the V2Ray transport options.
func (n *normalizer) transport() {
	p := &n.p
	if ws := model.AsObject(p.Value("ws-opts")); ws != nil {
		ws = ws.Clone()
		if headers := model.AsObject(ws.Value("headers")); headers != nil {
			ws.Set("headers", singleHeaders(headers))
		}
		for _, key := range []string{"max-early-data"} {
			if value, set := ws.Get(key); set {
				if i, ok := model.Int(value); ok {
					ws.Set(key, i)
				} else {
					ws.Delete(key)
				}
			}
		}
		for _, key := range []string{"v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"} {
			if value, set := ws.Get(key); set {
				b, _ := model.Bool(value)
				ws.Set(key, b)
			}
		}
		p.Set("ws-opts", ws)
	}
	if h2 := model.AsObject(p.Value("h2-opts")); h2 != nil {
		h2 = h2.Clone()
		if host := strings_(h2.Value("host")); host != nil {
			h2.Set("host", host)
		}
		p.Set("h2-opts", h2)
	}
	if http := model.AsObject(p.Value("http-opts")); http != nil {
		http = http.Clone()
		if path := strings_(http.Value("path")); path != nil {
			http.Set("path", path)
		}
		if headers := model.AsObject(http.Value("headers")); headers != nil {
			lists := make(model.Object, 0, len(headers))
			for _, field := range headers {
				lists = append(lists, model.Field{Key: field.Key, Value: strings_(field.Value)})
			}
			http.Set("headers", lists)
		}
		p.Set("http-opts", http)
	}
	if grpc := model.AsObject(p.Value("grpc-opts")); grpc != nil {
		p.Set("grpc-opts", renameKeys(grpc, map[string]string{"servicename": "grpc-service-name", "service-name": "grpc-service-name", "grpc-service-name": "grpc-service-name"}))
	}
}

// typed repairs what is particular to a type.
func (n *normalizer) typed(kind string) *Problem {
	p := &n.p
	switch kind {
	case "ss":
		if cipher := strings.ToLower(p.String("cipher")); cipher != "" {
			p.Set("cipher", ssCipher(cipher))
		}
		// ClashX and Surge-era configs set obfs on the proxy itself.
		if mode := p.String("obfs"); mode != "" {
			if _, set := p.Get("plugin"); !set {
				p.Set("plugin", "obfs")
				p.Set("plugin-opts", model.New("mode", mode, "host", p.String("obfs-host")))
			}
			p.Delete("obfs")
			p.Delete("obfs-host")
		}
		if plugin := strings.ToLower(p.String("plugin")); plugin != "" {
			return n.shadowsocksPlugin(plugin)
		}
		p.Delete("plugin-opts")
	case "ssr":
		if _, set := p.Get("obfs"); !set {
			p.Set("obfs", "plain")
		}
		if _, set := p.Get("protocol"); !set {
			p.Set("protocol", "origin")
		}
		if cipher := strings.ToLower(p.String("cipher")); cipher != "" {
			p.Set("cipher", ssCipher(cipher))
		}
	case "vmess":
		if _, set := p.Get("alterId"); !set {
			p.InsertAfter("uuid", "alterId", 0)
		}
		if cipher := strings.ToLower(p.String("cipher")); cipher == "" {
			p.InsertAfter("alterId", "cipher", "auto")
		} else {
			p.Set("cipher", cipher)
		}
	case "vless":
		if flow := p.String("flow"); flow == "none" {
			p.Delete("flow")
		}
	case "snell":
		if mode := p.String("obfs"); mode != "" {
			if _, set := p.Get("obfs-opts"); !set {
				p.Set("obfs-opts", model.New("mode", mode, "host", p.String("obfs-host")))
			}
			p.Delete("obfs")
			p.Delete("obfs-host")
		}
	case "hysteria", "hysteria2":
		if ports := p.String("ports"); ports != "" {
			p.Set("ports", PortRanges(strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '/' })))
		}
		if p.String("ports") == "" {
			p.Delete("ports")
		}
		if kind == "hysteria" {
			for _, key := range []string{"up", "down"} {
				if speed := p.String(key); speed == "" {
					if speeds, ok := model.Int(p.Value(key + "-speed")); ok && speeds > 0 {
						p.Set(key, strconv.Itoa(speeds)+" Mbps")
					}
				}
			}
		}
	case "mieru":
		if transport := strings.ToUpper(p.String("transport")); transport == "" {
			p.Set("transport", "TCP")
		} else {
			p.Set("transport", transport)
		}
	case "naive":
		// Cronet verifies certificates and picks the TLS fingerprint and ALPN itself.
		if b, _ := model.Bool(p.Value("skip-cert-verify")); b {
			return &Problem{model.WarnUnsupportedOption, "Naive cannot skip certificate verification"}
		}
		p.Delete("skip-cert-verify")
		for _, key := range []string{"client-fingerprint", "fingerprint", "alpn", "name-cert-verify"} {
			n.remove(key, "is Cronet's own")
		}
		if udp, _ := model.Bool(p.Value("udp")); udp {
			if over, _ := model.Bool(p.Value("udp-over-tcp")); !over {
				n.remove("udp", "needs udp-over-tcp")
			}
		}
	case "wireguard":
		return n.wireguard()
	case "tuic":
		if p.String("token") == "" && p.String("uuid") == "" {
			return invalid("no token or UUID")
		}
	}
	if version := p.String("ip-version"); version != "" {
		switch strings.ToLower(version) {
		case "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer":
			p.Set("ip-version", strings.ToLower(version))
		default:
			n.remove("ip-version", "is not one mihomo knows")
		}
	}
	return nil
}

func (n *normalizer) shadowsocksPlugin(plugin string) *Problem {
	p := &n.p
	var options model.Object
	switch opts := p.Value("plugin-opts").(type) {
	case model.Object:
		options = opts.Clone()
	case string:
		for key, value := range PluginOptions(opts) {
			options = append(options, model.Field{Key: key, Value: value})
		}
		sortFields(options)
	}
	switch plugin {
	case "obfs-local", "simple-obfs", "obfs":
		plugin = "obfs"
		options.Rename("obfs", "mode")
		options.Rename("obfs-host", "host")
	case "v2ray-plugin", "gost-plugin":
		if mode := options.String("mode"); mode == "" {
			options = append(model.Object{{Key: "mode", Value: "websocket"}}, withoutKey(options, "mode")...)
		} else if mode != "websocket" {
			return &Problem{model.WarnUnsupportedOption, plugin + " mode " + mode}
		}
		for _, key := range []string{"tls", "mux", "skip-cert-verify"} {
			if value, set := options.Get(key); set {
				b, ok := model.Bool(value)
				if !ok && value == "" {
					b = true // a flag without a value, as SIP003 writes it
				}
				options.Set(key, b)
			}
		}
	case "shadow-tls", "restls", "jls", "kcptun":
		if version, set := options.Get("version"); set {
			if v, ok := model.Int(version); ok {
				options.Set("version", v)
			}
		}
	default:
		return &Problem{model.WarnUnsupportedOption, "plugin " + plugin}
	}
	p.Set("plugin", plugin)
	p.Set("plugin-opts", options)
	return nil
}

func (n *normalizer) wireguard() *Problem {
	p := &n.p
	peers := model.AsList(p.Value("peers"))
	var kept []any
	for _, item := range peers {
		peer := model.AsObject(item)
		if peer == nil {
			continue
		}
		peer = peer.Clone()
		if server := strings.TrimSpace(peer.String("server")); server != "" {
			if host, port, ok := splitHostPort(server); ok {
				peer.Set("server", host)
				if _, set := peer.Get("port"); !set {
					peer.InsertAfter("server", "port", port)
				}
			}
		}
		if port, ok := model.Int(peer.Value("port")); ok {
			peer.Set("port", port)
		}
		if ips := strings_(peer.Value("allowed-ips")); ips != nil {
			peer.Set("allowed-ips", ips)
		} else {
			peer.Set("allowed-ips", []string{"0.0.0.0/0", "::/0"})
		}
		if reserved := reservedBytes(peer.Value("reserved")); reserved != nil {
			peer.Set("reserved", reserved)
		}
		if peer.String("server") == "" || peer.String("public-key") == "" {
			continue
		}
		kept = append(kept, peer)
	}
	if peers != nil {
		if len(kept) == 0 {
			return invalid("no usable WireGuard peer")
		}
		p.Set("peers", kept)
		// The proxy's own address is the first peer's, which clients show.
		first := model.AsObject(kept[0])
		if p.String("server") == "" {
			p.InsertAfter("type", "server", first.String("server"))
			p.InsertAfter("server", "port", first.Value("port"))
		}
	} else {
		if p.String("public-key") == "" {
			return invalid("no public key")
		}
		if ips := strings_(p.Value("allowed-ips")); ips != nil {
			p.Set("allowed-ips", ips)
		}
	}
	if reserved := reservedBytes(p.Value("reserved")); reserved != nil {
		p.Set("reserved", reserved)
	}
	for _, key := range []string{"ip", "ipv6"} {
		if address := p.String(key); strings.Contains(address, "/") {
			p.Set(key, address[:strings.Index(address, "/")])
		}
	}
	return nil
}

// required checks the fields mihomo cannot do without.
func (n *normalizer) required(kind string) *Problem {
	p := n.p
	if !serverless[kind] {
		server := p.String("server")
		if server == "" {
			return invalid("no server")
		}
		if strings.ContainsAny(server, " \t/\\@?#") {
			return invalid("server " + server)
		}
		port, _ := model.Int(p.Value("port"))
		ranged := p.String("ports") != "" || p.String("port-range") != ""
		switch {
		case port == 0 && ranged && (kind == "hysteria" || kind == "hysteria2" || kind == "mieru"):
			p.Delete("port")
		case port < 1 || port > 65535:
			if _, set := p.Get("port"); !set {
				return invalid("no port")
			}
			return invalid("port " + strconv.Itoa(port))
		}
	}
	for _, key := range credentials[kind] {
		value, set := p.Get(key)
		text, isText := value.(string)
		switch {
		case !set:
			if key == "password" && kind == "ss" && isPlain(p.String("cipher")) {
				n.p.Set("password", "")
				continue
			}
			return invalid("no " + key)
		case isText && text == "" && !(key == "password" && kind == "ss" && isPlain(p.String("cipher"))):
			return invalid("no " + key)
		}
	}
	return nil
}

var utls = set("chrome firefox safari ios android edge 360 qq random randomized chrome_psk chrome_pq chrome_psk_shuffle chrome_padding_psk_shuffle chrome_pq_psk chrome_120")

func isPlain(cipher string) bool {
	return cipher == "none" || cipher == "plain" || cipher == "dummy"
}

// ssCipher maps other names of Shadowsocks ciphers to mihomo's.
func ssCipher(cipher string) string {
	cipher = strings.ReplaceAll(cipher, "_", "-")
	cipher = strings.TrimPrefix(cipher, "aead-")
	switch cipher {
	case "chacha20-poly1305":
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305":
		return "xchacha20-ietf-poly1305"
	case "table":
		return "none"
	}
	return cipher
}

// reservedBytes reads WireGuard's reserved bytes from a list, "1,2,3" or Base64.
func reservedBytes(value any) any {
	switch v := value.(type) {
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			if i, ok := model.Int(item); ok {
				out = append(out, i)
			}
		}
		return out
	case string:
		if strings.Contains(v, ",") {
			out := []any{}
			for _, part := range strings.Split(v, ",") {
				if i, ok := model.Int(part); ok {
					out = append(out, i)
				}
			}
			return out
		}
		return v // Base64, which mihomo decodes itself
	}
	return nil
}

func splitHostPort(server string) (string, int, bool) {
	if _, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		return "", 0, false
	}
	index := strings.LastIndex(server, ":")
	if index <= 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(server[index+1:])
	if err != nil {
		return "", 0, false
	}
	return strings.Trim(server[:index], "[]"), port, true
}

// duration reads seconds written as a number or a Go duration ("30s", "5m").
func duration(value any) (int, bool) {
	if i, ok := model.Int(value); ok {
		return i, true
	}
	text, _ := value.(string)
	if d, err := time.ParseDuration(strings.TrimSpace(text)); err == nil && d >= 0 {
		return int(d / time.Second), true
	}
	return 0, false
}

func describe(value any) string {
	if text, ok := model.Text(value); ok {
		return strconv.Quote(text)
	}
	if value == nil {
		return "missing"
	}
	return "is not a scalar"
}

func text(value any) string {
	s, _ := model.Text(value)
	return s
}

// strings_ reads a list of strings, or a comma-separated string, or nil.
func strings_(value any) []string {
	switch v := value.(type) {
	case string:
		var out []string
		for part := range strings.SplitSeq(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := model.Text(item); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// singleHeaders turns header lists, as sing-box and Xray write them, into the single values
// mihomo's ws-opts take.
func singleHeaders(headers model.Object) model.Object {
	out := make(model.Object, 0, len(headers))
	for _, field := range headers {
		switch v := field.Value.(type) {
		case []any:
			if len(v) > 0 {
				s, _ := model.Text(v[0])
				out = append(out, model.Field{Key: field.Key, Value: s})
			}
		default:
			if s, ok := model.Text(v); ok {
				out = append(out, model.Field{Key: field.Key, Value: s})
			}
		}
	}
	return out
}

// renameKeys gives keys that fold (case, "_" as "-") to one of names its canonical spelling; the
// first field of a name wins.
func renameKeys(o model.Object, names map[string]string) model.Object {
	out := make(model.Object, 0, len(o))
	for _, field := range o {
		if name, ok := names[strings.ReplaceAll(strings.ToLower(field.Key), "_", "-")]; ok {
			if _, taken := out.Get(name); taken {
				continue
			}
			field.Key = name
		}
		out = append(out, field)
	}
	return out
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

func sortFields(o model.Object) {
	for i := 1; i < len(o); i++ {
		for j := i; j > 0 && o[j].Key < o[j-1].Key; j-- {
			o[j], o[j-1] = o[j-1], o[j]
		}
	}
}

func set(words string) map[string]bool {
	out := map[string]bool{}
	for _, word := range strings.Fields(words) {
		out[word] = true
	}
	return out
}
