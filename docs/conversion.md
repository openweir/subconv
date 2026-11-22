# Conversion

What subconv reads, what it makes of it, and what it leaves out. The ground truth for what can
be represented is the OpenWeir mihomo build ([openweir/mihomo](https://github.com/openweir/mihomo)):
`adapter/outbound/*.go` for proxies, `adapter/outboundgroup` for groups, `rules/` and
`config/config.go` for rules and providers.

## Formats

`Detect` names a body's format; `Convert` converts any of them. `Result.Format` carries the same
name.

| Constant | Name | Detected by | OpenWrt plugin id |
| --- | --- | --- | --- |
| `FormatClash` | `clash` | YAML or JSON with `proxies` or `proxy-providers` (also `Proxy`, Clash's early name) | `clash`, `openweir` |
| `FormatStash` | `stash` | Clash with `benchmark-url` health checks, `script` or `http.rewrite` | `stash` |
| `FormatSingBox` | `sing-box` | JSON (comments allowed) with `outbounds` or `endpoints` | `sing-box` |
| `FormatXray` | `xray` | JSON whose outbounds have `protocol` and no `type` | `xray` |
| `FormatLinks` | `links` | a line that starts with `scheme://` | `uri` |
| `FormatSurge` | `surge` | `[Proxy]`, `[Proxy Group]`, `[Rule]` or `[General]` sections | `surge` |
| `FormatSurfboard` | `surfboard` | a Surge config with `[Panel]` or a Surfboard comment | `surfboard` |
| `FormatLoon` | `loon` | Loon's own sections (`[Remote Rule]`, `[Proxy Chain]`, `[Plugin]`…) | `loon` |
| `FormatShadowrocket` | `shadowrocket` | a Surge config with a Shadowrocket comment or `bypass-system` | `shadowrocket` |
| `FormatQuantumultX` | `quantumultx` | `[server_local]`, `[policy]`, `[filter_local]`… or `shadowsocks=host:port` lines | `quantumultx` |
| `FormatSIP008` | `sip008` | JSON `{"servers": […]}`, a shadowsocks-windows `{"configs": […]}` or a bare list of servers | `sip008` |
| `FormatSSD` | `ssd` | `ssd://` | `ssd` |

The OpenWeir panel serves Clash YAML; it is `clash`.

### What a body may be wrapped in

A byte-order mark, UTF-16, CRLF line ends, Base64 of any of the formats (standard or URL-safe,
padded or not, wrapped in lines, or padded chunks one after another), JSON with `//` and `/* */`
comments and trailing commas, link lists with blank lines, comments and lines that are not
links. A Clash config whose YAML does not parse is read again with tab indentation taken as
spaces, then one section at a time and one list item at a time; a broken item is left out with a
warning. YAML anchors and aliases are expanded, and merge keys (`<<: *a`, `<<: [*a, *b]`);
YAML whose aliases loop, or add more values than a hundred times those it writes (at least
10,000 and at most a million are allowed), does not parse.

What is not a subscription fails, and every such error is also `ErrUnknownFormat`:

| Error | Body |
| --- | --- |
| `ErrEmpty` | nothing but whitespace |
| `ErrWebPage` | an HTML or XML page: an error page, a login, a challenge |
| `ErrMessage` | a short text or JSON message such as `{"msg":"token expired"}`; the error carries it |
| `ErrUnknownFormat` | anything else |

## Normalization

Every format's result goes through one pass, so that each client gets a config OpenWeir mihomo
loads. Valid items come back exactly as written, in their order: no defaults added, keys
renamed or values retyped (`TestValidClashUnchanged`). Only what mihomo refuses or misreads is
repaired; what cannot be repaired is left out with a warning, and the rest converts.

**Proxies**

- Types in any case and other clients' names (`shadowsocks`, `socks`, `hy2`, `wg`, `https`);
  key spellings mihomo matches loosely (`skip_cert_verify`, `Alterid`) and other clients' keys
  (`allowInsecure`, `method`, `obfs-pass`, `mport`, `service-name`…).
- Booleans written as strings (`"true"`, `"yes"`), which mihomo's decoder refuses; durations
  (`"30s"`) where mihomo takes seconds or milliseconds. Numbers written as strings stay, as
  mihomo reads them.
- Legacy fields: `ws-path` and `ws-headers` as `ws-opts`, Shadowsocks `obfs`/`obfs-host` as the
  obfs plugin, SIP003 plugin option strings, `sni` and `servername` per protocol, a uTLS name in
  `fingerprint` (mihomo's certificate pin) moved to `client-fingerprint`, string lists split,
  header lists reduced to the single values `ws-opts` take, a server written `host:port` or in
  brackets.
- Defaults mihomo requires: VMess `alterId` and `cipher`, ShadowsocksR `obfs` and `protocol`,
  Mieru `transport`, a Shadowsocks password for `none`, Hysteria `up`/`down` from Stash's
  `up-speed`/`down-speed`, REALITY's uTLS fingerprint.
- Removed with `ignored_option`: `interface-name` and `routing-mark` (the client's), local files
  (`*-path`, `*-file`, certificates and keys that are paths rather than PEM, ZeroTier's `planet`),
  Tailscale's and ZeroTier's `state-dir`, Naive options Cronet refuses (fingerprints, ALPN, a
  client `private-key`, a `certificate` that is not PEM CA certificates), Naive QUIC options
  without `quic` and `udp-over-tcp-version` without `udp-over-tcp`, and Naive `headers` the
  transport writes itself (`Host`, `Padding`, `Proxy-Authorization`…) or that are not HTTP
  headers. VLESS `encryption: auto`, VMess's word, is VLESS's none and goes too; REALITY without
  a `public-key` is plain TLS to mihomo, so its `reality-opts` go as well.
- What mihomo's constructors refuse at load, which would take the whole config down
  (`TestVectorsLoadInMihomo` checks every vector with a mihomo binary): REALITY public keys (32
  bytes of URL-safe Base64; other spellings of the same key are rewritten) and short IDs,
  REALITY implying TLS, and AnyTLS REALITY options without a key; Shadowsocks methods, 2022 key
  lengths, obfs modes and UDP-over-TCP versions; ShadowsocksR stream ciphers, obfs and
  protocols; VMess ciphers; VLESS's legacy XTLS flows and `encryption` (none or
  `mlkem768x25519plus` with its keys and padding); Trojan transports (TCP, `ws`, `grpc`); Snell
  versions and their options; Hysteria bandwidths (a bare number is Mbps; one mihomo reads as
  zero is refused), `auth` and protocols; Hysteria 2 obfs (salamander, and gecko with its packet
  sizes); ZeroTier network IDs and orbits; WireGuard keys, reserved bytes and addresses;
  certificate pins; ECH configs; Nowhere, Naive and Mieru options; SSH host keys; mux protocols.
  Values are checked the way mihomo's decoder reads them, so a number where it takes text (a
  Hysteria `up: 100`, a TUIC `token`, an `obfs-password`) counts as that text. An optional value
  is removed (`ignored_option`), anything else leaves the proxy out.
- Left out: a missing or invalid server or port (`invalid_proxy`), missing credentials
  (`invalid_credential`; also a Snell `password` without a `psk`), a type mihomo lacks
  (`unsupported_proxy`).
- Names: an empty name becomes `type server`; a duplicate or reserved name (`DIRECT`, `GLOBAL`…)
  gets a number (`renamed`).

**Proxy providers**: `http` with a web URL (its cache `path` removed, as the client chooses
it), `inline` (each proxy normalized), and `file`, kept with `local_provider` for the client to
decide. Intervals, `header`, `health-check`, `override` (without the client's settings) and
filters are checked; a provider named like a group, or `default`, is renamed.

**Regular expressions** (group and provider filters, `DOMAIN-REGEX`, `PROCESS-NAME-REGEX`,
`PROCESS-PATH-REGEX`) are checked as mihomo compiles them, with regexp2 (the version mihomo
uses, its default options): lookaround, `\pL` and `\x{…}` are kept, Go's own `\Q…\E` and
`(?P<name>…)` are not, nor are invalid ranges (`[z-a]`) or repeat counts (`a{3,1}`). A filter is
checked part by part, the parts separated by backquotes, and whole, as mihomo joins the filters
of a provider's groups for its health checks; a pattern that leaves the `x` or `n` option on at
its end, which would change the filters after it, is refused too. A refused filter goes with
`ignored_option` (a group filter mihomo cannot compile crashes it); a refused rule with
`unsupported_rule`.

**Groups**

- Types in any case and other names (`urltest`, `static`, `available`, `loadbalance`); options
  checked (`interval` as seconds, `strategy`, filters, `empty-fallback`, and `expected-status`
  as mihomo parses it: `*`, or up to 28 statuses and closed ranges separated by `/` or `,`; an
  open range such as `200-` would take the whole config down, so it is removed).
  `dialer-proxy`, `routing-mark` and `interface-name` are proxies' options and are removed.
- Members and `use` that do not exist are removed (`unknown_reference`); members left out
  earlier go quietly.
- `relay` groups, which mihomo removed in favour of `dialer-proxy`, become chains: each hop
  after the first is a copy of its proxy dialing through the hop before, and the last copy takes
  the relay's name, so rules and groups that use the relay keep working. A relay through a
  provider, or whose later hops are groups, is left out (`unsupported_group`).
- Groups that contain each other in a loop lose one member (`cyclic_reference`); so does a
  dialer-proxy chain that leads back to its proxy, directly or through a group. A group leads
  wherever mihomo may dial through it: its members, with `include-all` the proxies its `filter`
  matches, less those its `exclude-filter` matches or whose type its `exclude-type` lists
  (mihomo's names, such as `Shadowsocks` and `Vmess`; members listed in `proxies` included),
  and its `empty-fallback`. So a landing proxy may dial through a group of all proxies that
  excludes it.
- A group with nothing to choose from is left out (`empty_group`), and so are references to
  it, which may empty further groups.

**Rule providers**: `http` and `inline` with a behavior and format mihomo reads; `file` is
kept with `local_provider`. A missing format is mihomo's, YAML, unless the URL ends in `.mrs`,
`.srs` or `.json`: `.txt` and `.list` sets are often YAML `payload` lists. An inline set without
rules is kept, matching nothing, and so are the rules that use it. sing-box's
`.srs`/`.json` sets are replaced by MetaCubeX's `.mrs` twin when they are a well-known geosite or
geoip set (SagerNet's sing-geosite and sing-geoip, MetaCubeX's sing branch, or the
`geosite-*`/`geoip-*` names); other `.json` sets are kept only with `Options.ConvertsRuleSets`.

**Rules**

- Other clients' names (`HOST-SUFFIX`, `IP6-CIDR`, `DEST-PORT`, `SRC-IP`, `FINAL`), types in any
  case, spaces, Surge's `REJECT-TINYGIF` and similar as `REJECT`, policies in another case
  (Quantumult X's `proxy`), a bare IP as a /32 or /128, `DOMAIN-SUFFIX,.example.com`, port
  ranges written `a:b`; options other than `no-resolve` and `src` are dropped.
- Left out (`unsupported_rule`, with the rule as written): types mihomo lacks (`USER-AGENT`,
  `URL-REGEX`, `SCRIPT`, `SUB-RULE`), `UID` (mihomo refuses it on every system but Linux and
  Android), malformed rules and logical rules, invalid IP ranges, ports, DSCP values, inbound
  types or regexps, and rules whose policy or rule set does not exist or was left out.
- The rules end with one `MATCH`: rules after it never match and go. A `MATCH` whose policy is
  gone, or a missing one, sends traffic to the first group, as Clash configs do, or `DIRECT`
  when there is none; a config with groups and no rules gets that `MATCH` too.

**Rule statistics**: `Result.RuleStats` counts the subscription's rules (`Total`), those left
out (`Dropped`), and whether its final rule (`MATCH`, Surge's `FINAL`, sing-box's `route.final`
or first outbound, Xray's first outbound) survived with its policy (`Match`). Rules count as
Clash rules: a sing-box or Xray rule that tests several values counts once per value, and a
rule left out before it became one counts once. Rules a client handles itself (sniffing, DNS
hijacking, Xray's DNS and API traffic) and rules after the final `MATCH` do not count. A client
may fall back to a routing template when there are no rules, no `Match`, or too many dropped;
`Convert` itself decides nothing, `Build` does (below).

## Build

`Build(ctx, body, Options)` converts a subscription into the config a client runs:

- `Options.Rules`: `""` (auto) uses the subscription's routing unless it has no rules, its final
  rule did not survive (`RuleStats.Match`), or more than a tenth of its rules were left out; then
  the routing template of the rules branch ([rules.md](rules.md)). `"template"` always uses the
  template, `"subscription"` never.
- With the template, the subscription's groups, rule providers and rules give way to the
  template's: every `include-all` group lists its own members, then the nodes its filters let
  through (read by regexp2, as mihomo reads them) in subscription order; proxy providers join
  it as `use`, with its filters for their nodes; groups left empty go with their references;
  `{rules}` becomes the host the client picked. `Result.Template` (`Version`, `Reason`,
  `Cached`) and a `template_applied` warning say why: `requested`, `no_rules`, `no_match` or
  `dropped_rules`.
- Without a template (`rules.ErrNoTemplate`: no host served it and the cache holds none, or it
  fails `rules.Validate`), the plain conversion comes back with `template_unavailable`.
- `Options.Client` is the caller's `rules.Client` (HTTP client, hosts, cache, `MinVersion`).
- `Options.Head` puts the OpenWeir default head (`Head`, the panel template's settings before
  its proxies) in front of the parts.

## Formats in detail

### sing-box

- **Proxies**: shadowsocks (obfs-local, v2ray-plugin, UDP over TCP), the legacy shadowsocksr,
  vmess, vless (REALITY, OpenWeir's XHTTP), trojan, hysteria2 (port hopping), hysteria, tuic,
  anytls, naive, http, socks5, wireguard (outbound and endpoint, several peers), ssh, tailscale
  endpoints and snell. Transports ws, httpupgrade, grpc and http/h2; multiplex as smux (with
  brutal); `detour` as `dialer-proxy`; `tcp_fast_open` and `tcp_multi_path`.
- **ShadowTLS**: a proxy that dials through a shadowtls outbound becomes one proxy with
  mihomo's `shadow-tls` plugin (Shadowsocks), obfs (Snell) or `shadow-tls-opts` (VMess, VLESS,
  Trojan, AnyTLS).
- **TLS**: `server_name`, `insecure`, `alpn`, uTLS, REALITY, ECH (`ech-opts`, configs from PEM or
  from DNS as sing-box does), a pinned `certificate` as mihomo's `fingerprint` (the SHA-256 of
  the server's certificate or a CA it sends), client certificates.
- **Groups**: selector as select (`default` first), urltest as url-test (sing-box's 50 ms
  tolerance), libbox's loadbalance as load-balance.
- **Rules**: sing-box matches the address fields and `rule_set` of a rule as one group (any of
  them), ports, source addresses and source ports as others, and needs every group; a rule of
  several groups becomes an `AND`. Fields: domain, domain_suffix, domain_keyword, domain_regex,
  geosite, geoip, source_geoip, ip_cidr, ip_is_private and source_ip_is_private (mihomo's built-in
  `GEOIP,lan`), source_ip_cidr, ports and port ranges, network, process names and paths,
  package_name, user_id, rule_set (`rule_set_ip_cidr_match_source` as `src`), logical rules and
  `invert`. `reject` is REJECT (REJECT-DROP with `method: drop`). Rules a client handles itself
  (sniff, hijack-dns, resolve, route-options, clash_mode) go quietly; `route.final` is `MATCH`.
- **Left out**: SOCKS4 (mihomo speaks SOCKS5), Tor, the QUIC transport (mihomo has none), Naive
  that skips certificate verification (Cronet refuses), XHTTP on anything but VLESS, TLS inside
  ShadowTLS, ShadowTLS around other protocols, local rule sets, remote `.srs` sets that are not
  well-known (sing-box's binary format), and rules on Wi-Fi, network type, inbound, user, client
  or sniffed protocol. Ignored with a warning: `certificate_public_key_sha256` (mihomo pins whole
  certificates), `disable_sni` outside TUIC, WireGuard addresses beyond one IPv4 and one IPv6.

### Clash, mihomo and Stash

All five parts, through the normalization above. Stash's `benchmark-url` and
`benchmark-timeout` become `url` and `timeout`; its `http.rewrite` is reported as left out.

### Xray and V2Ray

vmess, vless (also Xray's flat settings), trojan, shadowsocks, socks, http, wireguard and
Hysteria 2 outbounds; an outbound with several servers or users becomes one proxy each and a
select group of them under its tag. Stream settings: tcp/raw (HTTP header obfuscation), ws,
httpupgrade, grpc, h2, xhttp; TLS (pinned certificate chains as `fingerprint`, ECH) and REALITY.
`proxySettings` and `sockopt.dialerProxy` are `dialer-proxy`; freedom and blackhole are DIRECT
and REJECT. Balancers become url-test (leastPing, leastLoad), load-balance (random, roundRobin)
or fallback groups. Routing rules: `domain` (`domain:`, `full:`, `keyword:`, `regexp:`,
`geosite:`, plain), `ip` and `source` (`geoip:private` as `lan`), `port`, `sourcePort`,
`network`, `process`. Rules a client handles itself go quietly: those to a dns outbound or the
API (`api.tag`, else `api`) and those from the API's or the DNS server's inbound tag
(`dns.tag`). Left out: kcp and quic, XHTTP extra settings, `ext:` domain files, `protocol` and
`attrs` rules; Xray's mux and WireGuard peers after the first are ignored with a warning.

### Share links

vless, trojan and trojan-go (with its Shadowsocks layer), vmess (v2rayN's Base64 JSON and
Shadowrocket's form), ss (SIP002 in either encoding, the legacy form, obfs and v2ray-plugin),
ssr, hysteria2/hy2 (`mport` or ports in the authority, `pinSHA256`), hysteria, tuic, anytls
(REALITY), naive+https and naive+quic, socks/socks5 (v2rayN's Base64 credentials), http/https,
ssh, wireguard/wg, mieru and mierus, nowhere and snell. Query keys: `type`, `security`, `sni`,
`fp`, `pbk`, `sid`, `flow`, `alpn`, `allowInsecure`/`insecure`, `path`, `host`, `serviceName`,
`mode`, `headerType`, `ech`, and XHTTP `extra` settings mihomo has (padding, no gRPC header,
xmux). Names are URL-decoded. Left out: Telegram proxies, transports mihomo lacks (kcp, quic),
XHTTP download settings, unknown schemes; a malformed link is `invalid_proxy`.

### Surge, Surfboard, Loon and Shadowrocket

- **Proxies**: ss (obfs, ShadowTLS), ShadowsocksR, vmess, vless (REALITY), trojan (ws), http and
  https, socks5 and socks5-tls, snell (obfs, ShadowTLS, v6's userkey and mode), hysteria2 (port
  hopping), tuic and tuic-v5, anytls, ssh, and WireGuard from Surge's `[WireGuard name]` sections
  and Loon's single lines. Loon's positional method, password and UUID. `underlying-proxy` is
  `dialer-proxy`, `server-cert-fingerprint-sha256` is `fingerprint`. `name = direct` and
  `name = reject` are aliases of the built-in policies.
- **Groups**: select, url-test (Loon's url, Surge's smart), fallback, load-balance;
  `include-all-proxies` and `policy-regex-filter`. Loon's `[Proxy Chain]` becomes a relay.
- **Rules**: Surge's rules as above; `RULE-SET` and `DOMAIN-SET` URLs and Loon's `[Remote Rule]`
  become http providers; `RULE-SET,LAN` is `GEOIP,lan`; `PROTOCOL,TCP/UDP` is `NETWORK`.
- **Left out**: rewrites, scripts, MITM, plugins (reported per section), SSID and subnet groups,
  `policy-path` and remote proxy lists (in the client's own format), external proxies,
  `RULE-SET,SYSTEM`, and remote rule lists that name a policy per rule.

### Quantumult X

`[server_local]` lines (shadowsocks with obfs and wss, ShadowsocksR, vmess, vless with REALITY,
trojan, http, socks5) and bare node lists, `[policy]` (static, url-latency-benchmark, available,
round-robin, dest-hash; `server-tag-regex`), `[filter_local]`, and `[filter_remote]` lists with a
`force-policy` when `Options.ConvertsRuleSets` is set (their content is Quantumult X's own). The
built-in `proxy` policy, when the config uses it without defining it, becomes a select group of
all proxies. Left out: `[server_remote]`, rewrites, tasks, SSID policies.

### SIP008 and SSD

SIP008's `servers`, shadowsocks-windows's `configs` and bare server lists; `ssd://` with the
airport's defaults and each server's overrides. Plugins as for share links.

## Provider content

subconv does no I/O. A client that downloads providers itself passes their bodies through:

- **`ConvertRuleSet(body, behavior, format)`**: Clash's YAML payload (read line by line) and
  text, MRS (checked for its zstd header and passed through), Surge and Loon lists, Quantumult X
  filter lists (their policy column dropped), sing-box source JSON. `behavior` and `format` are
  what the provider declares, as hints; the result's `Behavior` and `Format` (`text`, or `mrs`)
  are what the provider must declare for `Body`. Entries that are all domains or all IP ranges
  stay a domain or ipcidr list when declared so (or undeclared); anything else becomes
  classical. In a list that never writes `+.`, a leading dot means the domain too, as in
  Surge's DOMAIN-SET; otherwise it means subdomains only, as in mihomo. Comments, blank lines,
  byte-order marks and CRLF go; invalid entries are counted in `Skipped` and summarized in
  `Warnings`. Limits: 32 MiB (`ErrRuleSetTooLarge`), 250,000 entries, 8,192 characters a line;
  `ErrNoRules` when nothing is left.
- **`ConvertProxies(body)`**: a proxy provider's content in any format `Convert` reads; only the
  proxies, each normalized. A `dialer-proxy` stays as written, as it names the config the
  provider joins.

`ConvertWith(body, Options{ConvertsRuleSets: true})` keeps rule sets whose content only
`ConvertRuleSet` reads (sing-box source JSON, Quantumult X filter lists) as http providers;
`Convert` leaves them out, as a client whose mihomo downloads providers itself could not read
them.

## Warning codes

Each warning has a stable `code` and a `detail` that starts with the item: a proxy's, group's or
provider's name, or a rule as written (`rule N to POLICY` for sing-box and Xray rules).

| Code | Meaning | Routing changes |
| --- | --- | --- |
| `unsupported_proxy` | a proxy of a type mihomo lacks; left out | no |
| `unsupported_option` | a proxy option that cannot be represented; the proxy is left out | no |
| `invalid_proxy` | a broken proxy (server, port, a value mihomo refuses, malformed link or YAML); left out | no |
| `invalid_credential` | a proxy without its credentials, or with another protocol's (Snell `password`); left out | no |
| `ignored_option` | an option removed while its item stays (client settings, local files, values mihomo refuses) | no |
| `renamed` | an empty, duplicate or reserved name given a unique one | no |
| `unsupported_provider` | a proxy provider that cannot be used (no web URL, a client's own list format) | no |
| `local_provider` | a provider that reads a file on the client's disk; kept for the client to decide | — |
| `unsupported_group` | a group of a type mihomo lacks, or a relay that cannot be chained; left out | no |
| `unknown_reference` | a member, provider or dialer-proxy that does not exist; removed | no |
| `cyclic_reference` | groups or dialer-proxy chains in a loop; one reference removed | no |
| `empty_group` | a group with no members left; left out with its references | no |
| `unsupported_rule` | a rule left out (and rewrite or script sections) | **yes** |
| `unsupported_rule_set` | a rule set mihomo cannot read or reach; its rules are left out | **yes** |
| `template_applied` | Build put the routing template in place of the subscription's routing; the detail is the reason | the template's |
| `template_unavailable` | Build needed the template but has none; the subscription's routing stays | — |

A client should flag `unsupported_rule` and `unsupported_rule_set`: traffic goes elsewhere than
the subscription meant.

## Not representable

What OpenWeir mihomo cannot express, and why, by its source:

- **SOCKS4/4a**: `adapter/outbound/socks5.go` speaks SOCKS5 only.
- **The V2Ray QUIC and mKCP transports** for VMess, VLESS and Trojan: no QUIC transport in
  `transport/`; mKCP exists for VMess only through `mekya-opts`, which no subscription format
  writes.
- **Naive that skips certificate verification**: `naive_options.go` refuses `skip-cert-verify`,
  `alpn` and fingerprints, which Chromium's TLS does not take.
- **XHTTP on VMess or Trojan**: `xhttp-opts` is VLESS's (`vless.go`).
- **Trojan over h2 or HTTP**: `trojan.go` dials `ws` and `grpc` and takes any other `network` as
  plain TLS, which a server expecting HTTP/2 or HTTP framing does not speak; such a proxy is left
  out (`unsupported_option`).
- **TLS inside ShadowTLS, and ShadowTLS around QUIC protocols**: `shadow-tls-opts` replaces the
  proxy's TLS (`transport/vmess/tls.go`).
- **WireGuard with more than one IPv4 or IPv6 address**: `ip` and `ipv6` are single values.
- **sing-box's binary rule sets**: mihomo reads yaml, text and mrs (`constant/provider`).
- **Rules on Wi-Fi, network type, user agent, URL, sniffed protocol**: no such rule in
  `rules/parser.go`.
- **Relays through providers or groups**: `dialer-proxy` names one proxy or group, and only
  proxies take one (`outboundgroup/parser.go` refuses it on groups).
