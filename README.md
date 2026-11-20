# subconv

The subscription converter shared by OpenWeir clients, in Go. It converts subscriptions of any
format (sing-box, Clash/mihomo, share links, and more to come) into the OpenWeir subscription
format: the Clash YAML that the OpenWeir mihomo build ([openweir/mihomo](https://github.com/openweir/mihomo))
reads, as the OpenWeir panel serves it. A conversion yields the subscription's four parts,
`proxies`, `proxy-groups`, `rule-providers` and `rules`; everything else in a config (ports, DNS,
TUN, the controller) is up to each client.

Used by the desktop client ([app-desktop](https://github.com/openweir/app-desktop)'s Go core), the
OpenWrt plugin and the Android client. The iOS client's Rust core cannot link Go; it checks itself
against the shared vectors in `testdata/`.

Layout and extension points: [docs/architecture.md](docs/architecture.md). To try a subscription:

```bash
go run ./cmd/subconv subscription.json          # the OpenWeir YAML; warnings on stderr
go run ./cmd/subconv -json subscription.json    # the whole result as JSON
```

## Usage

```go
result, err := subconv.Convert(body) // detects sing-box JSON, Clash YAML or share links
if err != nil { ... }
fragment, err := result.YAML()       // proxies, proxy-groups, rule-providers, rules
for _, w := range result.Warnings {  // what the conversion left out: a stable code and the item
	log.Printf("%s: %s", w.Code, w.Detail)
}
```

The package does no I/O: a subscription's body goes in, a `Result` comes out. Downloading, caching
and merging subscriptions are the caller's job.

## Support

| Input | Status |
| --- | --- |
| Clash / mihomo YAML | The four parts are taken as they are; the client validates them when it loads the config |
| sing-box JSON (1.11+, including `endpoints`) | Proxies, groups, rule sets and rules are converted, as below |
| Share links / Base64 | Converted to proxies; a links subscription has no groups or rules |
| Surge, Loon, Quantumult X | Planned |

Share links: vless, trojan, vmess (v2rayN's Base64 JSON), ss (SIP002 and the legacy form, with
obfs and v2ray-plugin), ssr, hysteria2/hy2, hysteria, tuic, anytls (with REALITY), naive+https and
naive+quic, socks5, http/https, mierus, nowhere, snell (Shadowrocket's form) and wireguard, in the
forms the common clients and the OpenWeir panel write. Telegram proxies (`tg://`) and transports
mihomo lacks are left out with a warning; duplicate names get a number.

How sing-box converts:

- **Proxies**: shadowsocks (with obfs-local and v2ray-plugin), vmess, vless (with REALITY and
  OpenWeir's extended XHTTP), trojan, hysteria2, hysteria, tuic, anytls (with REALITY), naive
  (OpenWeir's native Naive), http, socks5, wireguard (outbound and endpoint) and ssh. Transports:
  ws, httpupgrade, grpc and http/h2. Multiplex becomes smux; `detour` becomes `dialer-proxy`.
- **Left out with a warning**: proxies OpenWeir mihomo cannot represent, such as shadowtls, SOCKS4,
  TLS ECH, the QUIC transport, WireGuard with more than one peer, Naive that skips certificate
  verification, and XHTTP on anything but VLESS.
- **Groups**: selector becomes select (with `default` moved first), urltest becomes url-test, and
  libbox's loadbalance becomes load-balance (consistent-hashing). Members that were left out are
  dropped; a group left empty falls back to DIRECT.
- **Rules**: domain, domain_suffix, domain_keyword, domain_regex, ip_cidr (with `no-resolve`, as
  sing-box matches without resolving), ip_is_private, source_ip_cidr, ports and port ranges,
  network, process names and paths, rule_set, logical rules and `invert`. Several values of one
  field become one rule each; several fields combine into an `AND`. `reject` becomes REJECT
  (REJECT-DROP with `method: drop`). Rules a client handles itself, such as sniff, hijack-dns and
  clash_mode, are skipped quietly; `route.final` becomes `MATCH`.
- **Rule sets**: inline sets become mihomo inline providers, and MetaCubeX's `geosite-*` and
  `geoip-*` sets become the matching `.mrs` files. Other remote sets are in sing-box's own binary or
  JSON format, which mihomo cannot read; they are left out with the rules that use them, with a
  warning.

## Test vectors

`testdata/<case>/input.*` converts to `testdata/<case>/expected.json`. After changing the
conversion:

```bash
go test ./... -run TestVectors -update   # rewrite expected.json; review every diff before committing
go test ./...
```

## Releases

Other modules require a tagged version: `go get github.com/openweir/subconv@latest`. Every push to
`main` that passes CI is released automatically from its [Conventional Commits](https://www.conventionalcommits.org/):
`feat` bumps the minor version, `fix` and `perf` the patch, and `docs`, `refactor`, `test`, `ci` and
`chore` release nothing. Versions stay below 1.0.0 while the API settles. Releases carry notes
only; there are no binaries to download.

## License

GPL-3.0; see [LICENSE](LICENSE).
