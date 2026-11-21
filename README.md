# subconv

[中文说明](README.zh-CN.md)

Converts proxy subscriptions of any common format into the OpenWeir subscription format: the
`proxies`, `proxy-providers`, `proxy-groups`, `rule-providers` and `rules` that the
[OpenWeir mihomo build](https://github.com/openweir/mihomo) loads. Pure Go; the conversion
does no I/O.

## Supported inputs

| Input | Converted |
| --- | --- |
| Clash / mihomo / Stash YAML | All five parts, each item repaired or left out on its own |
| sing-box JSON (1.11–1.13) | Outbounds, endpoints, groups, rule sets, rules |
| Xray / V2Ray JSON | Outbounds with stream settings, balancers, routing rules |
| Share links, plain or Base64 | vless, vmess, trojan, ss, ssr, hysteria2, hysteria, tuic, anytls, naive, socks, http, ssh, wireguard, snell, mieru, nowhere |
| Surge, Surfboard, Loon, Shadowrocket | Proxies, groups, rules, rule lists |
| Quantumult X | Servers, policies, filters |
| SIP008, `ssd://` | Shadowsocks servers |
| Rule-set content | Clash YAML and text, MRS, Surge / Loon / Quantumult X lists, sing-box source JSON |

What converts to what, what is left out and why, and the warning codes:
[docs/conversion.md](docs/conversion.md). Layout and tests: [docs/architecture.md](docs/architecture.md).

## Usage

```go
result, err := subconv.Convert(body) // any format; errors.Is(err, subconv.ErrWebPage), ErrMessage, ErrEmpty
fragment, err := result.YAML()       // the five parts as YAML
for _, w := range result.Warnings {  // what was left out or changed: a stable code and the item
	log.Printf("%s: %s", w.Code, w.Detail)
}
stats := result.RuleStats            // Total, Dropped, Match: how well the rules converted

// A config to run. Rules: "" (auto) | "template" | "subscription";
// Client: *rules.Client; Head: put the OpenWeir default head in front
config, err := subconv.Build(ctx, body, subconv.Options{Client: client, Head: true})

// Providers a client downloads itself
set, err := subconv.ConvertRuleSet(body, "domain", "text") // set.Behavior, set.Format, set.Body
proxies, err := subconv.ConvertProxies(body)
```

Subscriptions without rules (or whose rules convert poorly) get their routing from the template
on this repository's `rules` branch, rebuilt daily from dler-io/Rules and served through
jsDelivr-compatible CDNs; the `rules` package fetches it, checks it against the manifest and
caches it — see [docs/rules.md](docs/rules.md).

## Command line

```bash
go run ./cmd/subconv subscription.txt         # YAML; warnings on stderr
go run ./cmd/subconv -json subscription.txt   # the whole result as JSON
```

## Used by

The OpenWeir desktop client, OpenWrt plugin and Android client. The iOS client checks itself
against the vectors in `testdata/`.

## License

GPL-3.0; see [LICENSE](LICENSE).
