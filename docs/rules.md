# The rules branch

Subscriptions that carry no usable routing rules (share-link lists, Base64 lists, SIP008, sing-box
or Clash configs without rules, or whose rules converted too lossily) get their routing from a
template. The template, and the rule sets it loads, live on the `rules` branch of this
repository, which `.github/workflows/rules.yml` rebuilds daily with `cmd/rules`. Nothing on the
branch is in the Go code: the `rules` package fetches it and keeps the last good copy in the
caller's cache. A client that never got the template gets `rules.ErrNoTemplate`; `subconv.Build`
then returns the plain conversion with a `template_unavailable` warning, and the client routes
by its own defaults until a later fetch succeeds.

## The branch

```
manifest.json                 every file below, with size, SHA-256, source, license and dates
template.yaml                 the routing template
providers/<source>/<set>.<part>.mrs   rule sets in mihomo's binary format
providers/<source>/<set>.<part>.txt   the same in mihomo's text format (their source)
LICENSES/, NOTICE.md          upstream licenses and attribution
README.md
```

Each run replaces the branch with one orphan commit, force-pushed, and only when a file changed.
The rule sets change daily and their history is worth nothing (the manifest records sources and
dates), while keeping it would grow the repository by megabytes a day.

## Hosts

The branch is served under the same paths by every jsDelivr-compatible CDN, and by GitHub. In
order of preference before any was timed ([`rules.DefaultHosts`](../rules/rules.go)):

| Base URL | Operator | Hops |
| --- | --- | --- |
| `https://cdn.jsdmirror.com/gh/openweir/subconv@rules` | jsdmirror (Tencent EdgeOne, mainland China) | 2 |
| `https://fastly.jsdelivr.net/gh/openweir/subconv@rules` | jsDelivr | 1 |
| `https://testingcf.jsdelivr.net/gh/openweir/subconv@rules` | jsDelivr | 1 |
| `https://gcore.jsdelivr.net/gh/openweir/subconv@rules` | jsDelivr | 1 |
| `https://cdn.jsdelivr.net/gh/openweir/subconv@rules` | jsDelivr | 1 |
| `https://raw.githubusercontent.com/openweir/subconv/rules` | GitHub | 0 |

The template never names a host: rule provider URLs start with the placeholder `{rules}`, which
the client replaces with the base URL of the host it picked (`rules.Fill`).

Caching: jsDelivr caches a branch for up to 12 hours, browsers for 7 days; the workflow purges
every changed file through `purge.jsdelivr.net`, which clears all jsDelivr hostnames, the
manifest last. jsdmirror proxies jsDelivr (its responses carry jsDelivr's `x-jsd-version`) and
keeps files for `max-age=300, stale-while-revalidate=86400`; its purge API needs an API key, so
it catches up on its own, usually within minutes of jsDelivr. Its free tier limits one download
to 500 KB/s after the first 3 seconds. GitHub's raw files are cached for 5 minutes.

## Choosing a version

Third-party mirrors are not trusted, and the manifest is not signed, so a client cross-checks
hosts ([`Client.Latest`](../rules/client.go)):

1. It asks every host for `manifest.json` at once (at most `Parallel`, default 6, requests in
   flight; each bounded by `Timeout`, default 10 s, and 1 MiB).
2. It waits for every host, or for `Settle` (default 1.5 s) after the first valid manifest,
   whichever comes first, and cancels the rest.
3. Manifests older than the last version the client saw (`MinVersion`, or the cached manifest's)
   are rollbacks and never accepted.
4. It takes the newest manifest that at least two operators serve byte for byte. jsDelivr's
   hostnames are one operator: they share a cache.
5. Failing agreement, it takes the newest manifest of the operator fewest hops from the branch
   (GitHub, then jsDelivr, then jsdmirror), which must have come over HTTPS. A lone answer is
   accepted the same way.

The hosts that served the chosen manifest are ranked by response time; hosts that had not
answered follow, then hosts serving another version. `Snapshot.Fetch` downloads a file from the
first of them that serves it with the manifest's size and SHA-256, so a stale or tampered mirror
costs a retry, not a wrong file.

## The template

The template mirrors dler-io/Rules' layout `Clash/Rule.yaml`: its rules in their order, every
rule set mirrored on the branch. The proxy groups are ours (`cmd/rules/config.yaml`, the only
place their names come from); there are no region groups.

| Rule providers | Entries | Rule set files | Template |
| --- | --- | --- | --- |
| 68 (36 domain, 5 ipcidr .mrs; 27 classical text) | 16,122 | 128 KiB | 20.7 KiB |

It loads in OpenWeir mihomo with every entry counted (November 2026). Every IP rule ahead of the
final `LAN` and `GEOIP,CN` matches without resolving domains (`no-resolve`, in the rule or in its
rule set's entries), so domain connections are not resolved before the rules that decide them
by name.

It routes ads to 🛑 AdBlock (REJECT, DIRECT or Proxy), each service to its group, mainland China
(domains, then IP ranges) to 🎯 Domestic, private networks direct, the rest of China by GEOIP to
🎯 Domestic, and everything else to 🐟 Others. 🚀 Proxy offers ♻️ Auto, DIRECT and every node;
♻️ Auto is a url-test of every node; 🎯 Domestic offers DIRECT or 🚀 Proxy, 🐟 Others 🚀 Proxy or
🎯 Domestic. The service groups offer 🚀 Proxy, ♻️ Auto, DIRECT and every node; those reachable
from mainland China offer DIRECT first.

| Group | Layout policy | | Group | Layout policy |
| --- | --- | --- | --- | --- |
| 🚀 Proxy | Proxy | | 🎓 Scholar | Scholar |
| ♻️ Auto | (url-test) | | 📶 Speedtest | Speedtest |
| 🎯 Domestic | Domestic | | 🎮 Steam | Steam |
| 🐟 Others | Others | | 🎵 TikTok | TikTok |
| 🛑 AdBlock | AdBlock | | ✈️ Telegram | Telegram |
| 🎥 Netflix | Netflix | | 💬 Discord | Discord |
| 🏰 Disney Plus | Disney Plus | | 💰 Crypto | Crypto |
| 📹 YouTube | YouTube | | 💳 PayPal | PayPal |
| 🎬 Max | Max | | 📢 Google FCM | Google FCM |
| 🎧 Spotify | Spotify | | 🤖 AI Suite | AI Suite |
| 🌍 Streaming | Asian TV, Global TV | | 📺 Apple TV | Apple TV |
| 🏮 CN Mainland TV | CN Mainland TV (DIRECT first) | | 🔔 Apple Push | Apple Push (DIRECT first) |
| Ⓜ️ Microsoft | Microsoft (DIRECT first) | | 🍎 Apple Services | Apple Services (DIRECT first) |
| 🕹️ miHoYo | miHoYo (DIRECT first) | | | |

The names come only from `cmd/rules/config.yaml`: `policies` maps the layout's policies to the
groups, which is how dler-io's Asian TV and Global TV, region pickers for regional streaming
services, both go to 🌍 Streaming, keeping the rules' order. The template writes the emoji as
themselves (go-yaml would escape those outside the Basic Multilingual Plane); names are matched
exactly, variation selectors (U+FE0F) included.

### Schema

The template is a mihomo config fragment with only these top-level keys ([`rules.Validate`](../rules/template.go)
enforces it, and the generator validates every template it writes):

- `proxy-groups`: groups of type `select`, `url-test`, `fallback` or `load-balance`. A group
  names no node. `proxies` lists only other groups and `DIRECT`, `REJECT`, `REJECT-DROP` and
  `PASS`; `include-all: true` stands for every node of the subscription, narrowed by `filter`
  and `exclude-filter`, regular expressions on node names. Filters are written so that Go's
  RE2 and mihomo's regexp2 read them alike: no `\b`, `\w`, `\d` or `\s` (ASCII to one, Unicode
  to the other) and no backquote (mihomo splits filters at it); they list English terms first,
  then Chinese, then flags. Every group that takes all nodes excludes `rules.InfoFilter`
  (`(?i)expire|remaining|traffic|website|剩余|到期|过期|流量|官网|套餐|重置`), the pseudo-nodes
  that show traffic and expiry; clients can reuse the constant.
- `rule-providers`: `type: http`, `behavior` domain, ipcidr or classical, `format` mrs (domain
  and ipcidr only), text or yaml, `url` `{rules}/` and a path on the branch, `path` under
  `./rules/openweir/` so the cache survives a change of host, `interval` 86400.
- `rules`: mihomo rules, sending traffic only to the template's groups and the built-in
  policies, ending with `MATCH`.

Anything else (ports, `mode`, `dns`, `tun`, `external-controller`, `secret`, `profile`,
`sniffer`, `hosts`, `proxies`, `proxy-providers`, a second YAML document, a `<<` merge) fails.

Because the groups use mihomo's own fields, the template loads in mihomo as it is. When
`subconv.Build` fills the nodes in, it instead:

1. validate the template (`rules.Validate`);
2. add the converted `proxies` (and `proxy-providers`, if any);
3. expand every `include-all` group into explicit `proxies`: its listed members first, then the
   nodes whose names match `filter` and not `exclude-filter`, in subscription order (mihomo's
   `include-all` sorts them by name), adding the providers as `use` with the filters kept;
4. drop groups left without members, and their references, as the normalization already does;
5. replace `{rules}` with the chosen base URL (`rules.Fill`). A client may instead point the
   providers at files it downloaded with `Snapshot.Fetch`, whose content is checked against the
   manifest, which mihomo's own refresh is not.

## The rules package

```go
client := &rules.Client{
	HTTP:  httpClient,         // the caller's routing, proxies and address policy
	Cache: cache,              // rules.Cache: Get/Put by branch path; keeps the last good files
}
tpl, err := client.Template(ctx)
// err: ctx's error, or rules.ErrNoTemplate when no host serves the template and the cache has
// none.
// tpl.YAML has {rules}; tpl.Base is the fastest host serving tpl.Version.
// tpl.Origin is FromNetwork, or FromCache when no host served it (tpl.Err says why).
filled, err := tpl.Filled()

snap, err := client.Latest(ctx)              // the manifest and ranked hosts
data, err := snap.Fetch(ctx, "providers/dler/lan.classical.txt")
snap.Save()                                  // after the files: the cache's new minimum version
```

The cache holds `manifest.json` and files under their branch paths; the client checks whatever
it reads from it against a manifest, and the cached manifest's version is the rollback floor.
`Template` saves the manifest only after the template, so the cache never holds a manifest
whose template it lacks.

## The generator

`go run ./cmd/rules -out DIR -mihomo BIN [-prev manifest.json] [-changed FILE]` (or `-text`
instead of `-mihomo`, to try it without mihomo) builds the branch into an empty directory:

1. It resolves dler-io/Rules' current commit and downloads the repository at it as one
   archive. The layout's rule providers must come from a configured source; a file must be
   UTF-8 text under 16 MiB and not a web page.
2. Each rule set is parsed by its declared behavior. Entries written as classical rules are
   taken when they are of that behavior (a layout may declare a classical list ipcidr, which
   mihomo would load as empty). Rules mihomo cannot load are left out and logged.
3. A classical set with at least 100 domains and IP ranges is split into a domain part and an
   IP part (compiled to `.mrs`, which take less memory and need no scan) and a classical part
   for the rest (`DOMAIN-KEYWORD`, `PROCESS-NAME`, …), as consecutive `RULE-SET` rules with the
   same policy; IP ranges that said `no-resolve` keep it. Smaller sets stay whole.
4. `mihomo convert-ruleset` compiles the parts; the workflow uses the latest OpenWeir mihomo
   release, checked against its `sha256sums`.
5. It writes the template, `LICENSES/` (the texts of the licenses in use), `NOTICE.md`, the
   branch README and `manifest.json`, whose `version` is the build's Unix time, above the
   previous one.

With `-prev`, unchanged files keep their `updated` date, a rule set that lost more than half its
entries fails the build, and `-changed` lists the changed paths, the manifest last, or nothing.
The output is deterministic, so a day without upstream changes publishes nothing.

## Sources and licenses

| Source | License | Used for |
| --- | --- | --- |
| [dler-io/Rules](https://github.com/dler-io/Rules) | no LICENSE file; redistribution confirmed permitted (November 2026) | the layout, `providers/dler/` |

Each file's license is in the manifest; a source configured with `license-header` lets a file's
`# License:` header override the source's. dler-io's `Head*.yaml` (ports, DNS, TUN, controller
secret) are never read: only the layout's `rules` and `rule-providers` are, and the template
refuses everything else.
