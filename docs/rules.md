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
the client replaces with the base URL of a host serving the version it chose (`rules.Fill`; see
below for which).

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
   flight; each bounded by `Timeout`, default 10 s, and 1 MiB). A manifest that lists a
   template over 1 MiB (`MaxTemplateSize`) is invalid.
2. It refuses a version more than a day (`MaxAhead`) ahead of its clock: versions are build
   times, and no host may set one that later builds never reach. A client whose clock is a day
   or more behind refuses every manifest, and uses its cached template, until its clock is set.
3. It refuses rollbacks. The floor holds for every host: `MinVersion`, or the cache's `floor`,
   the newest version that two operators or GitHub served (`Snapshot.Trusted`; `Snapshot.Save`
   records it). The cached manifest's version holds only for a single operator other than
   GitHub, which may have set it alone: two operators, or GitHub, may go below it, down to the
   floor. A mirror that once answered alone, with whatever version, cannot shut the others out.
4. It waits for every host, or for `Settle` (default 1.5 s) after the first manifest it can
   accept on its own, whichever comes first, and cancels the rest. A rollback starts no wait.
5. It takes the newest manifest that at least two operators serve byte for byte. jsDelivr's
   hostnames are one operator: they share a cache.
6. Failing agreement, it takes the newest manifest of the operator fewest hops from the branch
   (GitHub, then jsDelivr, then jsdmirror), which must have come over HTTPS. A lone answer is
   accepted the same way, for this call; it raises no floor.

The hosts that served the chosen manifest are ranked by response time; hosts that had not
answered follow, then hosts serving another version. `Snapshot.Fetch` downloads a file from the
first of them that serves it with the manifest's size and SHA-256, so a stale or tampered mirror
costs a retry, not a wrong file.

`{rules}` gets another host: of those serving the chosen manifest, the one fewest hops from the
branch (GitHub, then jsDelivr, then jsdmirror), the fastest of them on a tie (`Snapshot.Base`).
mihomo refreshes the rule sets from it on its own and checks nothing against the manifest, so
the URL names the most direct host rather than the fastest. A client that wants every rule set
checked downloads them with `Snapshot.Fetch` and points the providers at its copies, as the
OpenWrt plugin does. A cached template gets the configured host fewest hops away.

## The template

The template mirrors dler-io/Rules' layout `Clash/Rule.yaml`: its rules in their order, every
rule set mirrored on the branch. The proxy groups are ours (`cmd/rules/config.yaml`, the only
place their names come from); there are no region groups. They are listed as clients show
them, which is not the order rules match in: 🚀 Proxy, 🎯 Domestic and 🐟 Others first, then
🛑 AdBlock and the services, ♻️ Auto last. OpenWeir's api-edge installs the same groups, in the
same order, with the same rules.

Entries the layout's rule sets lack come from `additions` in the config, by the layout's name
for the set: they are merged into its content before it is split, so the files on the branch
carry them (their header says so) and everything that loads the set gets them, OpenWeir's
api-edge included. `DST-PORT,22` joins Special, the direct exceptions, so SSH never goes through
a proxy; Anthropic's endpoints join AI Suite. A rule that belongs to no set can go in `extra`,
before or after one of the layout's rule sets, with a policy mapped like the layout's own.

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
  and ipcidr only), text or yaml, `url` `{rules}/` and a path on the branch, `path` a file
  under `./rules/openweir/` (`rules.ProviderDir`), so the cache survives a change of host and a
  template writes nowhere else in mihomo's home (not over `geoip.dat` or `config.yaml`),
  `interval` 86400.
- `rules`: mihomo rules, sending traffic only to the template's groups and the built-in
  policies, ending with `MATCH`.

Anything else (ports, `mode`, `dns`, `tun`, `external-controller`, `secret`, `profile`,
`sniffer`, `hosts`, `proxies`, `proxy-providers`, a second YAML document, a `<<` merge) fails.

Because the groups use mihomo's own fields, the template loads in mihomo as it is. When
`subconv.Build` fills the nodes in, it instead:

1. validate the template (`rules.Validate`), and hold the rule providers' paths to
   `./rules/openweir/` once more as it puts them in;
2. add the converted `proxies` (and `proxy-providers`, if any). The template's group names
   win: a node or proxy provider with one is renamed with a number (`renamed`), and every
   `dialer-proxy`, provider `proxy`, group member and `use` that named it follows, so the
   template's rules and groups never reach a node by its name;
3. keep, after the template's groups, the subscription's groups that chains go through: those a
   `dialer-proxy` names (a proxy's, a proxy provider's, its `override`'s or its inline
   proxies'), or a proxy provider's `proxy`, and the groups they contain, as converted (renamed
   like a node when one has a template group's name). A landing node keeps dialing through its
   entry group rather than directly; the subscription's other groups go;
4. expand every `include-all` group into explicit `proxies`: its listed members first, then the
   nodes whose names match `filter` and not `exclude-filter`, in subscription order (mihomo's
   `include-all` sorts them by name), adding the providers as `use` with the filters kept;
5. drop groups left without members, and their references, as the normalization already does
   (what it says again about the subscription's proxies and providers, such as
   `local_provider`, is reported once);
6. replace `{rules}` with the chosen base URL (`rules.Fill`). A client may instead point the
   providers at files it downloaded with `Snapshot.Fetch`, whose content is checked against the
   manifest, which mihomo's own refresh is not.

## The rules package

```go
client := &rules.Client{
	HTTP:  httpClient,         // the caller's routing, proxies and address policy
	Cache: cache,              // rules.Cache: Get/Put by branch path; keeps the last good files
}
tpl, err := client.Template(ctx)
// err: ctx's error, or rules.ErrNoTemplate when no host serves a template that passes
// rules.Validate and the cache has none.
// tpl.YAML has {rules}; tpl.Base is snap.Base() for tpl.Version.
// tpl.Origin is FromNetwork, or FromCache when no host served a valid one (tpl.Err says why).
filled, err := tpl.Filled()

snap, err := client.Latest(ctx)              // the manifest and ranked hosts
data, err := snap.Fetch(ctx, "providers/dler/lan.classical.txt")
snap.Save()                                  // after the files: the versions the cache accepts
```

The cache holds `manifest.json` and files under their branch paths, and the floor under
`floor` (`rules.FloorKey`); the client checks whatever it reads from it against a manifest.
`Template` validates the template before it caches it and saves the manifest, so the cache never
holds a manifest whose template it lacks, and a template this client refuses (one a newer
schema allows, say) never replaces the last good one. A caller that keeps `MinVersion` itself
keeps only versions of `Trusted` snapshots: the cached manifest's version is no floor.

## The generator

`go run ./cmd/rules -out DIR -mihomo BIN [-prev manifest.json] [-changed FILE]` (or `-text`
instead of `-mihomo`, to try it without mihomo) builds the branch into an empty directory:

1. It reads the head commit of dler-io/Rules' main branch from the repository, as
   `git ls-remote` does (no GitHub API request, so no API rate limit), and downloads the
   repository at that commit as one archive. The layout's rule providers must come from a
   configured source; a file must be UTF-8 text under 16 MiB and not a web page.
2. Each rule set is parsed by its declared behavior. Entries written as classical rules are
   taken when they are of that behavior (a layout may declare a classical list ipcidr, which
   mihomo would load as empty). Rules mihomo cannot load are left out and logged.
3. A classical set with at least 100 domains and IP ranges is split into a domain part and an
   IP part (compiled to `.mrs`, which take less memory and need no scan) and a classical part
   for the rest (`DOMAIN-KEYWORD`, `PROCESS-NAME`, …), as consecutive `RULE-SET` rules with the
   same policy; IP ranges that said `no-resolve` keep it. Smaller sets stay whole.
4. `mihomo convert-ruleset` compiles the parts. mihomo runs with only `PATH`, `HOME` and
   `TMPDIR` from the generator's environment, so no token there reaches it; the workflow uses the
   OpenWeir mihomo release that `cmd/rules/mihomo.pin` names, at the SHA-256 pinned there.
5. It writes the template, `LICENSES/` (the texts of the licenses in use), `NOTICE.md`, the
   branch README and `manifest.json`, whose `version` is the build's Unix time, above the
   previous one.

With `-prev`, unchanged files keep their `updated` date, a rule set that lost more than half its
entries fails the build, and `-changed` lists the changed paths, the manifest last, or nothing.
The output is deterministic, so a day without upstream changes publishes nothing.

## The workflow

`.github/workflows/rules.yml` runs daily, and on demand, in two jobs, so that the code it
downloads never holds a token that can write to the repository:

- `build` (`contents: read`, no token in its environment) checks out main without keeping
  credentials, downloads the pinned mihomo, runs the generator against the branch's current
  manifest, and uploads the branch and the changed paths as an artifact. The generator needs
  no token: it makes no GitHub API request.
- `publish` (`contents: write`) runs only when a path changed. It checks out nothing and
  executes nothing it downloaded: it refuses an artifact holding anything but regular files at
  the branch's paths (`manifest.json`, `template.yaml`, `README.md`, `NOTICE.md`, `LICENSES/…`,
  `providers/…`), commits the files as one orphan commit, force-pushes it to `rules` with the
  token handed to git by a credential helper, and purges the changed paths from jsDelivr.

A hostile mihomo or upstream could still put wrong rule sets on the branch, but not reach main,
its releases or any other branch.

### Bumping mihomo

`cmd/rules/mihomo.pin` names the OpenWeir mihomo release by tag and, for each platform, its
archive and SHA-256. The workflow downloads its runner's archive (linux/amd64) from that tag and
refuses any other bytes, so an asset replaced or a release published later changes nothing
until the pin moves. To move it:

1. Choose the release, and check that the `.mrs` its `convert-ruleset` writes still load in the
   mihomo the clients run.
2. Take the archives' lines from the release's `sha256sums`, and compare them with the digests
   GitHub computed when the assets were uploaded:

   ```sh
   tag=openweir-v1.0.0
   gh release download "$tag" --repo openweir/mihomo --pattern sha256sums --output - \
     | grep -E 'mihomo-linux-(amd64-v1|arm64)-'
   gh release view "$tag" --repo openweir/mihomo --json assets \
     --jq '.assets[] | select(.name | test("^mihomo-linux-(amd64-v1|arm64)-.*\\.gz$")) | "\(.digest) \(.name)"'
   ```

3. Write the tag and the two lines into `cmd/rules/mihomo.pin` (`go test ./cmd/rules` checks its
   form), commit it as `ci:` or `chore(rules):`, which release nothing, and run the workflow by
   hand (`gh workflow run rules.yml`) to see a build through.

## Sources and licenses

| Source | License | Used for |
| --- | --- | --- |
| [dler-io/Rules](https://github.com/dler-io/Rules) | no LICENSE file; redistribution confirmed permitted (November 2026) | the layout, `providers/dler/` |

Each file's license is in the manifest; a source configured with `license-header` lets a file's
`# License:` header override the source's. dler-io's `Head*.yaml` (ports, DNS, TUN, controller
secret) are never read: only the layout's `rules` and `rule-providers` are, and the template
refuses everything else.
