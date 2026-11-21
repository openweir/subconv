# Architecture

subconv converts subscriptions of any format into the OpenWeir subscription format: the Clash
parts the OpenWeir mihomo build loads. `Build` makes a config to run of them, with the routing
template of the rules branch when the subscription's own routing is missing or too lossy. This
document covers the layout, the flow of a conversion and of a build, how to extend them, and how
they are tested and released. What each format converts to is in [conversion.md](conversion.md);
the rules branch and the `rules` package are in [rules.md](rules.md).

## Layout

The module follows Go's [layout for a module](https://go.dev/doc/modules/layout): the root
package is the API, what it does lives under `internal/`, and each command under `cmd/`.

```
subconv.go             the conversion API: Convert, ConvertWith, Detect, ConvertRuleSet,
                       ConvertProxies, their errors, Result, the formats and warning codes
build.go               Build, its Options and Head: a config to run, with the routing template
subconv_test.go        vectors, rule-set vectors, the panel cross-check, the mihomo load check,
                       fuzz targets
build_test.go          Build against a rules branch served by a test server
internal/convert/      behind the conversion API: which format a body is, decoded and cleaned,
                       and the errors for bodies that are no subscription (detect.go); the
                       hand-off to each format's package and the normalization (convert.go)
internal/build/        behind Build: when the template applies and how its groups take the nodes
                       (template.go); the OpenWeir default head, held to the panel's by TestHead
                       (head.go)
internal/body/         a body as text: byte-order marks, UTF-16, Base64 variants, JSONC, web
                       pages and error messages
internal/model/        what every format shares: Result, Warning and its codes, RuleStats,
                       Options, the ordered Object, decoding YAML or JSON into ordered values
internal/normalize/    the pass every result goes through: proxies, names, providers, groups
                       (relays as dialer-proxy chains, loops), rules, rule statistics
internal/proxy/        proxy building blocks every format shares, the normalization of one
                       mihomo proxy (normalize.go) and the checks mihomo makes when it loads one
                       (validate.go)
internal/ruleset/      rule providers (behaviors, formats, MetaCubeX's .mrs twins), mihomo's rule
                       types, and rule-set content (content.go)
internal/clash/        Clash, mihomo and Stash YAML, and the recovery of broken YAML
internal/singbox/      sing-box: outbounds and endpoints (outbound.go), groups and references
                       (singbox.go), rule sets and rules (rules.go)
internal/xray/         Xray and V2Ray JSON
internal/links/        share links, one per line
internal/surge/        Surge, Surfboard, Loon, Shadowrocket and Quantumult X line configs
internal/shadowsocks/  SIP008 and SSD
rules/                 the public package that gets the routing template: hosts and the manifest
                       (rules.go), choosing a version across mirrors and fetching checked files
                       (client.go), the template's schema, Validate and Fill (template.go)
cmd/subconv/           a command-line tool for trying subscriptions
cmd/rules/             the generator of the rules branch; config.yaml names the layout, the
                       sources and the template's groups
scripts/               panel-vectors.ts, which regenerates testdata/panel/ from the panel's code
testdata/<case>/       shared vectors: input.* and the expected.json it converts to
testdata/ruleset/      rule-set vectors: input.*, provider.json, expected.json
testdata/panel/        the panel's sing-box outbounds, links and OpenWeir proxies for the same
                       nodes, checked by TestPanelVectors, and its template head
```

Clients import `github.com/openweir/subconv`, and `github.com/openweir/subconv/rules` for the
client and cache `Build` takes. Everything under `internal/` can change without touching them.

## A conversion

1. `convert.Detect` cleans the body (`internal/body`): a byte-order mark or UTF-16 goes, JSON
   comments go, and a body that is Base64 as a whole is decoded and detected again. HTML, empty
   bodies and short messages fail with `ErrWebPage`, `ErrEmpty` and `ErrMessage`.
2. The format's package reads the body into a `model.Result`: proxies, proxy providers, groups,
   rule providers and Clash rules, as close to mihomo's as the format allows. It never fails on
   an item it cannot represent: the item is left out with a `Warning` (and a rule with
   `Result.DropRule`), and only a body that is not the format at all fails.
3. `normalize.Result` makes the parts a config mihomo loads: each proxy repaired or left out
   (`proxy.Normalize`), unique names, usable providers, groups whose members exist and do not
   loop, relays as dialer-proxy chains, rules whose policies and rule sets exist, one final
   `MATCH`, and `RuleStats`. It leaves valid items exactly as written.
4. The caller places the parts in its own config, or renders them with `Result.YAML`.

Decoding keeps every mapping's key order (`model.Object`), so the output reads the way clients
write configs and the vectors compare byte for byte.

## A build

`Build` converts as `ConvertWith` does, then:

1. With `Options.Head`, sets `Result.Head` to `Head`, which `Result.YAML` writes before the
   parts.
2. Decides on the template from `Options.Rules` and the rule statistics (`build.Reason`):
   `RulesTemplate` always, `RulesSubscription` never, `RulesAuto` when the subscription has no
   rules, its final rule did not survive, or more than a tenth of its rules were left out.
3. Gets the template from `Options.Client` (`rules.Client.Template`: the agreed manifest, the
   template checked against it, the cache when no host answers). Without one, the plain
   conversion comes back with `template_unavailable`.
4. `build.Apply` validates the template, fills in the host, expands every `include-all` group
   into its members and the nodes its filters let through (in subscription order, with the
   proxy providers as `use`), puts its groups, rule providers and rules in place of the
   subscription's, and runs the normalization again, which removes the groups left empty. The
   rule statistics stay the subscription's; `Result.Template` and `template_applied` say why. A
   template that fails validation is unavailable too.

The rules branch itself (the template, its rule sets and the manifest) is built by `cmd/rules`
in a daily workflow and is not in the Go code ([rules.md](rules.md)).

### sing-box

sing-box names outbounds by tag and refers to them from groups, detours and rules, so the
conversion runs in passes: ShadowTLS outbounds are collected first (the proxies that dial
through them absorb them), every outbound is classified (`direct` is DIRECT, `block` REJECT,
`dns` dropped, groups kept for later, proxies converted), detours become `dialer-proxy`, groups
are converted, and rule sets and rules follow. A sing-box rule matches when every group of
fields matches and a group when any of its values does; a rule of one group becomes one Clash
rule per value, a rule of several one `AND` of the groups, each an `OR` of its values.

## Extending

- **A protocol**: add a case to each format that writes it (`proxy` in
  `internal/singbox/outbound.go`, `parse` in `internal/links/links.go`, `proxy` in
  `internal/surge/proxy.go`, `outbound` in `internal/xray/xray.go`), and its required fields to
  `credentials` in `internal/proxy/normalize.go`. Follow the field names of OpenWeir mihomo (and
  of api-edge's `clients.ts`, which writes the same proxies from the panel's side). Return a
  reason instead of a proxy when an option cannot be represented.
- **A rule field**: add a case to `atoms` in `internal/singbox/rules.go`, or a type to
  `internal/ruleset/types.go` when mihomo gains one.
- **A format**: add a package under `internal/`, a `Format` constant in `internal/model` and
  `subconv.go`, a branch in `detect` (`internal/convert/detect.go`) and `parts`
  (`internal/convert/convert.go`), a row in conversion.md, and a vector.
- A protocol the panel writes has a fixture in `scripts/panel-vectors.ts`; regenerate
  `testdata/panel/` so `TestPanelVectors` holds both sides to the same proxies.

## Tests

`testdata/<case>/input.*` converts to `testdata/<case>/expected.json`, and
`testdata/ruleset/<case>/input.*` with `provider.json` to its `expected.json`. Other
implementations (the iOS client's Rust core) check themselves against the same files. After
changing the conversion:

```bash
go test -run 'TestVectors|TestRuleSetVectors' -update .   # rewrite expected.json; review every diff
go test ./...
```

- `TestValidClashUnchanged` holds valid mihomo items to coming back exactly as written.
- `TestPanelVectors` converts the panel's sing-box outbounds, share links and its own Clash
  proxies and requires the proxies it writes, apart from a short list of settings a format
  cannot carry. Regenerate the files after changing the panel's client formats:
  `bun scripts/panel-vectors.ts ../api-edge`.
- `TestVectorsLoadInMihomo` loads every vector's conversion with the mihomo binary
  `SUBCONV_MIHOMO` names (`mihomo -t`); without one it is skipped.
- `FuzzConvert`, `FuzzConvertRuleSet` and `FuzzConvertProxies` run their seeds with
  `go test`; `go test -fuzz '^FuzzConvert$' .` explores further. Corpora go in
  `testdata/fuzz/<FuzzName>/`.
- `build_test.go` builds against a rules branch an `httptest` server serves; `TestHead`
  (`internal/build`) holds `Head` to the panel's template head in `testdata/panel/`. The
  `rules` package and `cmd/rules` test themselves against test servers too.

## Constraints

- No global state, and no I/O in the conversion: the package must run in the desktop core, the
  OpenWrt daemon and gomobile alike. `Build` reaches the network only through the caller's
  `rules.Client` (its HTTP client and cache).
- Pure Go with few dependencies (only `go.yaml.in/yaml/v3`), to keep the OpenWrt binary small.
  MRS rule sets therefore pass through unread: reading them needs zstd.
- The Go version stays at what the OpenWrt plugin builds with (go.mod's `go` line).

## Releases

Other modules require a tagged version: `go get github.com/openweir/subconv@latest`. Every push
to `main` that passes CI is released automatically from its
[Conventional Commits](https://www.conventionalcommits.org/): `feat` bumps the minor version,
`fix` and `perf` the patch, and `docs`, `refactor`, `test`, `ci` and `chore` release nothing.
Versions stay below 1.0.0 while the API settles. Releases carry notes only; there are no
binaries to download.
