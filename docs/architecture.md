# Architecture

subconv converts subscriptions of any format into the OpenWeir subscription format: the Clash
parts the OpenWeir mihomo build loads. This document covers the layout, the flow of a
conversion, how to extend it, and how it is tested and released. What each format converts to
is in [conversion.md](conversion.md).

## Layout

```
subconv.go             the conversion API: Convert, ConvertWith, Detect, ConvertRuleSet,
                       ConvertProxies, their errors, Result and the Format and warning constants
build.go               Build, Options and Head
subconv_test.go        the vectors, the panel cross-check, the mihomo load check, fuzz targets
build_test.go          Build against a test rules branch
internal/convert/      what the conversion API does: detect a body's format (detect.go), hand it
                       to the format's package, normalize the result
internal/build/        what Build adds: the routing template applied (template.go), the OpenWeir
                       default head (head.go)
internal/body/         a body as text: byte-order marks, UTF-16, Base64 variants, JSONC, web
                       pages and error messages
internal/model/        what every format shares: Result, Warning and its codes, RuleStats,
                       Options, the ordered Object, decoding YAML or JSON into ordered values
internal/normalize/    the pass every result goes through: proxies, names, providers, groups
                       (relays as dialer-proxy chains, loops), rules, rule statistics
internal/proxy/        proxy building blocks every format shares, and the normalization of one
                       mihomo proxy (normalize.go)
internal/ruleset/      rule providers (behaviors, formats, MetaCubeX's .mrs twins), mihomo's rule
                       types, and rule-set content (content.go)
internal/clash/        Clash, mihomo and Stash YAML, and the recovery of broken YAML
internal/singbox/      sing-box: outbounds and endpoints (outbound.go), groups and references
                       (singbox.go), rule sets and rules (rules.go)
internal/xray/         Xray and V2Ray JSON
internal/links/        share links, one per line
internal/surge/        Surge, Surfboard, Loon, Shadowrocket and Quantumult X line configs
internal/shadowsocks/  SIP008 and SSD
cmd/subconv/           a command-line tool for trying subscriptions
testdata/<case>/       shared vectors: input.* and the expected.json it converts to
testdata/ruleset/      rule-set vectors: input.*, provider.json, expected.json
testdata/panel/        the panel's sing-box outbounds, links and OpenWeir proxies for the same
                       nodes (scripts/panel-vectors.ts), checked by TestPanelVectors
```

Clients import only `github.com/openweir/subconv`. Everything under `internal/` can change
without touching them.

## A conversion

1. `convert.Detect` cleans the body (`internal/body`): a byte-order mark or UTF-16 goes, JSON comments
   go, and a body that is Base64 as a whole is decoded and detected again. HTML, empty bodies
   and short messages fail with `ErrWebPage`, `ErrEmpty` and `ErrMessage`.
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
go test ./... -run 'TestVectors|TestRuleSetVectors' -update   # rewrite expected.json; review every diff
go test ./...
```

- `TestValidClashUnchanged` holds valid mihomo items to coming back exactly as written.
- `TestPanelVectors` converts the panel's sing-box outbounds, share links and its own Clash
  proxies and requires the proxies it writes, apart from a short list of settings a format
  cannot carry. Regenerate the files after changing the panel's client formats:
  `bun scripts/panel-vectors.ts ../api-edge`.
- `FuzzConvert`, `FuzzConvertRuleSet` and `FuzzConvertProxies` run their seeds with
  `go test`; `go test -fuzz FuzzConvert` explores further.

## Constraints

- No I/O and no global state: the package must run in the desktop core, the OpenWrt daemon and
  gomobile alike.
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
