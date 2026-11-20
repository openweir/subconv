# Architecture

subconv converts subscriptions of any format into the OpenWeir subscription format: the Clash YAML
the OpenWeir mihomo build reads, as the OpenWeir panel serves it. This document covers the layout,
the flow of a conversion, and how to extend it.

## Layout

```
subconv.go             the public API: Detect, Convert, and aliases of the internal types
internal/model/        what every format shares: Result, Warning and its codes, the ordered
                       Object, decoding YAML or JSON into ordered values
internal/singbox/      sing-box → mihomo: outbounds and endpoints (outbound.go), groups and
                       references (singbox.go), rule sets and rules (rules.go)
internal/clash/        Clash and mihomo YAML, taken as they are
cmd/subconv/           a command-line tool for trying subscriptions
testdata/<case>/       shared vectors: input.* and the expected.json it converts to
```

Clients import only `github.com/openweir/subconv`. Everything under `internal/` can change without
touching them.

## A conversion

1. `Detect` looks at the body: a JSON object with `outbounds` or `endpoints` is sing-box; YAML or
   JSON with `proxies` (or `proxy-providers`) is Clash; lines with `://`, or Base64, are share links.
2. `Convert` hands the body to the format's package, which decodes it with `model.Decode`. Decoding
   keeps every mapping's key order (`model.Object`), so the output reads the way clients write
   configs and the vectors compare byte for byte.
3. The format's package fills a `model.Result`: proxies, groups, rule providers, rules, and a
   `Warning` for everything it leaves out. It never fails on content it cannot represent; it fails
   only on input that is not that format at all.
4. The caller places the parts in its own config, or renders them with `Result.YAML`.

### sing-box

sing-box names outbounds by tag and refers to them from groups, detours and rules, so the
conversion runs in passes:

1. Every outbound and endpoint is classified. `direct` maps to DIRECT, `block` to REJECT, `dns` is
   dropped (it only routes DNS), groups are kept for later, and proxies are converted. A proxy that
   cannot be represented maps to "" and gets a warning.
2. Detours are resolved into `dialer-proxy`, now that every tag is known.
3. Groups are converted, dropping members that map to "" and falling back to DIRECT when none is
   left.
4. Rule sets become rule providers, rules become Clash rules in order, and `route.final` (or the
   first outbound, as in sing-box) becomes `MATCH`.

A sing-box rule matches when every field matches, and a field when any of its values does. A rule
with one field becomes one Clash rule per value; a rule with several becomes one `AND` of the fields,
each an `OR` of its values.

## Extending

- **A protocol**: add a case to `proxy` in `internal/singbox/outbound.go`, reusing `withTLS`,
  `withStream` and `withMux`. Return a reason instead of a proxy when an option cannot be
  represented. Follow the field names of OpenWeir mihomo (and of api-edge's `clients.ts`, which
  writes the same proxies from the panel's side).
- **A rule field**: add a case to `atoms` in `internal/singbox/rules.go`.
- **A format**: add a package under `internal/`, a `Format` constant in `internal/model`, a branch
  in `Detect` and `Convert`, and a vector.
- Every change to the output updates the vectors: `go test ./... -run TestVectors -update`, then
  review the diff.

## Constraints

- No I/O and no global state: the package must run in the desktop core, the OpenWrt daemon and
  gomobile alike.
- Pure Go with few dependencies (only `go.yaml.in/yaml/v3`), to keep the OpenWrt binary small.
- The Go version stays at what the OpenWrt plugin builds with (go.mod's `go` line).
