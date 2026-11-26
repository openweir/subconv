# OpenWeir rules

Generated daily by <https://github.com/openweir/subconv> (`cmd/rules`); every run replaces this
branch with one new commit, so do not edit it.

- `template.yaml`: the routing template for subscriptions without usable rules. `{rules}`
  stands for this branch's URL on the CDN a client picked.
- `providers/`: the rule sets it loads, as mihomo `.mrs` and as text.
- `manifest.json`: every file with its size, SHA-256, source, license and dates. Its version
  grows with every publish.
- `NOTICE.md`, `LICENSES/`: attribution and licenses.

See <https://github.com/openweir/subconv/blob/main/docs/rules.md>.
