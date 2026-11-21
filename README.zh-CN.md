# subconv

[English](README.md)

把各种常见格式的代理订阅转换成 OpenWeir 订阅格式，也就是
[OpenWeir mihomo](https://github.com/openweir/mihomo) 能直接加载的 `proxies`、`proxy-providers`、
`proxy-groups`、`rule-providers` 和 `rules`。纯 Go 实现，不做任何网络或文件 I/O。

## 支持的输入

| 输入 | 转换内容 |
| --- | --- |
| Clash / mihomo / Stash YAML | 全部五个部分，逐项修复，修不好的单独剔除 |
| sing-box JSON（1.11–1.13） | 出站、端点、策略组、规则集、规则 |
| Xray / V2Ray JSON | 出站及传输设置、负载均衡器、路由规则 |
| 分享链接（明文或 Base64） | vless、vmess、trojan、ss、ssr、hysteria2、hysteria、tuic、anytls、naive、socks、http、ssh、wireguard、snell、mieru、nowhere |
| Surge、Surfboard、Loon、Shadowrocket | 节点、策略组、规则、规则列表 |
| Quantumult X | 节点、策略、分流 |
| SIP008、`ssd://` | Shadowsocks 节点 |
| 规则集内容 | Clash YAML 与文本、MRS、Surge / Loon / Quantumult X 列表、sing-box 源格式 JSON |

各格式的转换细节、哪些内容会被剔除及原因、警告代码一览见
[docs/conversion.md](docs/conversion.md)；代码结构与测试见 [docs/architecture.md](docs/architecture.md)。

## 用法

```go
result, err := subconv.Convert(body) // 自动识别格式；可用 errors.Is 判断 subconv.ErrWebPage、ErrMessage、ErrEmpty
fragment, err := result.YAML()       // 五个部分的 YAML
for _, w := range result.Warnings {  // 被剔除或改动的内容：稳定的代码加上具体条目
	log.Printf("%s: %s", w.Code, w.Detail)
}
stats := result.RuleStats            // Total、Dropped、Match：规则转换得是否完整

// 客户端自行下载的 provider
set, err := subconv.ConvertRuleSet(body, "domain", "text") // set.Behavior、set.Format、set.Body
proxies, err := subconv.ConvertProxies(body)
```

## 命令行

```bash
go run ./cmd/subconv subscription.txt         # 输出 YAML，警告打印到 stderr
go run ./cmd/subconv -json subscription.txt   # 以 JSON 输出完整结果
```

## 使用者

OpenWeir 桌面客户端、OpenWrt 插件和 Android 客户端直接引用本库；iOS 客户端用 `testdata/` 中的测试向量校验自身实现。

## 许可证

GPL-3.0，见 [LICENSE](LICENSE)。
