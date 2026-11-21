// Regenerates testdata/panel/ from the OpenWeir panel's own client formats (api-edge), so that
// subconv's conversions stay consistent with what the panel writes:
//
//   bun scripts/panel-vectors.ts ../api-edge
//
// For a set of panel nodes it writes the sing-box outbounds (singbox.json), the share links
// (links.txt) and the panel's OpenWeir proxies (openweir.json). TestPanelVectors converts the
// first two and compares the proxies with the third. It also copies the head of the panel's
// OpenWeir template (openweir-head.yaml), which TestHead holds subconv's head to.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const apiEdge = resolve(process.argv[2] ?? "../api-edge");
const { clientFormats } = await import(join(apiEdge, "src/features/proxy/clients.ts"));
const { nodeUri } = await import(join(apiEdge, "src/features/proxy/links.ts"));

const account = { uid: "1", uuid: "01234567-89ab-cdef-0123-456789abcdef", password: "N9Za3_0TWlW0l4Sko-VSpKrz" };
const tls = (sni: string) => ({ security: "tls", sni });
const reality = { security: "reality", reality_public_key: "PUBKEY", reality_short_ids: ["abcd"], reality_server_names: ["www.microsoft.com"] };

const fixtures: [string, string, Record<string, unknown>][] = [
	["VLESS REALITY", "vless", { ...reality, flow: "xtls-rprx-vision" }],
	["VLESS WS", "vless", { ...tls("v.example.com"), transport: "ws", path: "/ws", host: "v.example.com" }],
	["VLESS gRPC", "vless", { ...tls("v.example.com"), transport: "grpc", service_name: "gun" }],
	["VLESS XHTTP", "vless", { ...tls("x.example.com"), transport: "xhttp", path: "/stream", host: "x.example.com", xhttp_mode: "auto" }],
	["VMess WS", "vmess", { ...tls("vm.example.com"), transport: "ws", path: "/ray", host: "vm.example.com" }],
	["VMess TCP", "vmess", { security: "none" }],
	["Trojan", "trojan", tls("t.example.com")],
	["Trojan gRPC", "trojan", { ...tls("t.example.com"), transport: "grpc", service_name: "gun" }],
	["SS", "shadowsocks", { cipher: "aes-128-gcm" }],
	["SS 2022", "shadowsocks", { cipher: "2022-blake3-aes-128-gcm", server_key: "c2VydmVyLWtleS0xNmJ5dGU=" }],
	["SS obfs", "shadowsocks", { cipher: "aes-128-gcm", plugin: "obfs", plugin_opts: { mode: "http", host: "bing.com" } }],
	["SSR", "shadowsocksr", { cipher: "aes-128-cfb", protocol: "auth_chain_a", obfs: "plain", server_key: "shared" }],
	["Hy2", "hysteria2", { sni: "h.example.com", obfs: "salamander", obfs_password: "ob", hop_ports: "20000-30000" }],
	["TUIC", "tuic", { sni: "u.example.com", congestion_controller: "bbr" }],
	["AnyTLS", "anytls", tls("a.example.com")],
	["AnyTLS REALITY", "anytls", reality],
	["Naive", "naive", { sni: "n.example.com" }],
	["Naive QUIC", "naive", { sni: "n.example.com", network: "udp" }],
	["HTTP", "http", {}],
	["HTTPS", "https", { sni: "p.example.com" }],
	["SOCKS", "socks5", {}],
	["Snell v5", "snell", { version: "5", obfs: "http" }],
	["Snell v6", "snell", { version: "6", mode: "default" }],
	["Mieru", "mieru", { network: "tcp" }],
	["Nowhere", "nowhere", { sni: "nw.example.com", obfs: "none" }],
];

const nodes = fixtures.map(([name, protocol, params], index) => ({
	id: `node${index}`,
	name,
	source: "direct",
	server_id: 1,
	endpoint_id: "e",
	port: 443,
	address: `${protocol}.example.com`,
	naming: { landing: "A", landingServer: "1", position: index },
	params,
	protocol,
	ratio: 1,
	ratio_source: "inherit",
	tags: [],
	visible: true,
}));

const formats = clientFormats(nodes, account);
const out = resolve(import.meta.dir, "../testdata/panel");
mkdirSync(out, { recursive: true });
const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
writeFileSync(
	join(out, "singbox.json"),
	json({ outbounds: formats.flatMap((f: { singbox: unknown }) => (f.singbox ? [f.singbox] : [])) }),
);
writeFileSync(join(out, "links.txt"), `${nodes.flatMap((n) => nodeUri(n, account) ?? []).join("\n")}\n`);
writeFileSync(
	join(out, "openweir.json"),
	json(formats.flatMap((f: { openweir: unknown }) => (f.openweir ? [f.openweir] : []))),
);
// The template's settings before its proxies, without its Liquid lines.
const template = readFileSync(join(apiEdge, "resources/subscriptions/openweir.liquid.txt"), "utf8");
const head = template
	.slice(0, template.indexOf("\nproxies:") + 1)
	.split("\n")
	.filter((line) => !line.includes("{%") && !line.includes("{{"))
	.join("\n");
writeFileSync(join(out, "openweir-head.yaml"), head);
console.log(`wrote ${out}`);
