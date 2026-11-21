package subconv

// Head is the OpenWeir default head: the settings of a complete config before its proxies,
// exactly as the OpenWeir panel's template writes them (api-edge's
// resources/subscriptions/openweir.liquid.txt). Build puts it in front of the converted parts
// when Options.Head is set. TestHead holds it to testdata/panel/openweir-head.yaml, which
// scripts/panel-vectors.ts copies from the panel; update both together.
const Head = `mixed-port: 9347
allow-lan: false
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
geodata-mode: true
geo-auto-update: true
geo-update-interval: 72
geox-url:
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
profile:
  store-selected: true
  store-fake-ip: true
sniffer:
  enable: true
  sniff:
    HTTP: { ports: [80, 8080-8880], override-destination: true }
    TLS: { ports: [443, 8443] }
    QUIC: { ports: [443, 8443] }
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ["*.lan", "*.local", "+.msftconnecttest.com", "+.msftncsi.com", "time.*.com", "+.stun.*.*", "localhost.ptlogin2.qq.com"]
  default-nameserver: [223.5.5.5, 119.29.29.29]
  nameserver: [https://dns.alidns.com/dns-query, https://doh.pub/dns-query]
  proxy-server-nameserver: [https://dns.alidns.com/dns-query, https://doh.pub/dns-query]
  nameserver-policy:
    "geosite:geolocation-!cn": [https://dns.cloudflare.com/dns-query, https://dns.google/dns-query]
`
