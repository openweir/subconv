package ruleset

import "strings"

// Types are the rule types OpenWeir mihomo parses (rules/parser.go).
var Types = map[string]bool{}

func init() {
	for _, kind := range strings.Fields("DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-REGEX DOMAIN-WILDCARD GEOSITE " +
		"GEOIP SRC-GEOIP IP-ASN SRC-IP-ASN IP-CIDR IP-CIDR6 SRC-IP-CIDR IP-SUFFIX SRC-IP-SUFFIX SRC-PORT DST-PORT " +
		"IN-PORT DSCP PROCESS-NAME PROCESS-PATH PROCESS-NAME-REGEX PROCESS-PATH-REGEX PROCESS-NAME-WILDCARD " +
		"PROCESS-PATH-WILDCARD NETWORK UID IN-TYPE IN-USER IN-NAME REMATCH-NAME AND OR NOT RULE-SET MATCH") {
		Types[kind] = true
	}
}

// Aliases are other clients' names for mihomo's rule types: Surge, Quantumult X and older
// Clash.
var Aliases = map[string]string{
	"HOST":           "DOMAIN",
	"HOST-SUFFIX":    "DOMAIN-SUFFIX",
	"HOST-KEYWORD":   "DOMAIN-KEYWORD",
	"HOST-WILDCARD":  "DOMAIN-WILDCARD",
	"HOST-REGEX":     "DOMAIN-REGEX",
	"IP6-CIDR":       "IP-CIDR6",
	"IP-CIDR6":       "IP-CIDR6",
	"DEST-PORT":      "DST-PORT",
	"DEST-PORTS":     "DST-PORT",
	"SRC-IP":         "SRC-IP-CIDR",
	"SOURCE-IP-CIDR": "SRC-IP-CIDR",
	"FINAL":          "MATCH",
	"PROCESS":        "PROCESS-NAME",
	"IP-ASN6":        "IP-ASN",
}

// CommaPayload holds the rule types whose payload may contain commas: the policy is the last
// field.
var CommaPayload = map[string]bool{"AND": true, "OR": true, "NOT": true, "SUB-RULE": true,
	"DOMAIN-REGEX": true, "PROCESS-NAME-REGEX": true, "PROCESS-PATH-REGEX": true}
