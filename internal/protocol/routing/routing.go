// Package routing builds subscription routing-rule presets — the BPB/Nova-style
// "bypass Iran / block ads / block porn / block QUIC" rules — for the three
// config formats ForgePanel ships that can carry routing: sing-box, Xray and
// Clash-Meta. The rules are the same policy expressed three ways.
//
// The design goal is that the rule material is fetchable FROM Iran: sing-box
// rule-sets are downloaded through the proxy tunnel (download_detour = the proxy
// selector), and Xray leans on the geoip/geosite databases the clients already
// bundle, so nothing has to reach a blocked host in the clear.
package routing

import (
	"net/url"
	"strings"
)

// Options is a routing preset expressed as independent toggles.
type Options struct {
	BypassIran   bool // Iran domestic domains/IPs go direct, not through the tunnel
	DirectLAN    bool // private/LAN ranges go direct
	BlockAds     bool // ads + trackers
	BlockMalware bool // malware + phishing
	BlockPorn    bool // adult content
	BlockQUIC    bool // drop UDP/443 so browsers fall back to TCP (helps some DPI)
}

// Enabled reports whether any rule would be emitted.
func (o Options) Enabled() bool {
	return o.BypassIran || o.DirectLAN || o.BlockAds || o.BlockMalware || o.BlockPorn || o.BlockQUIC
}

// Preset resolves a named preset. Unknown names (including "", "default") fall
// back to the sensible Iran default; "off"/"none" disables routing entirely.
func Preset(name string) Options {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "off", "none", "disabled", "0", "false":
		return Options{}
	case "full", "iran-full", "strict":
		return Options{BypassIran: true, DirectLAN: true, BlockAds: true, BlockMalware: true, BlockPorn: true, BlockQUIC: true}
	case "block", "secure":
		return Options{DirectLAN: true, BlockAds: true, BlockMalware: true}
	default: // "iran", "iran-lite", "default", ""
		return Options{BypassIran: true, DirectLAN: true, BlockAds: true, BlockMalware: true}
	}
}

// FromQuery builds Options from subscription query parameters. A named `routing`
// (or `preset`) parameter sets the base; individual `bypass_iran`, `direct_lan`,
// `block_ads`, `block_malware`, `block_porn`, `block_quic` flags then override
// (1/0/true/false/on/off). Absent everything, returns the given default preset.
func FromQuery(q url.Values, def string) Options {
	base := def
	if v := q.Get("routing"); v != "" {
		base = v
	} else if v := q.Get("preset"); v != "" {
		base = v
	}
	o := Preset(base)
	set := func(key string, field *bool) {
		if v := q.Get(key); v != "" {
			*field = truthy(v)
		}
	}
	set("bypass_iran", &o.BypassIran)
	set("direct_lan", &o.DirectLAN)
	set("block_ads", &o.BlockAds)
	set("block_malware", &o.BlockMalware)
	set("block_porn", &o.BlockPorn)
	set("block_quic", &o.BlockQUIC)
	return o
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes", "y":
		return true
	default:
		return false
	}
}

// --- Xray TLS fragment ----------------------------------------------------

// Fragment configures Xray's TLS-hello fragmentation — the DPI-evasion trick
// (BPB "Fragment") that splits the ClientHello into small pieces so a censor's
// SNI filter never sees a whole handshake. Xray-only; sing-box has no equivalent.
type Fragment struct {
	Enabled  bool
	Packets  string // which packets to split; "tlshello" splits only the TLS hello
	Length   string // per-piece byte range, e.g. "100-200"
	Interval string // ms between pieces, e.g. "10-20"
}

// FragmentFromQuery reads fragment settings from subscription query parameters:
// ?fragment=1 turns it on with sane defaults; fragment_packets / fragment_length
// / fragment_interval override them.
func FragmentFromQuery(q url.Values) Fragment {
	f := Fragment{Packets: "tlshello", Length: "100-200", Interval: "10-20"}
	f.Enabled = truthy(q.Get("fragment"))
	if v := q.Get("fragment_packets"); v != "" {
		f.Packets = v
	}
	if v := q.Get("fragment_length"); v != "" {
		f.Length = v
	}
	if v := q.Get("fragment_interval"); v != "" {
		f.Interval = v
	}
	return f
}

// Outbound returns the Xray "fragment" freedom outbound that performs the split.
// Proxy outbounds route through it via sockopt.dialerProxy = tag.
func (f Fragment) Outbound(tag string) map[string]any {
	return map[string]any{
		"tag": tag, "protocol": "freedom",
		"settings": map[string]any{
			"domainStrategy": "AsIs",
			"fragment": map[string]any{
				"packets": f.Packets, "length": f.Length, "interval": f.Interval,
			},
		},
		"streamSettings": map[string]any{"sockopt": map[string]any{"tcpNoDelay": true}},
	}
}

// --- sing-box -------------------------------------------------------------

// sing-box community rule-sets (binary .srs). Iran-maintained, widely used, and
// downloaded through the tunnel so a blocked GitHub is a non-issue.
const sbBase = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/"

type sbRuleSet struct{ tag, file string }

// Singbox returns (rules, ruleSets) to splice into a sing-box route block. rules
// go before the caller's final selector; ruleSets go in route.rule_set. Every
// remote set downloads through proxyTag so it works from a censored network.
func (o Options) Singbox(proxyTag, directTag string) (rules []any, ruleSets []any) {
	if o.DirectLAN {
		rules = append(rules, map[string]any{"ip_is_private": true, "outbound": directTag})
	}
	var used []sbRuleSet
	add := func(rs sbRuleSet, action map[string]any) {
		used = append(used, rs)
		rules = append(rules, action)
	}
	if o.BlockAds {
		add(sbRuleSet{"geosite-ads", "geosite-category-ads-all.srs"}, map[string]any{"rule_set": "geosite-ads", "action": "reject"})
	}
	if o.BlockMalware {
		add(sbRuleSet{"geosite-malware", "geosite-malware.srs"}, map[string]any{"rule_set": "geosite-malware", "action": "reject"})
		add(sbRuleSet{"geosite-phishing", "geosite-phishing.srs"}, map[string]any{"rule_set": "geosite-phishing", "action": "reject"})
	}
	if o.BlockPorn {
		add(sbRuleSet{"geosite-nsfw", "geosite-nsfw.srs"}, map[string]any{"rule_set": "geosite-nsfw", "action": "reject"})
	}
	if o.BlockQUIC {
		rules = append(rules, map[string]any{"network": "udp", "port": 443, "action": "reject"})
	}
	if o.BypassIran {
		add(sbRuleSet{"geoip-ir", "geoip-ir.srs"}, map[string]any{"rule_set": "geoip-ir", "outbound": directTag})
		add(sbRuleSet{"geosite-ir", "geosite-ir.srs"}, map[string]any{"rule_set": "geosite-ir", "outbound": directTag})
	}
	for _, rs := range used {
		ruleSets = append(ruleSets, map[string]any{
			"tag": rs.tag, "type": "remote", "format": "binary",
			"url": sbBase + rs.file, "download_detour": proxyTag,
		})
	}
	return rules, ruleSets
}

// --- Xray -----------------------------------------------------------------

// Xray returns routing rules for an Xray client config. It uses the geoip:/
// geosite: categories the clients bundle (geoip.dat/geosite.dat), so it needs no
// network fetch. Rules are ordered: direct exceptions, blocks, then the caller
// appends the catch-all proxy rule.
func (o Options) Xray(directTag, blockTag string) []any {
	var rules []any
	directIP := []string{}
	if o.DirectLAN {
		directIP = append(directIP, "geoip:private")
	}
	if o.BypassIran {
		directIP = append(directIP, "geoip:ir")
	}
	if len(directIP) > 0 {
		rules = append(rules, map[string]any{"type": "field", "ip": directIP, "outboundTag": directTag})
	}
	if o.BypassIran {
		rules = append(rules, map[string]any{"type": "field", "domain": []string{"geosite:category-ir"}, "outboundTag": directTag})
	}
	var blockDomains []string
	if o.BlockAds {
		blockDomains = append(blockDomains, "geosite:category-ads-all")
	}
	if o.BlockPorn {
		blockDomains = append(blockDomains, "geosite:category-porn")
	}
	if len(blockDomains) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": blockDomains, "outboundTag": blockTag})
	}
	if o.BlockQUIC {
		rules = append(rules, map[string]any{"type": "field", "network": "udp", "port": "443", "outboundTag": blockTag})
	}
	return rules
}

// XrayDomainStrategy is the strategy the preset needs: IP rules (geoip) only bite
// when the client resolves names, so any IP-based rule requires IPIfNonMatch.
func (o Options) XrayDomainStrategy() string {
	if o.BypassIran || o.DirectLAN {
		return "IPIfNonMatch"
	}
	return "AsIs"
}

// --- Clash-Meta -----------------------------------------------------------

const clashBase = "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/"

type clashProvider struct {
	tag, behavior, file string
}

// Clash returns (rules, ruleProviders). rules are Clash rule strings to place
// BEFORE the caller's final MATCH; ruleProviders is the rule-providers map. The
// caller decides the final target (usually the proxy selector).
func (o Options) Clash(proxyName string) (rules []string, providers map[string]any) {
	providers = map[string]any{}
	addProvider := func(p clashProvider) {
		providers[p.tag] = map[string]any{
			"type": "http", "behavior": p.behavior, "format": "yaml",
			"url": clashBase + p.file, "path": "./ruleset/" + p.tag + ".yaml",
			"interval": 86400,
		}
	}
	if o.DirectLAN {
		rules = append(rules, "GEOIP,private,DIRECT,no-resolve")
	}
	if o.BlockAds {
		addProvider(clashProvider{"ads", "domain", "ads.yaml"})
		rules = append(rules, "RULE-SET,ads,REJECT")
	}
	if o.BlockMalware {
		addProvider(clashProvider{"malware", "domain", "malware.yaml"})
		addProvider(clashProvider{"phishing", "domain", "phishing.yaml"})
		rules = append(rules, "RULE-SET,malware,REJECT", "RULE-SET,phishing,REJECT")
	}
	if o.BlockPorn {
		addProvider(clashProvider{"porn", "domain", "porn.yaml"})
		rules = append(rules, "RULE-SET,porn,REJECT")
	}
	if o.BlockQUIC {
		rules = append(rules, "AND,((NETWORK,udp),(DST-PORT,443)),REJECT")
	}
	if o.BypassIran {
		addProvider(clashProvider{"ir-domains", "domain", "ir.yaml"})
		rules = append(rules, "RULE-SET,ir-domains,DIRECT", "GEOIP,ir,DIRECT,no-resolve")
	}
	if len(providers) == 0 {
		providers = nil
	}
	return rules, providers
}
