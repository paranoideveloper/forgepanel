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
	"fmt"
	"net/url"
	"strconv"
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

// --- TLS ClientHello fragment ---------------------------------------------

// Fragment configures TLS-hello fragmentation — the DPI-evasion trick (BPB
// "Fragment") that splits the ClientHello into small pieces so a censor's SNI
// filter never sees a whole handshake.
//
// Two cores can express it and they express it differently: Xray dials every
// proxy through a freedom outbound that does the splitting (Outbound below),
// sing-box has a native tls.record_fragment flag (ApplySingbox). Clash-Meta has
// no fragment primitive at all, which is why FragmentCores lists two names and
// not three — an operator who asks for it on Clash is told, not ignored.
//
// Cores is a comma-joined string rather than a []string on purpose: Fragment is
// compared with == (in tests and in "is this the zero value?" checks), and a
// slice field would make the struct non-comparable.
type Fragment struct {
	Enabled  bool
	Level    string // severity preset name: light | medium | aggressive ("" = medium)
	Cores    string // cores that honour it; empty means every core that can
	Packets  string // which packets to split; "tlshello" splits only the TLS hello
	Length   string // per-piece byte range, e.g. "100-200"
	Interval string // ms between pieces, e.g. "10-20"
}

// FragmentCores are the cores whose config format can carry fragmentation.
// Clash-Meta is deliberately absent: mihomo has no equivalent, so listing it
// would promise something no generated Clash config could deliver.
func FragmentCores() []string { return []string{"xray", "sing-box"} }

// fragmentPackets are the only packet selectors Xray's freedom fragment accepts.
var fragmentPackets = []string{"tlshello", "1-1", "1-2", "1-3", "1-5"}

// FragmentPreset resolves a severity level, mirroring Preset: unknown names
// (including "" and "default") fall back to the middle setting, and
// "off"/"none" is the zero Fragment.
//
// medium is byte-identical to the values this package hardcoded before levels
// existed, so an operator who never touches the new knob keeps exactly the
// subscription they already had.
func FragmentPreset(name string) Fragment {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "off", "none", "disabled", "0", "false":
		return Fragment{}
	case "light":
		// Big slices, short gaps: cheapest to the handshake, enough to break a
		// censor that only pattern-matches a contiguous SNI.
		return Fragment{Level: "light", Packets: "tlshello", Length: "40-100", Interval: "5-10"}
	case "aggressive":
		// Splits the first packets outright, into small pieces, with long gaps.
		// Costs handshake latency and trips some middleboxes; it is the setting
		// that still works when the lighter ones have stopped.
		return Fragment{Level: "aggressive", Packets: "1-3", Length: "10-40", Interval: "20-40"}
	default: // "medium", "default", ""
		return Fragment{Level: "medium", Packets: "tlshello", Length: "100-200", Interval: "10-20"}
	}
}

// Validate reports whether these values are ones a core will actually start
// with. Nothing checked them before: ?fragment_length=abc went straight into the
// emitted JSON and the subscriber got a config that would not run, with no clue
// where it came from.
func (f Fragment) Validate() error {
	if !containsFold(fragmentPackets, f.Packets) {
		return fmt.Errorf("fragment packets %q is not one of: %s", f.Packets, strings.Join(fragmentPackets, ", "))
	}
	if err := validFragmentRange("length", f.Length); err != nil {
		return err
	}
	return validFragmentRange("interval", f.Interval)
}

// validFragmentRange accepts "N" or "N-M" (M >= N), the form both cores expect.
func validFragmentRange(field, v string) error {
	v = strings.TrimSpace(v)
	lo, hi, found := strings.Cut(v, "-")
	n, err := strconv.Atoi(lo)
	if err != nil || n < 0 {
		return fmt.Errorf("fragment %s %q is not a number or a number range", field, v)
	}
	if !found {
		return nil
	}
	m, err := strconv.Atoi(hi)
	if err != nil || m < n {
		return fmt.Errorf("fragment %s %q is not a number or a number range", field, v)
	}
	return nil
}

// CoreEnabled reports whether this core should fragment.
//
// An EMPTY Cores means every capable core, not none: a bare
// Fragment{Enabled: true, …} literal — which is what a per-request ?fragment=1
// and every caller predating the per-core matrix produces — must keep working.
func (f Fragment) CoreEnabled(core string) bool {
	if strings.TrimSpace(f.Cores) == "" {
		return true
	}
	want := canonicalCore(core)
	for _, c := range strings.Split(f.Cores, ",") {
		if canonicalCore(c) == want {
			return true
		}
	}
	return false
}

// canonicalCore folds the spellings an operator plausibly types ("sing-box",
// "singbox", "Sing-Box") onto one name.
func canonicalCore(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "")
}

func containsFold(list []string, v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// FragmentFromQuery reads fragment settings from subscription query parameters,
// starting from the operator's default: ?fragment=1/0 turns it on or off,
// ?fragment_level= picks a severity preset, and fragment_packets /
// fragment_length / fragment_interval tune it further.
//
// An individual override that would not validate is DROPPED rather than emitted.
// A subscriber who mistypes a length gets the operator's working config, not a
// config the core refuses to start.
func FragmentFromQuery(q url.Values, def Fragment) Fragment {
	f := def
	if v := q.Get("fragment_level"); v != "" {
		if lvl := FragmentPreset(v); lvl.Level == "" {
			// "off" is one of the names FragmentPreset answers, and it answers
			// with the zero Fragment. Carrying Enabled onto that would leave
			// fragmentation on with three empty strings in it, which is an
			// outbound the core refuses — so it flips the switch instead.
			f.Enabled = false
		} else {
			// A per-request severity picks how hard to fragment, never which
			// cores do it — that stays the operator's decision.
			lvl.Enabled, lvl.Cores = f.Enabled, f.Cores
			f = lvl
		}
	}
	if v := q.Get("fragment"); v != "" {
		f.Enabled = truthy(v)
	}
	if v := q.Get("fragment_packets"); v != "" && containsFold(fragmentPackets, v) {
		f.Packets = strings.ToLower(strings.TrimSpace(v))
	}
	if v := q.Get("fragment_length"); v != "" && validFragmentRange("length", v) == nil {
		f.Length = strings.TrimSpace(v)
	}
	if v := q.Get("fragment_interval"); v != "" && validFragmentRange("interval", v) == nil {
		f.Interval = strings.TrimSpace(v)
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

// ApplySingbox marks every TLS-carrying outbound in a sing-box document for
// record fragmentation. sing-box does this natively — there is no detour
// outbound to build, only a flag on the tls object — so an outbound without one
// (selector, direct, plain Shadowsocks) is skipped rather than wrapped.
//
// record_fragment is a BOOL: sing-box takes no packet/length/interval, so the
// severity level reaches Xray only. It still decides whether sing-box fragments
// at all, because "off" is one of the levels.
//
// outs is []any because that is the type of the outbound slice the subscription
// builder assembles.
func (f Fragment) ApplySingbox(outs []any) {
	for _, o := range outs {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		tls, ok := m["tls"].(map[string]any)
		if !ok || tls == nil {
			continue
		}
		tls["record_fragment"] = true
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
