package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
)

// subRoutingPreset is the operator's default routing preset for generated
// sing-box/Xray/Clash configs. Defaults to the Iran preset (bypass Iran + direct
// LAN + block ads/malware); a per-request ?routing= overrides it. Stored under
// the "sub_routing_preset" setting so an operator can change or disable it.
func (s *Server) subRoutingPreset() string {
	if s.db == nil {
		return "iran"
	}
	if v := s.db.GetSetting("sub_routing_preset"); v != "" {
		return v
	}
	return "iran"
}

// subFragmentDefault reports whether generated Xray subscriptions fragment the
// TLS hello by default (operator setting; per-request ?fragment= overrides it).
func (s *Server) subFragmentDefault() bool {
	return s.db != nil && s.db.GetSetting("sub_fragment_default") == "1"
}

// subNameTemplate is the operator's node-naming template, e.g. "{FLAG} {NAME}".
// Empty (the default) means "leave each node's own remark untouched", so the
// feature is strictly opt-in and changes nothing until a template is set.
func (s *Server) subNameTemplate() string {
	if s.db == nil {
		return ""
	}
	return s.db.GetSetting("sub_name_template")
}

// subPatternDefault is the operator's default for the unsafe-uTLS "pattern"
// variant on link/v2ray subscriptions (per-request ?patt= overrides it).
func (s *Server) subPatternDefault() patternMode {
	if s.db == nil {
		return patternOff
	}
	return parsePatternMode(s.db.GetSetting("sub_pattern_default"), patternOff)
}

// subFrontDomain is the fancy wizard's fronting/camouflage domain applied to
// every node in the subscription. Empty means no fronting.
func (s *Server) subFrontDomain() string {
	if s.db == nil {
		return ""
	}
	return strings.TrimSpace(s.db.GetSetting("sub_front_domain"))
}

// subFrontMode is how subFrontDomain is applied (none | sni | cdn).
func (s *Server) subFrontMode() model.FrontMode {
	if s.db == nil {
		return model.FrontNone
	}
	return model.ParseFrontMode(s.db.GetSetting("sub_front_mode"))
}

// subExpandSNI fans a REALITY inbound out into one config per borrowed SNI.
// Default ON — it is the whole point of listing several SNIs on an inbound.
func (s *Server) subExpandSNI() bool {
	if s.db == nil {
		return true
	}
	return s.db.GetSetting("sub_expand_sni") != "0"
}

// subFrontCleanIP fans a CDN-frontable inbound out across the clean-IP list.
// Default OFF — it only helps once the operator has a clean-IP list set.
func (s *Server) subFrontCleanIP() bool {
	if s.db == nil {
		return false
	}
	return s.db.GetSetting("sub_front_cleanip") == "1"
}

// subCleanIPs is the operator's comma/space/newline-separated list of clean
// Cloudflare edge IPs (or hostnames) used for CDN IP fan-out.
func (s *Server) subCleanIPs() []string {
	if s.db == nil {
		return nil
	}
	raw := s.db.GetSetting("sub_clean_ips")
	if raw == "" {
		return nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// patternSettingString maps a mode back to its stored form.
func patternSettingString(m patternMode) string {
	switch m {
	case patternOnly:
		return "only"
	case patternBoth:
		return "both"
	default:
		return "off"
	}
}

// handleGetSubSettings returns the operator's subscription defaults (routing
// preset + fragment) and the selectable presets for the UI.
func (s *Server) handleGetSubSettings(c *gin.Context) {
	c.JSON(200, gin.H{
		"routing_preset": s.subRoutingPreset(),
		"fragment":       s.subFragmentDefault(),
		"presets":        []string{"iran", "full", "block", "off"},
		"name_template":  s.subNameTemplate(),
		"name_tokens":    []string{"{FLAG}", "{COUNTRY}", "{NAME}", "{PROTOCOL}", "{NET}", "{TLS}", "{PORT}", "{HOST}", "{USER}", "{NUM}", "{DATE}"},
		"pattern":        patternSettingString(s.subPatternDefault()),
		"pattern_modes":  []string{"off", "only", "both"},
		// Fancy-config wizard: the fronting domain + model + the styled theme
		// catalogue the UI offers.
		"front_domain": s.subFrontDomain(),
		"front_mode":   string(s.subFrontMode()),
		"front_modes":  []string{"none", "sni", "cdn"},
		"fancy_themes": model.FancyThemes(),
	})
}

// handleSetSubSettings persists the subscription defaults.
func (s *Server) handleSetSubSettings(c *gin.Context) {
	var req struct {
		RoutingPreset *string `json:"routing_preset"`
		Fragment      *bool   `json:"fragment"`
		NameTemplate  *string `json:"name_template"`
		Pattern       *string `json:"pattern"`
		FrontDomain   *string `json:"front_domain"`
		FrontMode     *string `json:"front_mode"`
		// FancyTheme applies a styled preset: it sets name_template to the
		// theme's template and front_mode to the theme's fronting model in one
		// step, so the wizard is a single click plus a domain.
		FancyTheme *string `json:"fancy_theme"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	if s.db == nil {
		c.JSON(501, gin.H{"error": "no store"})
		return
	}
	if req.RoutingPreset != nil {
		_ = s.db.SetSetting("sub_routing_preset", strings.ToLower(strings.TrimSpace(*req.RoutingPreset)))
	}
	if req.Fragment != nil {
		v := "0"
		if *req.Fragment {
			v = "1"
		}
		_ = s.db.SetSetting("sub_fragment_default", v)
	}
	if req.NameTemplate != nil {
		_ = s.db.SetSetting("sub_name_template", strings.TrimSpace(*req.NameTemplate))
	}
	if req.Pattern != nil {
		_ = s.db.SetSetting("sub_pattern_default", patternSettingString(parsePatternMode(*req.Pattern, patternOff)))
	}
	// Applying a theme wins over a raw name_template/front_mode in the same
	// request, since it is the higher-level intent.
	if req.FancyTheme != nil {
		id := strings.TrimSpace(*req.FancyTheme)
		if id == "" {
			// An explicit empty theme clears fancy naming back to plain remarks.
			_ = s.db.SetSetting("sub_name_template", "")
			_ = s.db.SetSetting("sub_front_mode", string(model.FrontNone))
		} else if th, ok := model.FancyThemeByID(id); ok {
			_ = s.db.SetSetting("sub_name_template", th.Template)
			_ = s.db.SetSetting("sub_front_mode", string(th.Front))
		} else {
			c.JSON(400, gin.H{"error": "unknown fancy theme: " + id})
			return
		}
	}
	if req.FrontDomain != nil {
		_ = s.db.SetSetting("sub_front_domain", strings.TrimSpace(*req.FrontDomain))
	}
	if req.FrontMode != nil {
		_ = s.db.SetSetting("sub_front_mode", string(model.ParseFrontMode(*req.FrontMode)))
	}
	s.audit(c, "settings.subscription.update", s.subRoutingPreset())
	c.JSON(200, gin.H{"ok": true, "routing_preset": s.subRoutingPreset(), "fragment": s.subFragmentDefault(),
		"name_template": s.subNameTemplate(), "front_domain": s.subFrontDomain(), "front_mode": string(s.subFrontMode())})
}

// subFormats are the subscription formats this endpoint can render, listed for
// the error message when a client asks for something else.
var subFormats = []string{"v2ray", "clash", "clash-meta", "sing-box", "xray", "surge", "loon", "quantumultx", "links", "json"}

// canonicalSubFormat maps a requested format (and its aliases) to the single
// name the renderer switch uses. It returns "" for anything unsupported, so an
// explicit request for a format we do not have becomes a clear error instead of
// silently returning a different one the client cannot parse.
//
// Shadowrocket is a true alias of the base64 link list — that is exactly what it
// imports — so it maps to "v2ray" rather than pretending to be a distinct
// renderer.
func canonicalSubFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "v2ray", "v2rayn", "v2rayng", "base64", "shadowrocket":
		return "v2ray"
	case "clash", "clash-meta", "clashmeta", "mihomo":
		return "clash"
	case "sing-box", "singbox", "sb":
		return "sing-box"
	case "xray", "xray-json", "v2ray-json":
		return "xray"
	case "surge":
		return "surge"
	case "loon":
		return "loon"
	case "quantumultx", "quantumult", "qx":
		return "quantumultx"
	case "links", "raw", "uri", "plain":
		return "links"
	case "json":
		return "json"
	default:
		return ""
	}
}

// handleSub serves a subscription (spec §9). Format is chosen by explicit
// suffix (/clash, /sing-box, /links, /json) or, absent that, auto-detected from
// the User-Agent. Correct subscription headers are always emitted.
func (s *Server) handleSub(c *gin.Context) {
	// This response is per-subscriber, and its body varies on the User-Agent
	// while the URL stays constant. Without both headers an intermediate cache
	// could serve one subscriber's config — their credentials — to another, or
	// hand a sing-box client the body rendered for a Clash client. Set them
	// first so they are present on every path out of here, errors included.
	c.Header("Vary", "User-Agent")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Header("Pragma", "no-cache")

	// Subscription tokens are bearer credentials on an unauthenticated endpoint,
	// so blind guessing is throttled per source. Valid subscribers are unaffected:
	// only failed lookups count against the budget.
	ip := c.ClientIP()
	if s.subs != nil && !s.subs.Allowed(ip) {
		c.String(http.StatusTooManyRequests, "too many subscription lookups; try again shortly")
		return
	}

	// Resolve the format before doing any work, so an unsupported explicit
	// request fails cleanly rather than rendering something else.
	explicit := strings.Trim(c.Param("format"), "/")

	// A human opening the bare subscription URL in a browser gets a friendly
	// landing page (per-client import buttons + copy links) instead of a wall of
	// base64. Proxy clients are never affected: this needs a browser User-Agent,
	// an explicit text/html Accept, and no known client token. ?raw=1 opts out.
	if explicit == "" && c.Query("raw") == "" &&
		isBrowserSubRequest(c.GetHeader("User-Agent"), c.GetHeader("Accept")) {
		token := c.Param("token")
		base := hostSubBase(c)
		c.Header("Subscription-Userinfo", s.subscriptionUserinfo(token))
		c.Data(200, "text/html; charset=utf-8", subLandingPage(base, s.subscriptionUserinfo(token)))
		return
	}

	requested := explicit
	if requested == "" {
		// Explicit path/query always wins; sniffing is only the fallback.
		requested = detectFormat(c.GetHeader("User-Agent"))
	}
	format := canonicalSubFormat(requested)
	if format == "" {
		c.String(http.StatusNotFound, "unsupported subscription format %q; supported: %s",
			explicit, strings.Join(subFormats, ", "))
		return
	}

	token := c.Param("token")
	nodes := s.subscriptionNodes(token, hostOnly(c.Request.Host))
	if nodes == nil {
		// Unknown token: return an empty but valid subscription rather than
		// leaking which tokens exist — but charge it against the guess budget.
		if s.subs != nil {
			s.subs.Fail(ip)
		}
		nodes = []*model.Node{}
	} else if s.subs != nil {
		s.subs.Success(ip)
	}

	// Never hand a subscriber material only the server should hold (REALITY/TLS/
	// WireGuard server private keys). Redact once, up front, so every format below
	// is safe; client-side fields are preserved so configs still work.
	nodes = redactNodesForClient(nodes)

	c.Header("Profile-Update-Interval", "12")
	// Real usage/quota/expiry from the DB, not a hardcoded zero line. Clients
	// render this as "X of Y used, expires Z"; emitting all-zeros told every user
	// they had unlimited quota and no expiry regardless of their account.
	c.Header("Subscription-Userinfo", s.subscriptionUserinfo(token))
	c.Header("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("ForgePanel")))
	c.Header("Access-Control-Allow-Origin", "*")

	// Routing preset for the runnable config formats (sing-box/Xray/Clash): the
	// operator default, overridable per request with ?routing= (and fine-grained
	// block_ads / bypass_iran / … flags).
	route := routing.FromQuery(c.Request.URL.Query(), s.subRoutingPreset())
	frag := routing.FragmentFromQuery(c.Request.URL.Query())
	if _, explicit := c.Request.URL.Query()["fragment"]; !explicit {
		frag.Enabled = s.subFragmentDefault()
	}
	// The unsafe-uTLS "pattern" variant for the link/v2ray formats.
	pmode := parsePatternMode(c.Query("patt"), s.subPatternDefault())

	switch format {
	case "clash":
		y, err := export.ClashYAML(nodes)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.Data(200, "text/yaml; charset=utf-8", []byte(clashWithRouting(y, route)))
	case "links":
		c.Data(200, "text/plain; charset=utf-8", []byte(plainLinksMode(nodes, pmode)))
	case "json":
		c.JSON(200, nodes)
	case "sing-box":
		c.Data(200, "application/json; charset=utf-8", singboxSubscription(nodes, route))
	case "xray":
		c.Data(200, "application/json; charset=utf-8", xraySubscription(nodes, route, frag))
	case "surge":
		c.Data(200, "text/plain; charset=utf-8", surgeSubscription(nodes))
	case "loon":
		c.Data(200, "text/plain; charset=utf-8", loonSubscription(nodes))
	case "quantumultx":
		c.Data(200, "text/plain; charset=utf-8", quantumultxSubscription(nodes))
	default: // v2ray/base64 subscription (also Shadowrocket)
		b64 := base64.StdEncoding.EncodeToString([]byte(plainLinksMode(nodes, pmode)))
		c.Data(200, "text/plain; charset=utf-8", []byte(b64))
	}
}

// subscriptionUserinfo builds the SIP008-style Subscription-Userinfo header from
// the user's real DB record. ForgePanel accounts a single combined byte total,
// so it is reported under download with upload=0; total is the data limit (0 =
// unlimited, which clients show as no cap); expire is the unix expiry (0 = never).
func (s *Server) subscriptionUserinfo(token string) string {
	if s.db == nil {
		return "upload=0; download=0; total=0; expire=0"
	}
	u, err := s.db.UserBySubToken(token)
	if err != nil {
		return "upload=0; download=0; total=0; expire=0"
	}
	var expire int64
	if u.ExpireAt != nil {
		expire = u.ExpireAt.Unix()
	}
	return fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d",
		u.UsedTraffic, u.DataLimit, expire)
}

// xraySubscription renders a complete, runnable Xray CLIENT config: a local
// SOCKS+HTTP inbound, the per-node outbounds (canonical render.XrayOutbound),
// plus freedom/blackhole, and a routing block selecting the first proxy. Some
// clients (v2rayN and others) import a raw Xray JSON directly; this is that, and
// it is accepted by `xray run -test`. Tags are de-duplicated the same way the
// sing-box builder reserves its own, so no two outbounds collide.
func xraySubscription(nodes []*model.Node, route routing.Options, frag routing.Fragment) []byte {
	const (
		xrayDirectTag   = "direct"
		xrayBlockTag    = "block"
		xrayFragmentTag = "fragment"
	)
	outs := make([]any, 0, len(nodes)+3)
	seen := map[string]int{xrayDirectTag: 1, xrayBlockTag: 1, xrayFragmentTag: 1}
	var proxyTags []string
	var proxyOuts []map[string]any
	for i, n := range nodes {
		o, err := render.XrayOutbound(n)
		if err != nil {
			continue
		}
		tag, _ := o["tag"].(string)
		if tag == "" {
			tag = fmt.Sprintf("proxy-%d", i)
		}
		if k, dup := seen[tag]; dup {
			seen[tag] = k + 1
			tag = fmt.Sprintf("%s-%d", tag, k+1)
		} else {
			seen[tag] = 1
		}
		o["tag"] = tag
		proxyTags = append(proxyTags, tag)
		proxyOuts = append(proxyOuts, o)
		outs = append(outs, o)
	}
	// TLS fragmentation (DPI evasion): route every proxy outbound's TCP dial
	// through a freedom "fragment" outbound that splits the TLS hello.
	if frag.Enabled && len(proxyOuts) > 0 {
		for _, o := range proxyOuts {
			ss, _ := o["streamSettings"].(map[string]any)
			if ss == nil {
				ss = map[string]any{}
				o["streamSettings"] = ss
			}
			sock, _ := ss["sockopt"].(map[string]any)
			if sock == nil {
				sock = map[string]any{}
				ss["sockopt"] = sock
			}
			sock["dialerProxy"] = xrayFragmentTag
		}
		outs = append(outs, frag.Outbound(xrayFragmentTag))
	}
	outs = append(outs,
		map[string]any{"protocol": "freedom", "tag": xrayDirectTag},
		map[string]any{"protocol": "blackhole", "tag": xrayBlockTag},
	)
	// Preset rules (direct-Iran/LAN, block ads/porn/QUIC) come first, then the
	// catch-all that sends everything else through the first proxy.
	rules := []any{}
	strategy := "AsIs"
	if route.Enabled() {
		rules = append(rules, route.Xray(xrayDirectTag, xrayBlockTag)...)
		strategy = route.XrayDomainStrategy()
	}
	if len(proxyTags) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "outboundTag": proxyTags[0], "network": "tcp,udp",
		})
	}
	socks := map[string]any{
		"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
		"settings": map[string]any{"udp": true, "auth": "noauth"},
	}
	if route.Enabled() {
		// Domain-based routing rules need the destination host; sniff it off the
		// forwarded connection so geosite matching works.
		socks["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}
	}
	doc := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{socks, map[string]any{"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"}},
		"outbounds": outs,
		"routing":   map[string]any{"domainStrategy": strategy, "rules": rules},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

// singboxSubscription renders a minimal, valid sing-box CLIENT config whose
// outbounds are the canonical per-node renderings (render.SingboxOutbound), so a
// sing-box client receives real sing-box JSON instead of the base64 V2Ray list.
//
// sing-box rejects a config with two outbounds sharing a tag ("duplicate
// outbound/endpoint tag"). Per-node renderings all default their tag to "proxy"
// (render.SingboxOutbound), and this function additionally emits a "selector"
// outbound tagged "proxy" and a "direct" outbound tagged "direct". So the
// reserved tags "proxy" and "direct" are seeded into the dedup set BEFORE the
// nodes are numbered: without that, the first node keeps "proxy" and collides
// with the selector, and the whole subscription is refused by the core. The
// selector therefore always owns "proxy" and node tags fall out as
// proxy-2, proxy-3, …
const (
	sbSelectorTag = "proxy"
	sbDirectTag   = "direct"
)

func singboxSubscription(nodes []*model.Node, route routing.Options) []byte {
	outs := make([]any, 0, len(nodes)+2)
	// Pre-reserve the tags this function emits itself, so no node can claim them.
	seen := map[string]int{sbSelectorTag: 1, sbDirectTag: 1}
	var tags []string
	for i, n := range nodes {
		o, err := render.SingboxOutbound(n)
		if err != nil {
			continue
		}
		tag, _ := o["tag"].(string)
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		if k, dup := seen[tag]; dup {
			seen[tag] = k + 1
			tag = fmt.Sprintf("%s-%d", tag, k+1)
		} else {
			seen[tag] = 1
		}
		o["tag"] = tag
		tags = append(tags, tag)
		if n.Protocol == model.ProtoShadowTLS && n.ShadowTLS != nil {
			// ShadowTLS is pure TLS camouflage: on its own it carries no proxy
			// bytes. The sing-box client needs a two-outbound chain — an inner
			// Shadowsocks outbound that tunnels THROUGH the shadowtls outbound via
			// `detour`. Rewrite the rendered shadowtls to be the detour target and
			// make the Shadowsocks entry the tag the selector points at.
			stlsTag := tag + "-stls"
			o["tag"] = stlsTag
			ss := map[string]any{
				"type": "shadowsocks", "tag": tag,
				"method": n.ShadowTLS.InnerMethod, "password": n.ShadowTLS.InnerPassword,
				"detour": stlsTag,
			}
			outs = append(outs, ss, o)
			continue
		}
		outs = append(outs, o)
	}
	final := sbDirectTag
	if len(tags) > 0 {
		outs = append(outs, map[string]any{"type": "selector", "tag": sbSelectorTag, "outbounds": append(append([]string{}, tags...), sbDirectTag), "default": tags[0]})
		final = sbSelectorTag
	}
	outs = append(outs, map[string]any{"type": "direct", "tag": sbDirectTag})
	// A subscription must be runnable as delivered: ship a local mixed
	// (socks+http) inbound and a route whose final hop is the node selector, so
	// `sing-box run -c <sub>` actually forwards traffic — matching the xray
	// format's socks/http inbounds. Without an inbound the config parses but can
	// carry nothing.
	routeBlock := map[string]any{"final": final}
	if route.Enabled() {
		// Direct/block preset rules come before the implicit final selector; every
		// remote rule-set downloads through the proxy so a censored GitHub is fine.
		rules, ruleSets := route.Singbox(final, sbDirectTag)
		if len(rules) > 0 {
			routeBlock["rules"] = rules
		}
		if len(ruleSets) > 0 {
			routeBlock["rule_set"] = ruleSets
		}
	}
	doc := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{
			map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 10808},
		},
		"outbounds": outs,
		"route":     routeBlock,
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

// clashWithRouting splices a routing preset into a Clash-Meta document produced
// by export.ClashYAML. The base ends with `rules:` / `  - MATCH,PROXY`; the
// preset's rules are inserted immediately before that catch-all, and a
// rule-providers block is prepended (a top-level key Clash accepts anywhere). It
// works at the text level so the canonical Clash exporter stays untouched.
func clashWithRouting(base string, route routing.Options) string {
	if !route.Enabled() {
		return base
	}
	rules, providers := route.Clash(export.ClashProxySelector)
	// The exporter quotes list scalars (commas), so the catch-all is `  - "MATCH,PROXY"`.
	match := "  - \"MATCH," + export.ClashProxySelector + "\""
	if !strings.Contains(base, match) {
		return base // formatting changed unexpectedly — never emit a broken doc
	}
	var inject strings.Builder
	for _, r := range rules {
		inject.WriteString("  - \"" + r + "\"\n")
	}
	out := strings.Replace(base, match, inject.String()+match, 1)

	if len(providers) == 0 {
		return out
	}
	var head strings.Builder
	head.WriteString("rule-providers:\n")
	for tag, p := range providers {
		m, _ := p.(map[string]any)
		head.WriteString("  " + tag + ":\n")
		for _, k := range []string{"type", "behavior", "format", "url", "path", "interval"} {
			switch k {
			case "url", "path":
				head.WriteString(fmt.Sprintf("    %s: %q\n", k, m[k]))
			default:
				head.WriteString(fmt.Sprintf("    %s: %v\n", k, m[k]))
			}
		}
	}
	return head.String() + out
}

// redactNodesForClient returns copies of the nodes with server-only secrets
// blanked. Client-facing fields (public keys, shortIDs, the client's own peer
// private key) are kept so links/clash/sing-box/json all still produce working
// configs. Operates on deep copies — the stored config is never mutated.
func redactNodesForClient(nodes []*model.Node) []*model.Node {
	out := make([]*model.Node, 0, len(nodes))
	for _, n := range nodes {
		c := n.Clone()
		if c.Security.Reality != nil {
			c.Security.Reality.PrivateKey = ""
		}
		c.Security.KeyFile = "" // path to the server's TLS private key
		if c.WireGuard != nil {
			c.WireGuard.PrivateKey = "" // the server's WG key; clients use PeerPrivateKey
		}
		out = append(out, c)
	}
	return out
}

func plainLinks(nodes []*model.Node) string { return plainLinksMode(nodes, patternOff) }

// plainLinksMode renders the newline-separated share links, optionally adding the
// unsafe-uTLS "pattern" variant (patt-only, or both normal + patterned).
func plainLinksMode(nodes []*model.Node, mode patternMode) string {
	var b strings.Builder
	for _, n := range nodes {
		uri, err := export.URI(n)
		if err != nil {
			continue
		}
		switch mode {
		case patternOnly:
			b.WriteString(applyPattern(uri))
			b.WriteByte('\n')
		case patternBoth:
			b.WriteString(uri)
			b.WriteByte('\n')
			if p := applyPattern(uri); p != uri {
				b.WriteString(tagRemark(p))
				b.WriteByte('\n')
			}
		default:
			b.WriteString(uri)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// detectFormat maps a client User-Agent to a subscription format (spec §9).
func detectFormat(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "clash"):
		return "clash"
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox"):
		return "sing-box"
	case strings.Contains(ua, "v2rayng") || strings.Contains(ua, "v2ray") || strings.Contains(ua, "nekobox") || strings.Contains(ua, "shadowrocket"):
		return "v2ray"
	default:
		return "v2ray"
	}
}

// fallbackStudio is served if the embedded studio.html asset is missing. The
// real, polished Config Studio lives in web/studio.html.
const fallbackStudio = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ForgePanel</title>
<style>body{background:#0b0f17;color:#e5e7eb;font-family:system-ui;margin:0;padding:2rem}
a{color:#7dd3fc}code{background:#111827;padding:.2em .4em;border-radius:4px}</style></head>
<body><h1>⚡ ForgePanel</h1>
<p>The Config Studio asset was not embedded in this build. The API is live:</p>
<ul><li><code>GET /api/protocols</code></li><li><code>POST /api/studio/preview</code></li>
<li><code>POST /api/keygen</code></li><li><code>GET /sub/:token</code></li></ul>
</body></html>`
