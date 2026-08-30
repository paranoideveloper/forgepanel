package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The subscription renderer's operator defaults. Each one is a key in the
// settings registry (internal/settings/defs.go), which owns its type, its
// default and — for the three enums — the values it will accept. These
// accessors used to carry a copy of the default in each of two branches, and
// nothing tied either copy to the list the UI offered or to what a write would
// be allowed to store.
//
// s.knobs is nil in the stateless constructor and every one of these still
// answers the registered default, which is what the old `if s.db == nil` arms
// returned.

// subRoutingPreset is the default routing preset baked into generated
// sing-box/Xray/Clash configs; a per-request ?routing= overrides it.
func (s *Server) subRoutingPreset() string { return s.knobs().String("sub_routing_preset") }

// subFragmentDefault reports whether generated Xray subscriptions fragment the
// TLS hello by default (per-request ?fragment= overrides it).
func (s *Server) subFragmentDefault() bool { return s.knobs().Bool("sub_fragment_default") }

// subFragmentLevel is the severity preset (light|medium|aggressive) the
// fragment toggle applies; a per-request ?fragment_level= overrides it.
func (s *Server) subFragmentLevel() string { return s.knobs().String("sub_fragment_level") }

// subFragmentCores is the set of cores that honour the toggle. Clash-Meta is not
// a legal entry: it has no fragment primitive to honour.
func (s *Server) subFragmentCores() []string { return s.knobs().List("sub_fragment_cores") }

// fragmentDefaults is the operator's fragment configuration as one value, the
// base every subscription request starts from before its own query parameters
// are applied.
func (s *Server) fragmentDefaults() routing.Fragment {
	f := routing.FragmentPreset(s.subFragmentLevel())
	f.Enabled = s.subFragmentDefault()
	f.Cores = strings.Join(s.subFragmentCores(), ",")
	return f
}

// subNameTemplate is the operator's node-naming template, e.g. "{FLAG} {NAME}".
// Empty (the default) means "leave each node's own remark untouched", so the
// feature is strictly opt-in and changes nothing until a template is set.
func (s *Server) subNameTemplate() string { return s.knobs().String("sub_name_template") }

// subPatternDefault is the operator's default for the unsafe-uTLS "pattern"
// variant on link/v2ray subscriptions (per-request ?patt= overrides it).
func (s *Server) subPatternDefault() patternMode {
	return parsePatternMode(s.knobs().String("sub_pattern_default"), patternOff)
}

// subFrontDomain is the fancy wizard's fronting/camouflage domain applied to
// every node in the subscription. Empty means no fronting.
func (s *Server) subFrontDomain() string { return s.knobs().String("sub_front_domain") }

// subFrontMode is how subFrontDomain is applied (none | sni | cdn).
func (s *Server) subFrontMode() model.FrontMode {
	return model.ParseFrontMode(s.knobs().String("sub_front_mode"))
}

// subExpandSNI fans a REALITY inbound out into one config per borrowed SNI.
// Default ON — it is the whole point of listing several SNIs on an inbound.
func (s *Server) subExpandSNI() bool { return s.knobs().Bool("sub_expand_sni") }

// subFrontCleanIP fans a CDN-frontable inbound out across the clean-IP list.
// Default OFF — it only helps once the operator has a clean-IP list set.
func (s *Server) subFrontCleanIP() bool { return s.knobs().Bool("sub_front_cleanip") }

// subCleanIPs is the operator's list of clean Cloudflare edge IPs (or
// hostnames) used for CDN IP fan-out.
func (s *Server) subCleanIPs() []string { return s.knobs().List("sub_clean_ips") }

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
		// Fragmentation is three decisions, not one: whether, how hard, and on
		// which cores. The supported-core list is served rather than hardcoded in
		// the UI so the panel can never offer a core the renderer ignores.
		"fragment_level":           s.subFragmentLevel(),
		"fragment_levels":          settings.Choices("sub_fragment_level"),
		"fragment_cores":           strings.Join(s.subFragmentCores(), ", "),
		"fragment_cores_supported": routing.FragmentCores(),
		"presets":                  settings.Choices("sub_routing_preset"),
		"name_template":            s.subNameTemplate(),
		"name_tokens":              []string{"{FLAG}", "{COUNTRY}", "{NAME}", "{PROTOCOL}", "{NET}", "{TLS}", "{PORT}", "{HOST}", "{USER}", "{NUM}", "{DATE}"},
		"pattern":                  patternSettingString(s.subPatternDefault()),
		"pattern_modes":            settings.Choices("sub_pattern_default"),
		// Fancy-config wizard: the fronting domain + model + the styled theme
		// catalogue the UI offers.
		"front_domain": s.subFrontDomain(),
		"front_mode":   string(s.subFrontMode()),
		"front_modes":  settings.Choices("sub_front_mode"),
		"fancy_themes": model.FancyThemes(),
		// The formats this endpoint can actually render, so the sub dialog offers
		// exactly them. It offered three of nine hardcoded, which meant the Surge,
		// Loon and Quantumult X renderers — complete, tested, and reachable by
		// typing the URL — were invisible to every operator who used the panel.
		"formats": subFormats,
		// Read on every subscription request and, until now, writable only by
		// the Preset Wizard (two of them) or not at all (clean_ips as a list the
		// operator can see).
		"expand_sni":     s.subExpandSNI(),
		"front_clean_ip": s.subFrontCleanIP(),
		"clean_ips":      strings.Join(s.subCleanIPs(), ", "),
	})
}

// handleSetSubSettings persists the subscription defaults.
func (s *Server) handleSetSubSettings(c *gin.Context) {
	var req struct {
		RoutingPreset *string `json:"routing_preset"`
		Fragment      *bool   `json:"fragment"`
		FragmentLevel *string `json:"fragment_level"`
		FragmentCores *string `json:"fragment_cores"`
		NameTemplate  *string `json:"name_template"`
		Pattern       *string `json:"pattern"`
		FrontDomain   *string `json:"front_domain"`
		FrontMode     *string `json:"front_mode"`
		// FancyTheme applies a styled preset: it sets name_template to the
		// theme's template and front_mode to the theme's fronting model in one
		// step, so the wizard is a single click plus a domain.
		FancyTheme *string `json:"fancy_theme"`
		// Three settings the subscription renderer reads on every request and
		// that this endpoint could not write. The Preset Wizard set two of them
		// as a side effect of applying a preset, so an operator who had never
		// run the wizard had no way to reach them at all, and one who had could
		// not change them afterwards without running it again.
		ExpandSNI    *bool   `json:"expand_sni"`
		FrontCleanIP *bool   `json:"front_clean_ip"`
		CleanIPs     *string `json:"clean_ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	if s.db == nil {
		fail(c, 501, "no store")
		return
	}
	// Collected first and written once, by the registry. Every one of these
	// eleven writes used to go straight into the settings table unchecked: an
	// unknown routing preset was stored and echoed back in the 200, then
	// silently ignored by routing.Preset, so the panel displayed a policy it did
	// not serve. Validating the whole batch before writing any of it also means
	// one bad field no longer leaves the card half-saved.
	pending := map[string]string{}
	if req.RoutingPreset != nil {
		pending["sub_routing_preset"] = *req.RoutingPreset
	}
	if req.Fragment != nil {
		pending["sub_fragment_default"] = strconv.FormatBool(*req.Fragment)
	}
	if req.FragmentLevel != nil {
		pending["sub_fragment_level"] = *req.FragmentLevel
	}
	if req.FragmentCores != nil {
		pending["sub_fragment_cores"] = *req.FragmentCores
	}
	if req.NameTemplate != nil {
		pending["sub_name_template"] = *req.NameTemplate
	}
	if req.Pattern != nil {
		pending["sub_pattern_default"] = *req.Pattern
	}
	// Applying a theme sets the name template; a raw name_template in the same
	// request is overwritten by it, and a raw front_mode below still wins.
	if req.FancyTheme != nil {
		id := strings.TrimSpace(*req.FancyTheme)
		if id == "" {
			// An explicit empty theme clears fancy naming back to plain remarks.
			pending["sub_name_template"] = ""
			pending["sub_front_mode"] = string(model.FrontNone)
		} else if th, ok := model.FancyThemeByID(id); ok {
			pending["sub_name_template"] = th.Template
			pending["sub_front_mode"] = string(th.Front)
		} else {
			failFields(c, 400, "unknown fancy theme: "+id,
				map[string]string{"fancy_theme": "no theme with that id"})
			return
		}
	}
	if req.FrontDomain != nil {
		pending["sub_front_domain"] = *req.FrontDomain
	}
	if req.FrontMode != nil {
		pending["sub_front_mode"] = *req.FrontMode
	}
	if req.ExpandSNI != nil {
		pending["sub_expand_sni"] = strconv.FormatBool(*req.ExpandSNI)
	}
	if req.FrontCleanIP != nil {
		pending["sub_front_cleanip"] = strconv.FormatBool(*req.FrontCleanIP)
	}
	if req.CleanIPs != nil {
		pending["sub_clean_ips"] = *req.CleanIPs
	}
	if err := s.knobs().SetAll(pending); err != nil {
		var ve *settings.ValidationError
		if errors.As(err, &ve) {
			// Named per field, so the UI can mark the input instead of showing a
			// sentence about a card with eleven of them.
			failFields(c, 400, ve.Error(), ve.Fields())
			return
		}
		failErr(c, 500, err)
		return
	}
	s.audit(c, "settings.subscription.update", s.subRoutingPreset())
	c.JSON(200, gin.H{"ok": true, "routing_preset": s.subRoutingPreset(), "fragment": s.subFragmentDefault(),
		"fragment_level": s.subFragmentLevel(), "fragment_cores": strings.Join(s.subFragmentCores(), ", "),
		"name_template": s.subNameTemplate(), "front_domain": s.subFrontDomain(), "front_mode": string(s.subFrontMode()),
		"expand_sni": s.subExpandSNI(), "front_clean_ip": s.subFrontCleanIP(),
		"clean_ips": strings.Join(s.subCleanIPs(), ", ")})
}

// subFormats are the subscription formats this endpoint can render. It is the
// list the sub dialog offers and the list the error message names when a client
// asks for something else, so the two can never disagree.
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

// recordSubFetch stamps one subscription pull.
//
// It is fire-and-forget by design: a telemetry write must never fail a
// subscription fetch, because that would take working clients offline for the
// sake of a reporting feature.
func (s *Server) recordSubFetch(c *gin.Context, token, format string) {
	if s.db == nil {
		return // the stateless constructor has no store to write to
	}
	u, err := s.db.UserBySubToken(token)
	if err != nil {
		// An UNKNOWN token must never create a row, or this unauthenticated
		// public endpoint becomes a way to fill the operator's database.
		return
	}
	ua := c.GetHeader("User-Agent")
	if len(ua) > 512 {
		// The column's width. ToValidUTF8 drops the rune the cut landed inside,
		// so a long non-ASCII User-Agent cannot leave a broken byte sequence in
		// the JSON the inspector serves.
		ua = strings.ToValidUTF8(ua[:512], "")
	}
	_ = s.db.RecordSubRequest(&store.SubRequest{
		UserID: u.ID, Format: format, UserAgent: ua, IP: c.ClientIP(),
	})
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
		// Recorded on THIS exit too, not only the client one: a human opening the
		// link is the most common interaction with a subscription URL, and a
		// history that omitted it would tell the operator "never fetched" about a
		// user who had just looked at their own page.
		s.recordSubFetch(c, token, "browser")
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

	// One call site above the renderer switch, so all ten formats record, and it
	// records the CANONICAL name: clash-meta and mihomo both land as "clash", so
	// the inspector's vocabulary is the renderer set plus "browser" rather than
	// whatever string a User-Agent happened to imply.
	s.recordSubFetch(c, token, format)

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
	// TLS-hello fragmentation: the operator's severity + core selection, which a
	// request can override with ?fragment= / ?fragment_level= / the three tuning
	// parameters.
	frag := routing.FragmentFromQuery(c.Request.URL.Query(), s.fragmentDefaults())
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
		c.Data(200, "application/json; charset=utf-8", singboxSubscription(nodes, route, frag))
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
// the user's real DB record.
//
// upload and download here MUST sum to the usage quotas are enforced on, because
// that is the number every client displays. So upload is the attributed uplink
// and download is everything else — not the attributed downlink. The difference
// matters: a remote node reports one combined counter with no split, and
// presenting only the attributed halves would show a user less usage than they
// have actually been billed for.
//
// It used to hardcode upload=0 and put the whole total under download, because
// the engine's separate uplink/downlink counters were summed before anything
// could see them.
//
// total is the data limit (0 = unlimited, which clients show as no cap); expire
// is the unix expiry (0 = never).
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
	up := u.UploadTraffic
	if up > u.UsedTraffic {
		// Cannot happen from the accounting path, but a hand-edited row must not
		// produce a negative download that clients render as nonsense.
		up = u.UsedTraffic
	}
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		up, u.UsedTraffic-up, u.DataLimit, expire)
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
	if frag.Enabled && frag.CoreEnabled("xray") && len(proxyOuts) > 0 {
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
	// sbAutoTag is the latency-tested group. Reserved alongside the other two:
	// sing-box refuses a config with two outbounds sharing a tag, and a node
	// that claimed this one would take the whole subscription down.
	sbAutoTag = "auto"
)

func singboxSubscription(nodes []*model.Node, route routing.Options, frag routing.Fragment) []byte {
	outs := make([]any, 0, len(nodes)+2)
	// Pre-reserve the tags this function emits itself, so no node can claim them.
	seen := map[string]int{sbSelectorTag: 1, sbDirectTag: 1, sbAutoTag: 1}
	var tags []string
	for i, n := range nodes {
		// Outbounds, plural: ShadowTLS is a PAIR — an inner Shadowsocks that
		// carries the traffic and the shadowtls camouflage it detours through.
		// This function used to build that pair itself, which meant every other
		// caller of the renderer (the diagnostic verifier, the egress chain
		// builder, RenderSingboxJSON) emitted the bare shadowtls outbound and
		// produced a config that connected and carried nothing. One
		// implementation now, in the renderer, where the knowledge belongs.
		rendered, err := render.SingboxOutbounds(n)
		if err != nil {
			continue
		}
		tag, _ := rendered[0]["tag"].(string)
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		if k, dup := seen[tag]; dup {
			seen[tag] = k + 1
			tag = fmt.Sprintf("%s-%d", tag, k+1)
		} else {
			seen[tag] = 1
		}
		// Renames the primary AND repoints anything detouring through it, so a
		// deduplicated tag cannot leave a detour aimed at a tag that is gone.
		render.RetagOutbounds(rendered, tag)
		tags = append(tags, tag)
		for _, o := range rendered {
			outs = append(outs, o)
		}
	}
	// sing-box fragments natively — a flag on each outbound's tls object, no
	// detour outbound of its own — so this runs over the NODE outbounds only,
	// before the selector and direct are appended. Neither of those carries tls,
	// so it would be a no-op on them; scoping it here says so.
	if frag.Enabled && frag.CoreEnabled("sing-box") {
		frag.ApplySingbox(outs)
	}
	final := sbDirectTag
	if len(tags) > 0 {
		// The latency-tested group, and the selector's default, so a client that
		// has never been opened uses the fastest node rather than whichever one
		// was generated first. Only worth emitting for more than one node: a
		// urltest over a single outbound measures it and then picks it.
		members := append([]string{}, tags...)
		if len(tags) > 1 {
			outs = append(outs, map[string]any{
				"type": "urltest", "tag": sbAutoTag,
				"outbounds": append([]string{}, tags...),
				"url":       export.DefaultURLTestURL,
				// sing-box wants a duration string, not a number; a bare integer
				// is rejected at parse time and takes the whole config with it.
				"interval":  fmt.Sprintf("%ds", export.DefaultURLTestInterval),
				"tolerance": export.DefaultURLTolerance,
			})
			members = append([]string{sbAutoTag}, members...)
		}
		outs = append(outs, map[string]any{"type": "selector", "tag": sbSelectorTag,
			"outbounds": append(members, sbDirectTag), "default": members[0]})
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

// panelAssetMissing is served when the frontend bundle is not embedded in this
// build — a `go build` without `bun run build` first.
//
// It replaced a fallback that served the Config Studio's own shell in that
// situation. That was a fallback to another PAGE, and when the studio page was
// deleted it became a fallback to a fallback: the panel would have served this
// stub everywhere while reporting nothing wrong. A missing bundle should say it
// is missing, not quietly hand back a different page.
const panelAssetMissing = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ForgePanel</title>
<style>body{background:#0b0f17;color:#e5e7eb;font-family:system-ui;margin:0;padding:2rem}
a{color:#7dd3fc}code{background:#111827;padding:.2em .4em;border-radius:4px}</style></head>
<body><h1>⚡ ForgePanel</h1>
<p>The panel's web assets were not embedded in this build — it was compiled without
building the frontend first. The API is live:</p>
<ul><li><code>GET /api/protocols</code></li><li><code>POST /api/studio/preview</code></li>
<li><code>POST /api/keygen</code></li><li><code>GET /sub/:token</code></li></ul>
</body></html>`
