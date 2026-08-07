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
)

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

	switch format {
	case "clash":
		y, err := export.ClashYAML(nodes)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.Data(200, "text/yaml; charset=utf-8", []byte(y))
	case "links":
		c.Data(200, "text/plain; charset=utf-8", []byte(plainLinks(nodes)))
	case "json":
		c.JSON(200, nodes)
	case "sing-box":
		c.Data(200, "application/json; charset=utf-8", singboxSubscription(nodes))
	case "xray":
		c.Data(200, "application/json; charset=utf-8", xraySubscription(nodes))
	case "surge":
		c.Data(200, "text/plain; charset=utf-8", surgeSubscription(nodes))
	case "loon":
		c.Data(200, "text/plain; charset=utf-8", loonSubscription(nodes))
	case "quantumultx":
		c.Data(200, "text/plain; charset=utf-8", quantumultxSubscription(nodes))
	default: // v2ray/base64 subscription (also Shadowrocket)
		b64 := base64.StdEncoding.EncodeToString([]byte(plainLinks(nodes)))
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
func xraySubscription(nodes []*model.Node) []byte {
	const (
		xrayDirectTag = "direct"
		xrayBlockTag  = "block"
	)
	outs := make([]any, 0, len(nodes)+2)
	seen := map[string]int{xrayDirectTag: 1, xrayBlockTag: 1}
	var proxyTags []string
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
		outs = append(outs, o)
	}
	outs = append(outs,
		map[string]any{"protocol": "freedom", "tag": xrayDirectTag},
		map[string]any{"protocol": "blackhole", "tag": xrayBlockTag},
	)
	rules := []any{}
	if len(proxyTags) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "outboundTag": proxyTags[0], "network": "tcp,udp",
		})
	}
	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]any{"udp": true, "auth": "noauth"},
			},
			map[string]any{
				"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
			},
		},
		"outbounds": outs,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
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

func singboxSubscription(nodes []*model.Node) []byte {
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
		outs = append(outs, o)
	}
	if len(tags) > 0 {
		outs = append(outs, map[string]any{"type": "selector", "tag": sbSelectorTag, "outbounds": append(append([]string{}, tags...), sbDirectTag), "default": tags[0]})
	}
	outs = append(outs, map[string]any{"type": "direct", "tag": sbDirectTag})
	doc := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"outbounds": outs,
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
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

func plainLinks(nodes []*model.Node) string {
	var b strings.Builder
	for _, n := range nodes {
		if uri, err := export.URI(n); err == nil {
			b.WriteString(uri)
			b.WriteString("\n")
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
