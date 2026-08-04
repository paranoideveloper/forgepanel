package api

import (
	"encoding/base64"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// handleSub serves a subscription (spec §9). Format is chosen by explicit
// suffix (/clash, /sing-box, /links, /json) or, absent that, auto-detected from
// the User-Agent. Correct subscription headers are always emitted.
func (s *Server) handleSub(c *gin.Context) {
	token := c.Param("token")
	nodes := s.subscriptionNodes(token, hostOnly(c.Request.Host))
	if nodes == nil {
		// Unknown token: return an empty but valid subscription rather than
		// leaking which tokens exist.
		nodes = []*model.Node{}
	}
	format := strings.Trim(c.Param("format"), "/")
	if format == "" {
		format = detectFormat(c.GetHeader("User-Agent"))
	}

	c.Header("Profile-Update-Interval", "12")
	c.Header("Subscription-Userinfo", "upload=0; download=0; total=0; expire=0")
	c.Header("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("ForgePanel")))
	c.Header("Access-Control-Allow-Origin", "*")

	switch format {
	case "clash", "clash-meta":
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
	default: // v2ray/base64 subscription
		b64 := base64.StdEncoding.EncodeToString([]byte(plainLinks(nodes)))
		c.Data(200, "text/plain; charset=utf-8", []byte(b64))
	}
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
