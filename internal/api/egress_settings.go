package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/netegress"
)

// The egress proxy the panel uses for its OWN outbound requests.
//
// Separate from every proxy the panel serves to clients: this one is how the
// panel reaches the update check, Telegram, the DNS provider APIs and GeoIP. On
// a censored network those all failed while the panel sat on a machine that
// could reach the outside perfectly well, because it is the machine running the
// tunnels.

func (s *Server) handleGetEgressSettings(c *gin.Context) {
	c.JSON(200, gin.H{
		"proxy":      netegress.Current(),
		"configured": netegress.Current() != "",
	})
}

func (s *Server) handleSetEgressSettings(c *gin.Context) {
	var req struct {
		Proxy string `json:"proxy"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	// Validate BEFORE persisting. A stored proxy that cannot be parsed would be
	// applied on the next boot and take every outbound call down with it, and
	// the panel would come up looking healthy.
	if err := netegress.Set(req.Proxy); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "egress-settings", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Remediation: "Use http://host:port, https://host:port, socks5://host:port or socks5h://host:port, optionally with user:password@."})
		return
	}
	p := s.cfg.Panel()
	p.EgressProxy = req.Proxy
	if err := config.SavePanelSettings(s.cfg.DataDir, p); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "settings.egress_proxy", redactProxy(req.Proxy))
	c.JSON(200, gin.H{"proxy": netegress.Current(), "configured": netegress.Current() != ""})
}

// handleTestEgress checks the proxy the way the panel would use it, so an
// operator learns it is wrong here rather than from a Telegram alert that never
// arrived days later.
func (s *Server) handleTestEgress(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
	}
	_ = c.ShouldBindJSON(&req)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	// 502 is the handler's own diagnosis — "the proxy could not reach it". A
	// target the egress guard REFUSED is typed, so it keeps its own 400 and
	// remediation instead: the operator typed an address the panel will not
	// fetch, and telling them their proxy is broken sends them the wrong way.
	if err := netegress.Probe(ctx, req.Target); err != nil {
		failErr(c, http.StatusBadGateway, err)
		return
	}
	c.JSON(200, gin.H{"ok": true, "via": netegress.Current()})
}

// redactProxy keeps credentials out of the audit trail. A proxy URL routinely
// carries user:password, and the audit log is read by more people than the
// settings page is.
func redactProxy(s string) string {
	if s == "" {
		return "(cleared)"
	}
	if i := strings.Index(s, "@"); i >= 0 {
		if j := strings.Index(s, "://"); j >= 0 && j+3 < i {
			return s[:j+3] + "***@" + s[i+1:]
		}
	}
	return s
}
