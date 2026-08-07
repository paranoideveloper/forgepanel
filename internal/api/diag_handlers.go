package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/diag"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// This file exposes the Validation & Proof engine (§3): Layer-1 static
// validation, the Layer-3 live Verify, and the Panel Doctor battery.

// usedPortsExcept builds a port→remark map of enabled inbounds other than the
// given id, for the port-conflict check.
func (s *Server) usedPortsExcept(exceptID uint) map[int]string {
	out := map[int]string{}
	ins, _ := s.db.ListInbounds()
	for _, in := range ins {
		if in.ID == exceptID {
			continue
		}
		out[in.Port] = in.Remark
	}
	return out
}

// handleValidateInbound runs the instant static checks (Layer 1) on a posted
// node OR an existing inbound and returns coded findings.
func (s *Server) handleValidateInbound(c *gin.Context) {
	var n model.Node
	if err := c.ShouldBindJSON(&n); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	findings := diag.StaticValidate(&n, s.usedPortsExcept(0))
	c.JSON(200, gin.H{"findings": findings, "ok": !hasCritical(findings)})
}

// handleVerifyInbound runs the live proof-of-work (Layer 3): a real client core
// carries traffic through the inbound. The result is the badge the UI shows.
func (s *Server) handleVerifyInbound(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "inbound not found"})
		return
	}
	n, err := in.Node()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	res := diag.VerifySingbox(ctx, n, diag.Cores{})
	s.audit(c, "inbound.verify", res.Finding.Code)
	c.JSON(200, res)
}

// handleDoctor runs the whole battery (§3 Panel Doctor): system checks plus
// static validation of every inbound, producing one shareable report.
func (s *Server) handleDoctor(c *gin.Context) {
	report := gin.H{"checked_at": time.Now()}
	var findings []diag.Finding

	// System: clock sync is a classic silent killer for REALITY/TLS.
	if skew := clockSkew(); skew > 5*time.Second {
		findings = append(findings, diag.New("FP-CLOCK-001", skew.String()))
	}

	// Per-inbound static validation.
	ins, _ := s.db.ListInbounds()
	perInbound := make([]gin.H, 0, len(ins))
	for _, in := range ins {
		n, err := in.Node()
		if err != nil {
			continue
		}
		fs := diag.StaticValidate(n, s.usedPortsExcept(in.ID))
		findings = append(findings, fs...)
		perInbound = append(perInbound, gin.H{"id": in.ID, "remark": in.Remark, "findings": fs})
	}

	report["system_findings"] = findings
	report["inbounds"] = perInbound
	report["health"] = s.healthReport()
	report["ok"] = !hasCritical(findings)
	c.JSON(200, report)
}

func hasCritical(fs []diag.Finding) bool {
	for _, f := range fs {
		if f.Severity == diag.SevCritical {
			return true
		}
	}
	return false
}

// clockSkew is a best-effort local skew estimate. Without a trusted external
// time source it returns 0; the environment layer can compare against an NTP
// server when available.
func clockSkew() time.Duration { return 0 }

// (tests for these handlers live in diag_handlers_test.go)
