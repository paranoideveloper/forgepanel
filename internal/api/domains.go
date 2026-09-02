package api

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/domain"
)

// handleDomainCheck resolves a domain and reports whether it points at the given
// IP (spec §7 domain health).
func (s *Server) handleDomainCheck(c *gin.Context) {
	name := c.Query("domain")
	ip := c.Query("ip")
	h := s.domains.Check(c.Request.Context(), name, ip, time.Now())
	c.JSON(200, h)
}

// handleNSWizard returns the exact glue/NS records to delegate a ForgeDNS tunnel
// zone, then live-verifies the delegation (spec §5.3, §7).
func (s *Server) handleNSWizard(c *gin.Context) {
	zone := c.Query("zone")
	ip := c.Query("ip")
	records, err := domain.NSDelegation(zone, ip)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	nsHost := ""
	if len(records) > 0 {
		nsHost = records[0].Name
	}
	verify := s.domains.VerifyDelegation(c.Request.Context(), zone, nsHost, ip)
	c.JSON(200, gin.H{"records": records, "verification": verify})
}

// handleCertImport stores a user-supplied PEM cert+key (spec §7).
func (s *Server) handleCertImport(c *gin.Context) {
	var req struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	imp, err := s.certs.Import([]byte(req.Cert), []byte(req.Key))
	if err != nil {
		failErr(c, 400, err)
		return
	}
	s.audit(c, "cert.import", imp.Domains[0])
	c.JSON(201, imp)
}

// handleCertList lists imported certs (spec §7).
func (s *Server) handleCertList(c *gin.Context) {
	c.JSON(200, s.certs.List())
}
