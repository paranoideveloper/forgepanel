package api

import (
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/settings"
)

// domainRe validates a normalized hostname (labels of a-z0-9-, no leading or
// trailing hyphen, at least one dot). Deliberately strict — it also blocks the
// domain-injection surface (spaces, slashes, shell metacharacters) by rejecting
// anything outside this character set.
// normalizeDomain strips a scheme, path, port, and trailing dots/slashes, and
// lowercases the host — turning "HTTPS://Panel.Example.com:2053/x/" into
// "panel.example.com". Empty input yields empty output (IP-only panel).
func normalizeDomain(raw string) string { return settings.NormalizeDomain(raw) }

// validDomain reports whether a normalized domain is a well-formed hostname.
func validDomain(d string) bool { return settings.ValidDomain(d) }

// portFree reports whether a TCP port can be bound on bindAddr right now. It is
// the port-conflict probe used before persisting a port change (never leaves a
// listener open).
func portFree(bindAddr string, port int) bool { return settings.PortFree(bindAddr, port) }

// detectServerIPv6 returns the primary outbound IPv6, or "" when the host has no
// global IPv6 route. Sends no traffic (connected UDP socket route selection).
func detectServerIPv6() string {
	conn, err := net.Dial("udp6", "[2001:4860:4860::8888]:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP.IsGlobalUnicast() {
		return addr.IP.String()
	}
	return ""
}

// resolveDomain splits a domain's resolved addresses into A (IPv4) and AAAA
// (IPv6) records.
func resolveDomain(domain string) (v4, v6 []string, err error) { return settings.ResolveDomain(domain) }

// certStatusFor reports the panel certificate state for the given domain without
// triggering issuance.
func (s *Server) certStatusFor(domain string) gin.H {
	p := s.cfg.Panel()
	out := gin.H{
		"acme": gin.H{
			"enabled":       p.ACME.Enabled,
			"provider":      p.ACME.Provider,
			"email":         p.ACME.Email,
			"challenge":     p.ACME.Challenge,
			"staging":       p.ACME.Staging,
			"last_renewal":  p.ACME.LastRenewal,
			"renewal_error": p.ACME.RenewalError,
		},
		"available": false,
	}
	if domain == "" || s.certs == nil {
		return out
	}
	if info, ok := s.certs.CachedInfo(domain); ok {
		out["available"] = true
		out["issuer"] = info.Issuer
		out["not_before"] = info.NotBefore.Format(time.RFC3339)
		out["not_after"] = info.NotAfter.Format(time.RFC3339)
		out["days_remaining"] = int(time.Until(info.NotAfter).Hours() / 24)
	}
	return out
}

// handlePanelAddress (admin) returns the current panel address, detected server
// IPs, HTTPS/cert status, and the public URL.
func (s *Server) handlePanelAddress(c *gin.Context) {
	p := s.cfg.Panel()
	c.JSON(200, gin.H{
		"domain":        p.Domain,
		"bind_address":  p.BindAddress,
		"port":          p.Port,
		"public_url":    s.PublicURL(),
		"https_enabled": p.HTTPSEnabled,
		"admin_path":    p.AdminPath,
		"server_ipv4":   detectServerIP(),
		"server_ipv6":   detectServerIPv6(),
		"cert":          s.certStatusFor(p.Domain),
	})
}

// handlePanelDNSCheck (admin) resolves a candidate domain and reports whether it
// points at this server.
func (s *Server) handlePanelDNSCheck(c *gin.Context) {
	domain := normalizeDomain(c.Query("domain"))
	if !validDomain(domain) {
		c.JSON(400, gin.H{"error": "invalid domain"})
		return
	}
	v4, v6, err := resolveDomain(domain)
	if err != nil {
		c.JSON(200, gin.H{"domain": domain, "resolves": false, "error": err.Error(), "points_here": false})
		return
	}
	myV4, myV6 := detectServerIP(), detectServerIPv6()
	pointsHere := false
	for _, ip := range v4 {
		if ip == myV4 {
			pointsHere = true
		}
	}
	for _, ip := range v6 {
		if myV6 != "" && ip == myV6 {
			pointsHere = true
		}
	}
	c.JSON(200, gin.H{
		"domain": domain, "resolves": true, "a": v4, "aaaa": v6,
		"server_ipv4": myV4, "server_ipv6": myV6, "points_here": pointsHere,
	})
}

// handlePanelPortCheck (admin) reports whether a port is free to bind.
func (s *Server) handlePanelPortCheck(c *gin.Context) {
	port, err := strconv.Atoi(c.Query("port"))
	if err != nil || port < 1 || port > 65535 {
		c.JSON(400, gin.H{"error": "port must be an integer in 1..65535"})
		return
	}
	// The port the panel is currently bound to is "in use" by us but still valid.
	inUseByUs := port == s.cfg.Panel().Port
	c.JSON(200, gin.H{"port": port, "available": inUseByUs || portFree(s.cfg.Panel().BindAddress, port), "current": inUseByUs})
}

// handlePanelAddressUpdate (admin) validates and persists panel-address changes
// with a rollback snapshot. Domain/HTTPS/email changes that don't move the
// listener are safe to persist; a port or bind change is persisted too but only
// takes effect on the next restart (reported via restart_required) — the running
// listener is never torn out from under the administrator.
func (s *Server) handlePanelAddressUpdate(c *gin.Context) {
	var req struct {
		Domain       *string `json:"domain"`
		Port         *int    `json:"port"`
		BindAddress  *string `json:"bind_address"`
		HTTPSEnabled *bool   `json:"https_enabled"`
		ACMEEmail    *string `json:"acme_email"`
		VerifyDNS    bool    `json:"verify_dns"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	shared := settings.New(s.cfg)
	shared.IPv4 = detectServerIP
	shared.IPv6 = detectServerIPv6
	result, err := shared.Apply(settings.Change{
		Domain: req.Domain, Port: req.Port, BindAddress: req.BindAddress,
		HTTPSEnabled: req.HTTPSEnabled, ACMEEmail: req.ACMEEmail, VerifyDNS: req.VerifyDNS,
	})
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if s.db != nil && req.Domain != nil {
		_ = s.db.SetSetting("public_address", *req.Domain)
	}
	s.writePublicURLFile()
	s.audit(c, "panel.address.update", result.New.Domain)
	c.JSON(200, gin.H{
		"ok": true, "restart_required": result.RestartRequired,
		"public_url": s.PublicURL(), "https_enabled": result.New.HTTPSEnabled,
	})
}

// handlePanelCertRenew (admin) primes/renews the ACME certificate for the panel
// domain by fetching it through the manager (autocert issues or renews as
// needed). Returns the resulting status.
func (s *Server) handlePanelCertRenew(c *gin.Context) {
	release, err := config.LockSettings(s.cfg.DataDir)
	if err != nil {
		c.JSON(409, gin.H{"error": err.Error()})
		return
	}
	defer release()
	if err := s.cfg.ReloadPanel(); err != nil {
		c.JSON(500, gin.H{"error": "reload panel settings: " + err.Error()})
		return
	}
	p := s.cfg.Panel()
	if p.Domain == "" || !p.HTTPSEnabled {
		c.JSON(400, gin.H{"error": "configure a domain and enable HTTPS first"})
		return
	}
	if s.certs == nil {
		c.JSON(501, gin.H{"error": "certificate manager unavailable"})
		return
	}
	_, err = s.certs.ACMEManager().GetCertificate(&tls.ClientHelloInfo{ServerName: p.Domain})
	p.ACME.LastRenewal = time.Now().Format(time.RFC3339)
	if err != nil {
		p.ACME.RenewalError = err.Error()
	} else {
		p.ACME.RenewalError = ""
	}
	_ = s.cfg.SavePanel()
	if err != nil {
		c.JSON(502, gin.H{"error": "issuance failed: " + err.Error(), "cert": s.certStatusFor(p.Domain)})
		return
	}
	c.JSON(200, gin.H{"ok": true, "cert": s.certStatusFor(p.Domain)})
}
