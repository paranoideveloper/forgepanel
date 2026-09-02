package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
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

// isPrivateIP reports whether ip is loopback, link-local, or in a private/CGNAT
// range — i.e. not an address a public DNS delegation or A record can point at.
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsPrivate() {
		return true
	}
	// 100.64.0.0/10 (CGNAT) is not covered by net.IP.IsPrivate.
	if v4 := p.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// publicServerIP returns this server's public IPv4 for delegation records and
// A-record hints. detectServerIP() returns the outbound-route local address,
// which behind Docker/NAT is a private bridge IP (e.g. 172.18.0.2) — useless in
// a public DNS record. When that happens, resolve the panel's own configured
// domain (it points at this server's real public address) and use that instead.
func (s *Server) publicServerIP() string {
	ip := detectServerIP()
	if ip != "" && ip != "127.0.0.1" && !isPrivateIP(ip) {
		return ip
	}
	if p := s.cfg.Panel(); p != nil && p.Domain != "" {
		if v4, _, err := resolveDomain(p.Domain); err == nil {
			for _, a := range v4 {
				if !isPrivateIP(a) {
					return a
				}
			}
		}
	}
	return ip
}

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
		"server_ipv4":   s.publicServerIP(),
		"server_ipv6":   detectServerIPv6(),
		"cert":          s.certStatusFor(p.Domain),
	})
}

// handlePanelDNSCheck (admin) resolves a candidate domain and reports whether it
// points at this server.
func (s *Server) handlePanelDNSCheck(c *gin.Context) {
	domain := normalizeDomain(c.Query("domain"))
	if !validDomain(domain) {
		fail(c, 400, "invalid domain")
		return
	}
	v4, v6, err := resolveDomain(domain)
	if err != nil {
		c.JSON(200, gin.H{"domain": domain, "resolves": false, "error": err.Error(), "points_here": false})
		return
	}
	myV4, myV6 := s.publicServerIP(), detectServerIPv6()
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
		fail(c, 400, "port must be an integer in 1..65535")
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
		fail(c, 400, "invalid payload")
		return
	}
	// Saving a panel domain implies you want a real (ACME) certificate for it:
	// TLS is always served, and the only reason to attach a domain is to get a
	// browser-trusted cert instead of the self-signed fallback. If the caller
	// didn't explicitly say otherwise, enable HTTPS/ACME so the cert status, the
	// :80 ACME helper and the public URL all reflect that intent.
	if req.Domain != nil && normalizeDomain(*req.Domain) != "" && req.HTTPSEnabled == nil {
		enable := true
		req.HTTPSEnabled = &enable
	}
	shared := settings.New(s.cfg)
	shared.IPv4 = detectServerIP
	shared.IPv6 = detectServerIPv6
	result, err := shared.Apply(settings.Change{
		Domain: req.Domain, Port: req.Port, BindAddress: req.BindAddress,
		HTTPSEnabled: req.HTTPSEnabled, ACMEEmail: req.ACMEEmail, VerifyDNS: req.VerifyDNS,
	})
	if err != nil {
		failErr(c, 400, err)
		return
	}
	if req.Domain != nil {
		// Best-effort MIRROR. settings.Apply already persisted the authoritative
		// value to panel.json and reported any failure; this copy only spares
		// other readers a file parse, so losing it costs a lookup, not the
		// setting.
		//
		// The value mirrored is the one Apply NORMALIZED, not the raw request:
		// an operator who typed "https://Panel.Example.com/" had that whole
		// string copied here, and substituteAddr then handed it to every
		// exported link as a hostname.
		_ = s.knobs().Set("public_address", result.New.Domain)
	}
	s.writePublicURLFile()
	// Bring TLS up without a restart: a configured domain (re)starts the :80 ACME
	// helper and primes the certificate now; a cleared domain releases port 80.
	if result.New.Domain != "" {
		s.StartACMEHelper()
		s.PrimePanelCert()
	} else {
		s.StopACMEHelper()
	}
	s.audit(c, "panel.address.update", result.New.Domain)
	c.JSON(200, gin.H{
		"ok": true, "restart_required": result.RestartRequired,
		"public_url": s.PublicURL(), "https_enabled": result.New.HTTPSEnabled,
	})
}

// PrimePanelCert issues or renews the panel domain's ACME certificate in the
// background at startup, so the first visitor who reaches the panel over its
// domain is served a browser-trusted certificate instead of stalling the TLS
// handshake on a first-time Let's Encrypt order. Best-effort: it waits briefly
// for the :80 HTTP-01 helper to come up, then asks autocert for the cert; any
// failure is left for the real handshake (or the Force-Renew button) to retry.
func (s *Server) PrimePanelCert() {
	// Reload first, always — including when there is no panel domain. A
	// wildcard issued for an inbound is on disk too, and skipping the reload on
	// the no-domain path would re-issue it on the next restart.
	s.loadDNS01Cache()
	p := s.cfg.Panel()
	if p == nil || p.Domain == "" || s.certs == nil {
		return
	}
	domain := p.Domain
	go func() {
		// Give the :80 HTTP-01 helper a moment to listen, then prime the cert once.
		// A single attempt on purpose: the cert is served from the autocert cache on
		// later handshakes (see cert.cachedACMECert), so there is no need to keep
		// firing ACME orders here and risk a rate limit. Crucially, RECORD the
		// outcome — the old code discarded the error (`_, _ =`), so a genuinely
		// failing order left the panel self-signed with an empty renewal_error and
		// nothing in the log, which made it impossible to diagnose.
		time.Sleep(3 * time.Second)
		if s.isClosed() {
			return
		}
		// A dns-01 panel does NOT go through autocert: autocert cannot perform
		// that challenge, so calling it here would try http-01 against a host
		// whose port 80 is almost certainly shut — which is why dns-01 was
		// chosen. This is the branch whose absence made the setting a no-op.
		if s.usesDNS01() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			_, err := s.issueDNS01(ctx, domain)
			cancel()
			s.recordACMEOutcome(domain, err)
			return
		}
		_, err := s.certs.ACMEManager().GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		s.recordACMEOutcome(domain, err)
	}()
}

// recordACMEOutcome persists the result of a panel-certificate issuance attempt
// so `forgectl cert status` and the panel UI show whether — and why not — the
// panel is on a trusted certificate, and logs a failure so it is visible in the
// journal instead of being swallowed. Safe to call from the startup goroutine:
// it takes the settings lock and re-reads before writing, like the manual
// Force-Renew handler.
func (s *Server) recordACMEOutcome(domain string, issueErr error) {
	if issueErr != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: ACME certificate for %q not obtained: %v\n", domain, issueErr)
	}
	release, err := config.LockSettings(s.cfg.DataDir)
	if err != nil {
		return
	}
	defer func() { _ = release() }()
	if err := s.cfg.ReloadPanel(); err != nil {
		return
	}
	p := s.cfg.Panel()
	if p == nil || p.Domain != domain {
		return // domain changed under us; its own attempt will record the outcome
	}
	p.ACME.LastRenewal = time.Now().Format(time.RFC3339)
	if issueErr != nil {
		p.ACME.RenewalError = issueErr.Error()
	} else {
		p.ACME.RenewalError = ""
	}
	// Best-effort: this writes renewal BOOKKEEPING, not the certificate. A
	// failure here loses the record of when renewal last ran, and the
	// certificate itself is already issued and on disk. Failing the renewal over
	// an unwritable status field would be the tail wagging the dog.
	_ = s.cfg.SavePanel()
}

// handlePanelCertRenew (admin) primes/renews the ACME certificate for the panel
// domain by fetching it through the manager (autocert issues or renews as
// needed). Returns the resulting status.
func (s *Server) handlePanelCertRenew(c *gin.Context) {
	release, err := config.LockSettings(s.cfg.DataDir)
	if err != nil {
		failErr(c, 409, err)
		return
	}
	defer release()
	if err := s.cfg.ReloadPanel(); err != nil {
		fail(c, 500, "reload panel settings: "+err.Error())
		return
	}
	p := s.cfg.Panel()
	if p.Domain == "" {
		fail(c, 400, "configure a panel domain first (Panel → Address)")
		return
	}
	if s.certs == nil {
		fail(c, 501, "certificate manager unavailable")
		return
	}
	// Force-Renew must take the same branch startup does, or the button quietly
	// runs a different challenge from the one the panel is configured for.
	if s.usesDNS01() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 10*time.Minute)
		_, err = s.issueDNS01(ctx, p.Domain)
		cancel()
	} else {
		_, err = s.certs.ACMEManager().GetCertificate(&tls.ClientHelloInfo{ServerName: p.Domain})
	}
	p.ACME.LastRenewal = time.Now().Format(time.RFC3339)
	if err != nil {
		p.ACME.RenewalError = err.Error()
	} else {
		p.ACME.RenewalError = ""
	}
	_ = s.cfg.SavePanel()
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "panel-cert-issue", Kind: apierr.KindNetwork,
			Message: "issuance failed: " + err.Error(), Cause: err,
			Details: map[string]any{"cert": s.certStatusFor(p.Domain)}})
		return
	}
	c.JSON(200, gin.H{"ok": true, "cert": s.certStatusFor(p.Domain)})
}
