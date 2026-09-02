package api

// A real certificate for the CDN host, so the CDN inbounds can actually carry.
//
// THE FAILURE THIS FIXES, measured on a live panel whose three CDN inbounds all
// answered the same way through Cloudflare:
//
//	edge-1a2b3c4d.example.com:2096  status=526  Cloudflare rejected the origin's certificate
//	edge-1a2b3c4d.example.com:2087  status=526
//	edge-1a2b3c4d.example.com:2083  status=526
//
// The stored inbounds were correct — bind 0.0.0.0, advertise the CDN hostname,
// right path and SNI — and the ports were listening. What the origin presented
// was the panel's build-wide self-signed certificate:
//
//	subject=CN = forgepanel.local
//
// The zone is on Full (Strict), which requires a certificate a public CA signed,
// so Cloudflare refused the origin and every client got an error page. Nothing
// on the origin says so: the port answers perfectly when tested directly.
//
// The panel already resolves a certificate PER SNI — core.Controller.certFor is
// wired to cert.Store.Materialize — so the only missing piece was a certificate
// for the CDN hostname. The preset holds the operator's Cloudflare token, which
// is exactly what DNS-01 needs, and DNS-01 is the right challenge here because
// the hostname is proxied: HTTP-01 would have to survive the CDN, and the record
// the preset just created is one the same token can write to.
//
// WHY IN THE BACKGROUND. Issuance waits for a TXT record to propagate — three
// minutes by default — and the wizard is one HTTP request. Blocking it would
// turn a successful setup into a client timeout. The inbounds exist either way;
// they start working when the certificate lands, and the wizard says so.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/store"
)

// issueCDNCertificate obtains a certificate for the preset's CDN hostname.
//
// Returns the line to show the operator. Never fatal: a preset whose CDN half is
// waiting on a certificate is still a preset that built every direct inbound.
func (s *Server) issueCDNCertificate(host, token, accountID string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.TrimSpace(token) == "" {
		return ""
	}
	if s.certs == nil {
		return "no certificate store, so " + host + " will serve the panel's self-signed certificate — " +
			"Cloudflare refuses that on a Full (Strict) zone with a 526"
	}

	// Already have one? Re-issuing on every preset run burns the CA's rate limit
	// for a certificate that is already serving.
	if _, _, ok := s.certs.Materialize(host); ok {
		return ""
	}

	// Register the hostname FIRST, or nothing below can work.
	//
	// The certificate store is built with a closed allowlist (allowPanelHost in
	// server.go): the panel's own domain, plus any name in the domain registry.
	// An arbitrary SNI must not be able to trigger a Let's Encrypt order, which
	// is right — but the preset was minting a CDN hostname, pointing inbounds at
	// it, and never registering it. So the allowlist refused it, no certificate
	// could ever be issued, Materialize found nothing, and every CDN inbound
	// fell back to the build-wide self-signed cert. That is the whole 526.
	if s.db != nil {
		if _, err := s.db.DomainByName(host); err != nil {
			if cerr := s.db.CreateDomain(&store.Domain{
				Name:     host,
				Provider: "cloudflare",
				TLSMode:  "acme",
				Note:     "created by the preset wizard for CDN-fronted inbounds",
			}); cerr != nil {
				return "could not register " + host + " as a domain, so no certificate can be " +
					"issued for it: " + cerr.Error()
			}
		}
	}

	prov, err := dns.NewCloudflare(dns.Credentials{"api_token": token, "account_id": accountID})
	if err != nil {
		return "could not use the Cloudflare token to request a certificate for " + host + ": " + err.Error()
	}

	go func() {
		// Generous but bounded: propagation is the slow part, and a goroutine
		// that never returns is a goroutine that holds the solver's records
		// open forever.
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		solver := &dns.ACMESolver{Provider: prov}
		_, err := s.certs.IssueDNS01(ctx, cert.DNS01Options{
			Solver: solver,
			Email:  s.knobs().String("acme_email"),
			// Propagation must actually be checked. Without a lookup the CA is
			// asked to validate a record that may not be visible yet, which
			// spends an authorisation failure rather than waiting.
			// PUBLIC resolvers, not the host's.
			//
			// The host's resolver caches the NXDOMAIN for the challenge name —
			// including the one left by a previous attempt's cleanup — and then
			// reports the freshly published record as missing for the length of
			// that negative TTL. Measured: the same issuance succeeded once and
			// then failed at "not visible after 3m0s" on the retry, resolving
			// through the machine's own 108.61.10.10. The CA queries public DNS
			// anyway, so asking what IT will see is both more accurate and
			// immune to this.
			Lookup: func(ctx context.Context, fqdn string) ([]string, error) {
				return dns.NewResolver().LookupTXT(ctx, fqdn)
			},
		}, host)
		if err != nil {
			s.noteCDNCert(host, "certificate for "+host+" could not be issued: "+err.Error())
			return
		}
		s.noteCDNCert(host, "")
		// The engines pick the certificate up through certFor on the next build.
		s.startBackground(s.reloadEngines)
	}()

	return fmt.Sprintf("requesting a certificate for %s in the background. Until it lands, the CDN "+
		"inbounds serve the panel's self-signed certificate, which Cloudflare refuses on a "+
		"Full (Strict) zone (526) — check progress under Certificates.", host)
}

// noteCDNCert records the outcome so the operator can see it after the wizard's
// response is long gone. An issuance that failed in a goroutine and told nobody
// is the same as one that never ran.
func (s *Server) noteCDNCert(host, problem string) {
	if s.db == nil {
		return
	}
	action := "wizard.cdn_cert.issued"
	target := host
	if problem != "" {
		action = "wizard.cdn_cert.failed"
		target = problem
	}
	s.db.Audit(&store.AuditLog{Actor: "system", Action: action, Target: target})
}
