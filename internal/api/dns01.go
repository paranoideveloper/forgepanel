package api

// Making `acme.challenge: dns-01` mean something.
//
// The setting was accepted by the config loader, echoed back by the status
// endpoint, offered by the wizard and recommended by the HTTP-01 preflight's own
// remediation text — and then ignored, because issuance went through autocert,
// which speaks HTTP-01 and TLS-ALPN-01 only. An operator whose port 80 is
// blocked (the whole reason to pick dns-01) set it, saw the panel agree, and
// still got no certificate.
//
// This is the join: the panel's own DNS credentials become the ACME solver.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/dns"
)

// dnsCredentialStore builds a credential store on demand.
//
// Built per call rather than held on the Server because a credential can be
// added, replaced or deleted while the panel runs, and a store captured at
// startup would keep using a token that has since been rotated away.
func (s *Server) dnsCredentialStore() (*dns.CredentialStore, error) {
	if s.db == nil {
		return nil, errors.New("dns-01 issuance needs the database-backed credential store")
	}
	repo, err := dns.NewGormStore(s.db.DB())
	if err != nil {
		return nil, err
	}
	enc, err := dns.NewAESGCMFromPassphrase(deriveSecret(s.cfg))
	if err != nil {
		return nil, err
	}
	return dns.NewCredentialStore(repo, enc)
}

// solverForDomain picks the stored DNS credential that can actually edit the
// zone holding domain.
//
// It asks each credential rather than trusting a label, because "which of these
// tokens owns example.com" is not something the panel records anywhere — and a
// token that merely EXISTS is not a token that can write to this zone. Trying
// them is how a credential scoped to one zone out of five stops being a silent
// issuance failure.
func (s *Server) solverForDomain(ctx context.Context, domain string) (*dns.ACMESolver, string, error) {
	store, err := s.dnsCredentialStore()
	if err != nil {
		return nil, "", err
	}
	records, err := store.List()
	if err != nil {
		return nil, "", err
	}
	if len(records) == 0 {
		return nil, "", errors.New("no DNS provider credential is registered — " +
			"add one under Domains → DNS provider before using a dns-01 challenge")
	}
	// The zone that matters is the challenge name's, not the certificate name's:
	// a wildcard's challenge is published at the bare domain.
	probe := cert.ChallengeName(domain)

	var reasons []string
	for _, rec := range records {
		provider, _, err := store.Provider(rec.ID)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s (%s): %v", rec.Label, rec.Provider, err))
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		res, err := dns.ResolveZone(lookupCtx, provider, nil, probe)
		cancel()
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s (%s): %v", rec.Label, rec.Provider, err))
			continue
		}
		return &dns.ACMESolver{Provider: provider, Resolver: dns.NewResolver()}, res.Zone.Name, nil
	}
	return nil, "", fmt.Errorf("no registered DNS credential can edit the zone for %s: %s",
		domain, strings.Join(reasons, "; "))
}

// issueDNS01 obtains a certificate for domains through the DNS-01 challenge.
func (s *Server) issueDNS01(ctx context.Context, domains ...string) (*cert.Imported, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains were requested")
	}
	solver, zone, err := s.solverForDomain(ctx, domains[0])
	if err != nil {
		return nil, err
	}
	p := s.cfg.Panel()
	opts := cert.DNS01Options{
		Solver: solver,
		// The zone's own authoritative servers answer the propagation check.
		// A local resolver caches the NXDOMAIN it got a second ago and would
		// report the record missing for the length of that negative TTL.
		Lookup:  authoritativeTXT(zone),
		Staging: p != nil && p.ACME.Staging,
	}
	if p != nil {
		opts.Email = p.ACME.Email
	}
	return s.certs.IssueDNS01(ctx, opts, domains...)
}

// authoritativeTXT reads TXT records from the zone's own nameservers.
func authoritativeTXT(zone string) cert.TXTLookup {
	return func(ctx context.Context, fqdn string) ([]string, error) {
		res := dns.NewResolver()
		servers, err := res.LookupNS(ctx, zone)
		if err != nil || len(servers) == 0 {
			// Fall back to the default resolvers. Weaker, but a zone whose NS
			// lookup fails is a zone whose TXT lookup is about to fail too, and
			// the error from that is the more useful one to surface.
			return res.LookupTXT(ctx, fqdn)
		}
		return dns.NewResolver(servers...).LookupTXT(ctx, fqdn)
	}
}

// usesDNS01 reports whether the panel is configured for a dns-01 challenge.
func (s *Server) usesDNS01() bool {
	p := s.cfg.Panel()
	return p != nil && strings.EqualFold(strings.TrimSpace(p.ACME.Challenge), string(dns.ChallengeDNS01))
}

// certIssueRequest asks for a certificate covering specific names.
type certIssueRequest struct {
	// Domains are the names to cover. A wildcard is written as *.example.com.
	Domains []string `json:"domains"`
	// Wildcard adds *.<domain> alongside each bare domain, which is the shape
	// almost everyone actually wants and the shape that is easiest to get wrong
	// by hand: a certificate for *.example.com does NOT cover example.com,
	// because a TLS wildcard matches exactly one label.
	Wildcard bool `json:"wildcard"`
}

// handleCertIssueDNS01 (admin) issues a certificate over DNS-01, wildcards
// included. This is the only path to a wildcard: Let's Encrypt refuses to issue
// one against HTTP-01 or TLS-ALPN-01, by policy.
func (s *Server) handleCertIssueDNS01(c *gin.Context) {
	var req certIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "cert-issue-dns01", Kind: apierr.KindValidation,
			Message: "invalid request body", Cause: err,
			Details: map[string]any{"detail": `send {"domains":["example.com"],"wildcard":true}`}})
		return
	}
	names := req.Domains
	if req.Wildcard {
		for _, d := range req.Domains {
			d = strings.TrimSpace(strings.ToLower(d))
			if d == "" || strings.HasPrefix(d, "*.") {
				continue
			}
			names = append(names, "*."+d)
		}
	}
	if len(names) == 0 {
		fail(c, http.StatusBadRequest, "no domains were requested")
		return
	}

	// An ACME order is slow — authorization, propagation, validation — and well
	// past any sensible HTTP timeout. Bounding it here rather than on the
	// request context means a client that gives up waiting does not abandon an
	// order mid-flight and leave challenge records behind in the zone.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 10*time.Minute)
	defer cancel()

	imported, err := s.issueDNS01(ctx, names...)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Op: "cert-issue-dns01", Kind: apierr.KindNetwork,
			Message: "certificate issuance failed", Cause: err,
			Details: map[string]any{"detail": err.Error()}})
		return
	}
	s.audit(c, "cert.issue.dns01", strings.Join(names, ","))
	c.JSON(http.StatusOK, gin.H{
		"domains":    imported.Domains,
		"not_after":  imported.NotAfter,
		"issuer":     imported.Issuer,
		"not_before": imported.NotBefore,
	})
}

// loadDNS01Cache re-imports DNS-01 certificates issued in an earlier run.
//
// Without it the panel re-issues on every restart, which is how an operator
// meets Let's Encrypt's duplicate-certificate limit: five per week for the same
// set of names, then a week with none.
func (s *Server) loadDNS01Cache() {
	if s.certs == nil {
		return
	}
	n, err := s.certs.LoadDNS01Cache()
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: could not reload DNS-01 certificates:", err)
		return
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "forgepanel: reloaded %d DNS-01 certificate(s) from cache\n", n)
	}
}
