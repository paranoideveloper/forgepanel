package api

import (
	"strings"
	"testing"
)

// The CDN presets failed with HTTP 526 — "Cloudflare rejected the origin's
// certificate" — on every one of them, and the reason was three steps away from
// the symptom.
//
// The certificate store is built with a CLOSED allowlist (allowPanelHost in
// server.go): the panel's own domain, plus any name in the domain registry. That
// is correct — an arbitrary SNI must not be able to trigger a Let's Encrypt
// order. But the preset minted a CDN hostname, pointed three inbounds at it, and
// never registered it. So the allowlist refused it, no certificate could ever be
// issued for it, Materialize found nothing, and every CDN inbound fell back to
// the build-wide self-signed cert (CN = forgepanel.local) that a Full (Strict)
// zone rejects.
//
// Verified on a live panel: after registering the host and issuing, the origin
// presented "CN = edge-1a2b3c4d.example.com, issuer Let's Encrypt" and all three
// inbounds went from 526 to reaching the origin — then carried real traffic at
// 3.6 MB/s through Cloudflare.

func TestTheCDNHostIsRegisteredSoACertificateCanBeIssuedForIt(t *testing.T) {
	s, _ := adminAPI(t)
	const host = "edge-test.example.com"

	if _, err := s.db.DomainByName(host); err == nil {
		t.Fatal("the host was already registered; this test proves the preset adds it")
	}

	// A token that cannot be used is fine here: registration must happen before
	// any network call, because the allowlist decision is what gates issuance.
	note := s.issueCDNCertificate(host, "not-a-usable-token", "")

	if _, err := s.db.DomainByName(host); err != nil {
		t.Fatalf("the CDN host was not registered (%v).\n"+
			"Without it allowPanelHost refuses the name, no certificate can ever be issued, "+
			"and every CDN inbound serves the self-signed cert that Cloudflare answers 526 to.", err)
	}
	if strings.TrimSpace(note) == "" {
		t.Error("the operator was told nothing about the certificate their CDN inbounds depend on")
	}
}

// Registering twice must not fail the preset: an operator re-runs the wizard.
func TestRegisteringTheCDNHostTwiceIsHarmless(t *testing.T) {
	s, _ := adminAPI(t)
	const host = "edge-twice.example.com"
	first := s.issueCDNCertificate(host, "tok", "")
	second := s.issueCDNCertificate(host, "tok", "")
	if strings.Contains(second, "could not register") {
		t.Errorf("a second run failed on the existing registration: %q", second)
	}
	_ = first
}

// No token means no DNS-01 solver, so there is nothing to do — and nothing to
// claim. Registering a domain the panel then cannot get a certificate for would
// leave a registry entry that explains nothing.
func TestNoTokenMeansNoClaim(t *testing.T) {
	s, _ := adminAPI(t)
	if note := s.issueCDNCertificate("edge-notoken.example.com", "", ""); note != "" {
		t.Errorf("claimed something without a token: %q", note)
	}
	if _, err := s.db.DomainByName("edge-notoken.example.com"); err == nil {
		t.Error("registered a domain no certificate can be issued for")
	}
}

func TestAnEmptyHostIsIgnored(t *testing.T) {
	s, _ := adminAPI(t)
	if note := s.issueCDNCertificate("", "tok", ""); note != "" {
		t.Errorf("acted on an empty host: %q", note)
	}
}
