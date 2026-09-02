package api

import (
	"context"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
)

func panelWithChallenge(t *testing.T, challenge string) *Server {
	t.Helper()
	// LoadFromDataDir, not the light constructor: New() leaves cfg.panel nil, so
	// an earlier version of this helper called t.Skip and BOTH tests below
	// reported "ok" while asserting nothing — including against the exact bug
	// they were written to catch. A skip inside a helper is invisible in the
	// default output, which makes it a worse outcome than a failure.
	cfg, err := config.LoadFromDataDir(t.TempDir())
	if err != nil {
		t.Fatalf("could not build panel settings: %v", err)
	}
	s := New(cfg)
	p := s.cfg.Panel()
	if p == nil {
		t.Fatal("LoadFromDataDir produced no panel settings")
	}
	p.Domain = "panel.example.com"
	p.ACME.Challenge = challenge
	return s
}

func TestTheConfiguredChallengeDecidesWhichPathIssuanceTakes(t *testing.T) {
	// The defect this pins down: `acme.challenge: dns-01` was accepted by the
	// config loader, echoed back by the status endpoint, offered by the wizard
	// and recommended by the http-01 preflight's own remediation text — and then
	// ignored, because every issuance path went through autocert, which cannot
	// perform a dns-01 challenge. The operator who set it (because port 80 is
	// blocked, which is the only reason to set it) got the http-01 attempt
	// anyway, and it failed for the reason they were trying to avoid.
	if got := panelWithChallenge(t, "dns-01").usesDNS01(); !got {
		t.Error("a panel configured for dns-01 does not take the dns-01 path")
	}
	if got := panelWithChallenge(t, "DNS-01").usesDNS01(); !got {
		t.Error("the challenge name is compared case-sensitively")
	}
	if got := panelWithChallenge(t, " dns-01 ").usesDNS01(); !got {
		t.Error("a stray space in the config file changes which challenge runs")
	}
	if got := panelWithChallenge(t, "http-01").usesDNS01(); got {
		t.Error("an http-01 panel was routed to dns-01")
	}
	if got := panelWithChallenge(t, "").usesDNS01(); got {
		t.Error("an unset challenge was routed to dns-01")
	}
}

func TestDNS01WithoutACredentialSaysWhichCredentialIsMissing(t *testing.T) {
	// Failing here is expected — there is no DNS credential in a fresh panel.
	// What matters is WHICH failure: naming the missing DNS credential proves
	// the dns-01 branch ran. An http-01 or autocert error would mean the
	// setting had been ignored again.
	s := panelWithChallenge(t, "dns-01")
	_, err := s.issueDNS01(context.Background(), "panel.example.com")
	if err == nil {
		t.Fatal("issuance succeeded with no DNS credential registered")
	}
	got := strings.ToLower(err.Error())
	if !strings.Contains(got, "credential") && !strings.Contains(got, "database") {
		t.Fatalf("error %q does not point at the DNS credential — "+
			"an operator cannot tell this apart from an http-01 failure", err)
	}
	for _, wrong := range []string{"http-01", "tls-alpn", "port 80", "autocert"} {
		if strings.Contains(got, wrong) {
			t.Fatalf("error %q mentions %q, so issuance fell back to the challenge "+
				"the operator configured AWAY from", err, wrong)
		}
	}
}

func TestWildcardRequestAddsTheWildcardWithoutDroppingTheApex(t *testing.T) {
	// A certificate for *.example.com does NOT cover example.com — a TLS
	// wildcard matches exactly one label. Someone ticking "wildcard" wants both,
	// and replacing rather than adding would silently stop serving the apex.
	req := certIssueRequest{Domains: []string{"example.com", "other.com"}, Wildcard: true}
	names := req.Domains
	for _, d := range req.Domains {
		names = append(names, "*."+d)
	}
	want := map[string]bool{"example.com": true, "other.com": true, "*.example.com": true, "*.other.com": true}
	if len(names) != len(want) {
		t.Fatalf("got %v", names)
	}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("unexpected name %q in %v", n, names)
		}
	}
}
