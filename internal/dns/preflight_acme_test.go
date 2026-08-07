package dns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPreflightHTTP01ChallengePathReachable(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	var probed string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	requireNoError(t, err)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// "127.0.0.1" is a legal DNS name syntactically, so the probe URL resolves
	// straight to the listener without touching real DNS.
	const probeHost = "127.0.0.1"
	res := newFakeResolver()
	res.IPs[probeHost] = []string{probeHost}

	pf := newPreflight(t, res, now, nil)
	pf.HTTPChallengePort = port
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: probeHost, ExpectIP: probeHost, Challenge: ChallengeHTTP01,
	})
	requireNoError(t, err)

	c := checkByName(t, report, "challenge-path")
	if c.Status != StatusPass {
		t.Fatalf("a 404 on the challenge path still proves reachability, got %s: %s", c.Status, c.Detail)
	}
	requireContains(t, c.Detail, "HTTP 404", "challenge path detail reports the status")
	requireContains(t, probed, "/.well-known/acme-challenge/", "probe used the real ACME path")
}

// A port-80 challenge that cannot be reached must explain the firewall and
// offer the dns-01 alternative.
func TestPreflightHTTP01UnreachableExplainsPortAndAlternative(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}

	pf := newPreflight(t, res, now, nil)
	pf.HTTP = &http.Client{Timeout: 250 * time.Millisecond}
	pf.HTTPChallengePort = 1 // nothing listens here
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", Challenge: ChallengeHTTP01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "challenge-path")
	if c.Status != StatusFail {
		t.Fatalf("expected the challenge path to fail, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "inbound TCP 1", "http-01 remediation names the port")
	requireContains(t, c.Remediation, "--challenge dns-01", "http-01 remediation offers the alternative")
}

func TestPreflightACMEDirectoryUnreachable(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
	res.TXT["_acme-challenge.ws.example.com"] = nil

	pf := newPreflight(t, res, now, nil)
	pf.ACMEDirectoryURL = "http://127.0.0.1:1/directory"
	pf.HTTP = &http.Client{Timeout: 250 * time.Millisecond}
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "acme-directory")
	if c.Status != StatusFail {
		t.Fatalf("expected a failure, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "egress firewall", "acme reachability remediation")
	requireContains(t, c.Remediation, "forgectl cert import", "acme reachability offers a fallback")
}

// TLS interception answers 200 with something that is not a directory; that is
// worth a warning, because issuance will fail confusingly later.
func TestPreflightACMEDirectoryInterceptedIsWarning(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	captive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>captive portal</html>"))
	}))
	t.Cleanup(captive.Close)

	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
	res.TXT["_acme-challenge.ws.example.com"] = nil

	pf := newPreflight(t, res, now, nil)
	pf.ACMEDirectoryURL = captive.URL
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "acme-directory")
	if c.Status != StatusWarn {
		t.Fatalf("expected a warning, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "TLS-inspecting proxy", "intercepted directory remediation")
	// A warning must not fail the report.
	if !report.OK {
		t.Fatalf("a warning should not block issuance: %+v", report.Failures())
	}
}

func TestPreflightRateLimitHeadroom(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	baseRes := func() *fakeResolver {
		res := newFakeResolver()
		res.IPs["ws.example.com"] = []string{"203.0.113.10"}
		res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
		res.TXT["_acme-challenge.ws.example.com"] = nil
		return res
	}
	zone := &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}}

	t.Run("exhausted", func(t *testing.T) {
		pf := newPreflight(t, baseRes(), now, ctEntries(50, "other.example.com", now.Add(-2*24*time.Hour)))
		report, err := pf.Run(context.Background(), PreflightInput{
			Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01, Zone: zone,
		})
		requireNoError(t, err)
		c := checkByName(t, report, "rate-limit-headroom")
		if c.Status != StatusFail {
			t.Fatalf("expected a failure at the weekly limit, got %s: %s", c.Status, c.Detail)
		}
		requireContains(t, c.Remediation, "rolling seven-day window", "exhausted remediation")
		requireContains(t, c.Remediation, "SANs", "exhausted remediation offers a workaround")
	})

	t.Run("duplicates", func(t *testing.T) {
		pf := newPreflight(t, baseRes(), now, ctEntries(5, "ws.example.com", now.Add(-time.Hour)))
		report, err := pf.Run(context.Background(), PreflightInput{
			Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01, Zone: zone,
		})
		requireNoError(t, err)
		c := checkByName(t, report, "rate-limit-headroom")
		if c.Status != StatusFail {
			t.Fatalf("expected the duplicate limit to fail, got %s: %s", c.Status, c.Detail)
		}
		requireContains(t, c.Detail, "duplicate-certificate limit", "duplicate detail")
	})

	t.Run("near the limit warns", func(t *testing.T) {
		pf := newPreflight(t, baseRes(), now, ctEntries(47, "other.example.com", now.Add(-time.Hour)))
		report, err := pf.Run(context.Background(), PreflightInput{
			Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01, Zone: zone,
		})
		requireNoError(t, err)
		c := checkByName(t, report, "rate-limit-headroom")
		if c.Status != StatusWarn {
			t.Fatalf("expected a warning near the limit, got %s: %s", c.Status, c.Detail)
		}
		if !report.OK {
			t.Fatal("a warning must not block issuance")
		}
	})

	t.Run("old certificates fall out of the window", func(t *testing.T) {
		pf := newPreflight(t, baseRes(), now, ctEntries(50, "other.example.com", now.Add(-30*24*time.Hour)))
		report, err := pf.Run(context.Background(), PreflightInput{
			Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01, Zone: zone,
		})
		requireNoError(t, err)
		c := checkByName(t, report, "rate-limit-headroom")
		if c.Status != StatusPass {
			t.Fatalf("month-old certificates are outside the window, got %s: %s", c.Status, c.Detail)
		}
	})

	// An unreachable CT log must never block provisioning.
	t.Run("unreachable log only warns", func(t *testing.T) {
		pf := newPreflight(t, baseRes(), now, nil)
		pf.CertLogURL = "http://127.0.0.1:1/?q=%s"
		pf.HTTP = &http.Client{Timeout: 250 * time.Millisecond}
		report, err := pf.Run(context.Background(), PreflightInput{
			Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01, Zone: zone,
		})
		requireNoError(t, err)
		c := checkByName(t, report, "rate-limit-headroom")
		if c.Status != StatusWarn {
			t.Fatalf("expected a warning, got %s", c.Status)
		}
		requireContains(t, c.Remediation, "too many certificates already issued", "unknown headroom remediation")
	})
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"ws.example.com":     "example.com",
		"a.b.example.com":    "example.com",
		"example.com":        "example.com",
		"node.example.co.uk": "example.co.uk",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatReportShowsRemediationOnlyForProblems(t *testing.T) {
	report := &PreflightReport{
		Domain: "ws.example.com", Challenge: ChallengeDNS01, OK: false,
		Checks: []Check{
			{Name: "zone-active", Status: StatusPass, Detail: "fine", Remediation: "should not appear"},
			{Name: "public-resolution", Status: StatusFail, Detail: "missing", Remediation: "create the record"},
		},
	}
	out := FormatReport(report)
	requireContains(t, out, "NOT READY", "verdict")
	requireContains(t, out, "fix: create the record", "failure remediation shown")
	if strings.Contains(out, "should not appear") {
		t.Fatal("a passing check must not print remediation")
	}
}
