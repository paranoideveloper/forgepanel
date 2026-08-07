package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// acmeDirectoryServer serves a well-formed ACME directory.
func acmeDirectoryServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   "https://acme.test/acme/new-nonce",
			"newAccount": "https://acme.test/acme/new-acct",
			"newOrder":   "https://acme.test/acme/new-order",
			"revokeCert": "https://acme.test/acme/revoke-cert",
			"keyChange":  "https://acme.test/acme/key-change",
		})
	}))
	t.Cleanup(s.Close)
	return s
}

// ctLogServer serves crt.sh-shaped JSON with `count` certificates issued
// `age` ago covering `names`.
func ctLogServer(t *testing.T, entries []crtShEntry) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	t.Cleanup(s.Close)
	return s
}

func ctEntries(count int, name string, at time.Time) []crtShEntry {
	out := make([]crtShEntry, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, crtShEntry{
			NameValue: name, IssuerName: "C=US, O=Let's Encrypt, CN=R3",
			NotBefore: at.Format("2006-01-02T15:04:05"),
		})
	}
	return out
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// newPreflight builds a Preflight with every network dependency pointed at a
// local server, so a run touches nothing outside the test.
func newPreflight(t *testing.T, res Resolver, now time.Time, entries []crtShEntry) Preflight {
	t.Helper()
	acme := acmeDirectoryServer(t)
	ct := ctLogServer(t, entries)
	return Preflight{
		Resolver: res, HTTP: acme.Client(), Now: fixedNow(now),
		ACMEDirectoryURL: acme.URL,
		CertLogURL:       ct.URL + "/?q=%s",
	}
}

func checkByName(t *testing.T, report *PreflightReport, name string) Check {
	t.Helper()
	for _, c := range report.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, report.Checks)
	return Check{}
}

func TestPreflightHappyPathDNS01(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	res.TXT["_acme-challenge.ws.example.com"] = nil

	pf := newPreflight(t, res, now, ctEntries(2, "a.example.com", now.Add(-time.Hour)))
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", Provider: "cloudflare",
			NameServers: []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	if !report.OK {
		t.Fatalf("expected the report to pass, failures: %+v", report.Failures())
	}
	for _, name := range []string{"zone-active", "public-resolution", "ns-delegation", "challenge-path", "acme-directory", "rate-limit-headroom"} {
		if c := checkByName(t, report, name); c.Status == StatusFail {
			t.Fatalf("check %q failed: %s", name, c.Detail)
		}
	}
	headroom := checkByName(t, report, "rate-limit-headroom")
	requireContains(t, headroom.Detail, "2 of 50", "headroom detail")
}

func TestPreflightMissingRecordSaysCreateIt(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	if report.OK {
		t.Fatal("expected the report to fail")
	}
	c := checkByName(t, report, "public-resolution")
	requireContains(t, c.Detail, "NXDOMAIN", "missing record detail")
	requireContains(t, c.Remediation, "has not been created", "missing record remediation")

	// The aggregated error must carry the remediation, not just a raw failure.
	e := requireKind(t, report.Err(), KindPreflight)
	requireContains(t, e.Remediation, "has not been created", "aggregated remediation")
}

// A resolver that cannot be reached is a different problem from a name that
// does not exist, and must produce different advice.
func TestPreflightDistinguishesBrokenResolverFromMissingName(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.Fail["ws.example.com"] = fmt.Errorf("read udp 1.1.1.1:53: i/o timeout")
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "public-resolution")
	requireContains(t, c.Remediation, "recursive resolvers were unreachable", "broken resolver remediation")
	requireContains(t, c.Remediation, "outbound UDP/TCP 53", "broken resolver remediation")
}

// Behind a CDN the record deliberately does not resolve to the origin, so a
// mismatch there must not be reported as a failure.
func TestPreflightProxiedMismatchIsExpected(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"104.16.1.1", "104.16.2.2"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
	res.TXT["_acme-challenge.ws.example.com"] = nil

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Proxied: true, Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "public-resolution")
	if c.Status != StatusPass {
		t.Fatalf("a proxied record pointing at the edge is correct, got %s: %s", c.Status, c.Detail)
	}
	requireContains(t, c.Detail, "expected for a proxied record", "proxied detail")
}

func TestPreflightUnproxiedMismatchTellsYouToUpdateTheRecord(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"198.51.100.5"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "public-resolution")
	if c.Status != StatusFail {
		t.Fatalf("expected a failure, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "203.0.113.10", "mismatch remediation names the right IP")
	requireContains(t, c.Remediation, "previous TTL", "mismatch remediation mentions caching")
}

// The nameserver delegation lives at the registrar, not in the provider's DNS
// table — the remediation has to say so, because getting this wrong is the
// single most common support question.
func TestPreflightNSMismatchPointsAtTheRegistrar(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"ns1.oldhost.net", "ns2.oldhost.net"}
	res.TXT["_acme-challenge.ws.example.com"] = nil

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", Provider: "cloudflare",
			NameServers: []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "ns-delegation")
	if c.Status != StatusFail {
		t.Fatalf("expected the delegation check to fail, got %s", c.Status)
	}
	requireContains(t, c.Detail, "ns1.oldhost.net", "delegation detail names what is published")
	requireContains(t, c.Remediation, "REGISTRAR", "delegation remediation")
	requireContains(t, c.Remediation, "amy.ns.cloudflare.com", "delegation remediation names the target")
}

func TestPreflightDelegatedSubdomainCarriesTheACMEConsequence(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.team.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
	res.NS["team.example.com"] = []string{"ns1.otherdns.net"}

	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active", "amy.ns.cloudflare.com")
	resolution, err := ResolveZone(context.Background(), m.client(), res, "ws.team.example.com")
	requireNoError(t, err)

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.team.example.com", ExpectIP: "203.0.113.10",
		Resolution: resolution, Challenge: ChallengeDNS01,
	})
	requireNoError(t, err)
	c := checkByName(t, report, "ns-delegation")
	if c.Status != StatusFail {
		t.Fatalf("expected a delegation failure, got %s: %s", c.Status, c.Detail)
	}
	requireContains(t, c.Remediation, "NXDOMAIN looking up TXT", "delegated ACME consequence")
}

func TestPreflightZoneNotActiveFailsFirst(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "pending", Provider: "cloudflare",
			NameServers: []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "zone-active")
	if c.Status != StatusFail {
		t.Fatalf("expected a failure for a pending zone, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "amy.ns.cloudflare.com and bob.ns.cloudflare.com", "pending zone remediation")
	requireContains(t, c.Remediation, "Nothing else in this list can pass", "pending zone remediation")
}

// A SERVFAIL on the challenge name means a published TXT would never be seen —
// distinct from NXDOMAIN, which is the normal state before issuance.
func TestPreflightDNS01ChallengePathDistinguishesSERVFAIL(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	res := newFakeResolver()
	res.IPs["ws.example.com"] = []string{"203.0.113.10"}
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com"}
	res.Fail["TXT:_acme-challenge.ws.example.com"] = fmt.Errorf("server misbehaving (SERVFAIL)")

	pf := newPreflight(t, res, now, nil)
	report, err := pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	c := checkByName(t, report, "challenge-path")
	if c.Status != StatusFail {
		t.Fatalf("expected a failure on SERVFAIL, got %s", c.Status)
	}
	requireContains(t, c.Remediation, "DNSSEC", "SERVFAIL remediation names the usual cause")

	// NXDOMAIN, by contrast, is fine: nothing has been published yet.
	res.Fail = map[string]error{}
	report, err = pf.Run(context.Background(), PreflightInput{
		Domain: "ws.example.com", ExpectIP: "203.0.113.10", Challenge: ChallengeDNS01,
		Zone: &Zone{Name: "example.com", Status: "active", NameServers: []string{"amy.ns.cloudflare.com"}},
	})
	requireNoError(t, err)
	if c := checkByName(t, report, "challenge-path"); c.Status != StatusPass {
		t.Fatalf("NXDOMAIN on the challenge name is expected before issuance, got %s: %s", c.Status, c.Detail)
	}
}

// An http-01 probe against a listener that 404s every challenge path still
// proves reachability: only a connection failure is disqualifying, because the
