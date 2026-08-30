package netegress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The sink that was proven reachable end to end: Settings -> Egress -> Test
// HEADs whatever the operator types. The assertion that matters is that the
// PACKET was never sent, not that an error string changed — a guard that
// refuses after the dial has already done the port scan.
func TestProbeRefusesALoopbackTarget(t *testing.T) {
	reset(t)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	err := Probe(context.Background(), srv.URL)

	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("the panel connected to its own loopback: %d request(s) reached the internal listener", got)
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("Probe(%s) returned %v, want a *BlockedError", srv.URL, err)
	}
}

// The policy split is the design decision of this change, so it is pinned
// rather than left to whichever branch happened to be written last.
func TestTheTwoPoliciesDifferOnlyOnWhatAnOperatorLegitimatelyTargets(t *testing.T) {
	cases := []struct {
		addr               string
		strict, noMetadata bool
		why                string
	}{
		{"169.254.169.254", true, true, "the AWS/GCP/Azure/DO/Hetzner metadata endpoint"},
		{"::ffff:169.254.169.254", true, true, "the same endpoint spelled as IPv4-mapped IPv6"},
		{"fe80::a9fe:a9fe", true, true, "IPv6 link-local"},
		{"fd00:ec2::254", true, true, "the AWS IMDSv6 endpoint, a ULA that IsLinkLocalUnicast misses"},
		{"100.100.100.200", true, true, "the Alibaba metadata endpoint, in CGNAT so IsPrivate misses it"},
		{"127.0.0.1", true, false, "loopback: refused for a fetch, allowed for an internal webhook receiver"},
		{"10.0.0.5", true, false, "RFC1918: the documented internal-receiver case"},
		{"192.168.1.10", true, false, "RFC1918"},
		{"fc00::1", true, false, "IPv6 unique-local"},
		{"100.64.0.1", true, false, "CGNAT, which net.IP.IsPrivate does not cover"},
		{"0.0.0.0", true, false, "the unspecified address"},
		{"192.0.0.1", true, false, "IETF protocol assignments"},
		{"198.18.0.1", true, false, "the benchmarking range"},
		{"1.1.1.1", false, false, "public unicast: allowed everywhere"},
		{"2606:4700:4700::1111", false, false, "public IPv6 unicast"},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.addr)
		if ip == nil {
			t.Fatalf("%s is not parseable", tc.addr)
		}
		if _, got := blockedIP(PolicyStrict, ip); got != tc.strict {
			t.Errorf("blockedIP(PolicyStrict, %s) = %v, want %v — %s", tc.addr, got, tc.strict, tc.why)
		}
		if _, got := blockedIP(PolicyNoMetadata, ip); got != tc.noMetadata {
			t.Errorf("blockedIP(PolicyNoMetadata, %s) = %v, want %v — %s", tc.addr, got, tc.noMetadata, tc.why)
		}
	}
}

func TestAURLIsRefusedBeforeAnythingIsResolved(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"ftp://example.com/hook", "http or https"},
		{"http://", "no host"},
	} {
		if _, err := ValidateURL(PolicyNoMetadata, tc.raw); err == nil {
			t.Errorf("ValidateURL(%q) was accepted", tc.raw)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ValidateURL(%q) = %v, want a message about %q", tc.raw, err, tc.want)
		}
	}
}

// A lookup FAILURE is not a refusal. Getting this backwards is how the fix
// becomes "the panel can no longer reach anything" on the censored networks it
// is deployed on, where local DNS is broken and the proxy resolves fine.
func TestAFailedLookupIsAllowedThroughWhenAProxyIsConfigured(t *testing.T) {
	reset(t)
	if _, err := GuardTarget(context.Background(), PolicyStrict, "http://nx.invalid/x"); err == nil {
		t.Fatal("an unresolvable host was allowed with no proxy configured")
	}
	if err := Set("socks5://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	if _, err := GuardTarget(context.Background(), PolicyStrict, "http://nx.invalid/x"); err != nil {
		t.Fatalf("with a proxy configured a lookup failure must not block the request: %v", err)
	}
	// A refusal is still a refusal, proxy or not.
	var be *BlockedError
	if _, err := GuardTarget(context.Background(), PolicyStrict, "http://169.254.169.254/x"); !errors.As(err, &be) {
		t.Fatalf("with a proxy configured the metadata endpoint returned %v, want a *BlockedError", err)
	}
}

// The dial-time hook is the classic thing to leave dead: Transport() is a Clone
// that already carries a DialContext, so building a Dialer and not assigning it
// passes every resolve-time test while doing nothing. Reach the listener by an
// address ValidateURL cannot pre-judge and check the dial itself is stopped.
func TestTheDialTimeHookIsActuallyInstalled(t *testing.T) {
	reset(t)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The URL is never passed through GuardTarget here, so only the Control
	// hook can stop this.
	resp, err := GuardedClient(PolicyStrict, 5*time.Second).Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("GuardedClient dialled loopback %d time(s): the Control hook is not installed", got)
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("GuardedClient returned %v, want a *BlockedError from the dialer", err)
	}
}

func TestFetchCapsTheBodyRefusesRedirectsIntoTheMetadataServiceAndObeysThePolicy(t *testing.T) {
	reset(t)
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 4096))
	}))
	defer big.Close()

	// Loopback is allowed under PolicyNoMetadata, which is what makes it usable
	// as a stand-in receiver here.
	if _, _, err := Fetch(context.Background(), PolicyNoMetadata, big.URL, 4096); err != nil {
		t.Fatalf("a body exactly at the limit was refused: %v", err)
	}
	// One byte over must be an ERROR, not a silent truncation.
	body, status, err := Fetch(context.Background(), PolicyNoMetadata, big.URL, 4095)
	if err == nil {
		t.Fatalf("an oversized body was truncated to %d bytes and returned status %d with no error", len(body), status)
	}
	if !strings.Contains(err.Error(), "more than 4095 bytes") {
		t.Fatalf("Fetch over the cap = %v, want the cap message", err)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirect.Close()
	var be *BlockedError
	if _, _, err := Fetch(context.Background(), PolicyNoMetadata, redirect.URL, MaxFetchBytes); !errors.As(err, &be) {
		t.Fatalf("a redirect into the metadata service returned %v, want a *BlockedError", err)
	}

	if _, _, err := Fetch(context.Background(), PolicyStrict, big.URL, MaxFetchBytes); !errors.As(err, &be) {
		t.Fatalf("PolicyStrict fetched a loopback target: %v", err)
	}
}

// Embedded credentials are ACCEPTED on purpose, and this pins it.
//
// Refusing them is not an SSRF control — the resolved IP is what decides that,
// and it is checked either way — and ValidateURL runs against every stored
// webhook row at delivery time, so the refusal turned every receiver behind
// HTTP basic auth into a permanent failure on upgrade. webhook.Endpoint has no
// header field and the panel offers none, so the error's own remediation named
// something an operator could not do.
func TestEmbeddedCredentialsAreNotAnSSRFControl(t *testing.T) {
	u, err := ValidateURL(PolicyNoMetadata, "https://user:pw@example.com/x")
	if err != nil {
		t.Fatalf("a credentialed public URL was refused: %v", err)
	}
	if u.User == nil {
		t.Fatal("the credentials were stripped; the receiver would answer 401")
	}
	// The address still decides. Same URL shape, internal target, refused.
	if _, err := ValidateURL(PolicyStrict, "https://user:pw@127.0.0.1/x"); err == nil {
		t.Fatal("credentials smuggled an internal target past the guard")
	}
}
