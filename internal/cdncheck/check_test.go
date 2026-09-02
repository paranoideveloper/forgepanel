package cdncheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Cloudflare's 5xx codes each name a different thing to fix. Reporting the
// number alone leaves the operator searching; these pin that every one of them
// produces an actionable sentence, because the whole point of the package is
// that the failure is invisible from the origin side.
//
// Measured on a live zone, and the reason this exists: a plain-HTTP origin on a
// proxied port answers 200 when tested directly and 525 through the edge.

// edgeReturning stands in for Cloudflare's edge, which is the thing whose
// answer is being interpreted — a real origin cannot produce these codes.
func edgeReturning(t *testing.T, code int) (host string, port int, client *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "test")
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	u := strings.TrimPrefix(srv.URL, "https://")
	h, p, _ := strings.Cut(u, ":")
	n, _ := strconv.Atoi(p)
	// The server's own client trusts its throwaway certificate. Production
	// verifies properly — an edge certificate that does not validate is itself
	// worth reporting — so the trust is granted here rather than removed there.
	return h, n, srv.Client()
}

// The check refuses to run on a port Cloudflare does not proxy, so the test
// server is reached through a port that is in the list.
func checkAt(t *testing.T, code int) Result {
	t.Helper()
	host, port, client := edgeReturning(t, code)
	// Temporarily treat the ephemeral port as proxied: the port list is a real
	// constraint being tested separately, and conflating the two would make
	// every case here fail for the wrong reason.
	old := ProxiedHTTPSPorts
	ProxiedHTTPSPorts = append(append([]int{}, old...), port)
	t.Cleanup(func() { ProxiedHTTPSPorts = old })
	return Checker{Client: client}.Check(context.Background(), host, port)
}

func TestEveryCloudflareFailureNamesItsFix(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string // a phrase the fix must contain
	}{
		{521, "listening"},
		{522, "firewall"},
		{523, "public IP"},
		{525, "serve TLS"},
		{526, "Full (Strict)"},
	} {
		t.Run(strconv.Itoa(tc.code), func(t *testing.T) {
			r := checkAt(t, tc.code)
			if r.Reached {
				t.Fatalf("%d was treated as reaching the origin", tc.code)
			}
			if r.Problem == "" {
				t.Errorf("%d produced no problem statement", tc.code)
			}
			if !strings.Contains(r.Fix, tc.want) {
				t.Errorf("%d fix = %q, want it to mention %q", tc.code, r.Fix, tc.want)
			}
		})
	}
}

// 525 is the one that matters most: it is what a plain-HTTP origin on a proxied
// port produces, and the operator's own test of that origin says 200.
func TestThe525FixExplainsWhyALocalTestLooksFine(t *testing.T) {
	r := checkAt(t, 525)
	for _, want := range []string{"HTTPS to the origin", "Flexible"} {
		if !strings.Contains(r.Fix, want) {
			t.Errorf("the 525 fix should mention %q, got %q", want, r.Fix)
		}
	}
}

// A 404 from the origin is a SUCCESS for this check: the question is whether
// Cloudflare could reach the origin, and a proxy endpoint answers a bare GET
// with exactly that.
func TestAnOriginAnsweringAtAllCountsAsReached(t *testing.T) {
	for _, code := range []int{200, 400, 404, 502} {
		r := checkAt(t, code)
		if !r.Reached {
			t.Errorf("status %d should count as reaching the origin", code)
		}
		if r.Problem != "" {
			t.Errorf("status %d reported a problem: %s", code, r.Problem)
		}
	}
}

// An inbound on a port Cloudflare does not proxy is unreachable through the CDN
// however healthy it is, and the record looks perfectly correct in the
// dashboard. Caught before any request is made.
func TestAnUnproxiedPortIsRefusedWithoutAskingTheNetwork(t *testing.T) {
	r := Check(context.Background(), "example.invalid", 8081)
	if r.Reached {
		t.Fatal("an unproxied port was reported as reachable")
	}
	if r.Status != 0 {
		t.Errorf("status = %d, want no request to have been made", r.Status)
	}
	if !strings.Contains(r.Problem, "8081") {
		t.Errorf("the problem should name the port, got %q", r.Problem)
	}
	if !strings.Contains(r.Fix, "443") {
		t.Errorf("the fix should list the ports that do work, got %q", r.Fix)
	}
}

func TestPortIsProxiedMatchesCloudflaresList(t *testing.T) {
	for _, p := range []int{443, 2053, 2083, 2087, 2096, 8443} {
		if !PortIsProxied(p) {
			t.Errorf("%d is a Cloudflare HTTPS port and was rejected", p)
		}
	}
	for _, p := range []int{80, 8080, 8081, 9443, 22} {
		if PortIsProxied(p) {
			t.Errorf("%d is not proxied for HTTPS and was accepted", p)
		}
	}
}

func TestAnUnreachableHostIsReportedNotPanicked(t *testing.T) {
	r := Check(context.Background(), "no-such-host.invalid", 443)
	if r.Reached {
		t.Fatal("an unresolvable host was reported as reachable")
	}
	if r.Problem == "" || r.Fix == "" {
		t.Error("an unreachable host should still explain itself")
	}
}
