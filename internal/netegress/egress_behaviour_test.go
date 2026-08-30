package netegress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitHit takes the next proxy hit, or reports which proxy was never reached.
// A bare receive here DEADLOCKS when the request goes direct instead of through
// the proxy, which is exactly the regression this test exists to catch — so the
// failure mode would be a hung suite rather than a red test.
func waitHit(t *testing.T, hits <-chan string) string {
	t.Helper()
	select {
	case h := <-hits:
		return h
	case <-time.After(3 * time.Second):
		t.Fatal("no proxy was reached: the request went direct")
		return ""
	}
}

func reset(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { _ = Set("") })
	if err := Set(""); err != nil {
		t.Fatal(err)
	}
}

// A request must actually traverse the configured proxy. Asserting only that
// Set stored the string would pass against a Transport that never consults it.
func TestAConfiguredProxyActuallyCarriesTheRequest(t *testing.T) {
	reset(t)
	var mu sync.Mutex
	var sawAbsoluteURL bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A forward proxy receives the absolute URI, which is how we know the
		// request went through it rather than direct to the origin.
		mu.Lock()
		sawAbsoluteURL = strings.HasPrefix(r.RequestURI, "http://")
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer proxy.Close()

	if err := Set(proxy.URL); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	resp, err := Client(5 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("request did not go through the proxy: %v", err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if !sawAbsoluteURL {
		t.Error("the proxy did not receive a forward-proxy request")
	}
}

// The proxy is read per request, so changing it in the panel applies to the next
// call rather than the next restart. Baking it into the Transport at
// construction is the obvious implementation and gets this wrong.
func TestChangingTheProxyAppliesWithoutRebuildingTheClient(t *testing.T) {
	reset(t)
	hits := make(chan string, 4)
	mk := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits <- name
			w.WriteHeader(204)
		}))
	}
	a, b := mk("a"), mk("b")
	defer a.Close()
	defer b.Close()

	c := Client(5 * time.Second) // built ONCE, before either Set
	if err := Set(a.URL); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
	}
	if got := waitHit(t, hits); got != "a" {
		t.Fatalf("first request went to %q", got)
	}

	if err := Set(b.URL); err != nil {
		t.Fatal(err)
	}
	req2, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	if resp, err := c.Do(req2); err == nil {
		resp.Body.Close()
	}
	if got := waitHit(t, hits); got != "b" {
		t.Errorf("after the proxy changed the same client still used %q — it was baked in at "+
			"construction, so a change would need a restart", got)
	}
}

// A bad value must be refused where the operator can see it, not accepted and
// then silently break every outbound call.
func TestAnUnusableProxyIsRefused(t *testing.T) {
	reset(t)
	for _, bad := range []string{"ftp://host:1080", "not a url at all", "socks5://"} {
		if err := Set(bad); err == nil {
			t.Errorf("Set(%q) was accepted", bad)
		}
	}
	if Current() != "" {
		t.Errorf("a refused value was still stored: %q", Current())
	}
	for _, ok := range []string{"http://p:3128", "socks5://user:pw@p:1080", "socks5h://p:1080", "https://p:8443"} {
		if err := Set(ok); err != nil {
			t.Errorf("Set(%q): %v", ok, err)
		}
	}
}
