package geoip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func withProviders(t *testing.T, ps []Provider) {
	t.Helper()
	old, oldc := Providers, HTTPClient
	Providers = ps
	HTTPClient = &http.Client{Timeout: 3 * time.Second}
	// Answers are cached per host, and these tests reuse hosts like 8.8.8.8. A
	// code cached by an earlier test would be returned without the provider
	// being called at all, so a test asserting that a bad code is REJECTED would
	// pass on a good one cached moments before.
	ResetCache()
	t.Cleanup(func() {
		Providers, HTTPClient = old, oldc
		ResetCache()
	})
}

func TestLookupJSONProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The public IP must be in the path, not the private one.
		if !strings.Contains(r.URL.Path, "203.0.113.7") {
			t.Errorf("expected the public IP in the request, got %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"country_code":"de"}`))
	}))
	defer srv.Close()
	withProviders(t, []Provider{{srv.URL + "/%s", "country_code"}})
	cc, err := LookupCountry(context.Background(), "203.0.113.7")
	if err != nil || cc != "DE" {
		t.Fatalf("got %q err=%v, want DE", cc, err)
	}
}

func TestLookupPlainTextProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("NL\n"))
	}))
	defer srv.Close()
	withProviders(t, []Provider{{srv.URL + "/%s/country", ""}})
	cc, err := LookupCountry(context.Background(), "198.51.100.4")
	if err != nil || cc != "NL" {
		t.Fatalf("got %q err=%v, want NL", cc, err)
	}
}

func TestLookupFallsBackAcrossProviders(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"countryCode":"US"}`))
	}))
	defer good.Close()
	withProviders(t, []Provider{{bad.URL + "/%s", "cc"}, {good.URL + "/%s", "countryCode"}})
	cc, err := LookupCountry(context.Background(), "8.8.8.8")
	if err != nil || cc != "US" {
		t.Fatalf("got %q err=%v, want US (fallback)", cc, err)
	}
}

func TestPrivateIPUsesEgressLookup(t *testing.T) {
	var gotIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = strings.Trim(r.URL.Path, "/")
		_, _ = w.Write([]byte(`{"country_code":"IR"}`))
	}))
	defer srv.Close()
	withProviders(t, []Provider{{srv.URL + "/%s", "country_code"}})
	// A private/LAN address must not be sent to the provider — it asks for the
	// caller's own egress IP instead (empty path segment).
	cc, err := LookupCountry(context.Background(), "192.168.1.10")
	if err != nil || cc != "IR" {
		t.Fatalf("got %q err=%v, want IR", cc, err)
	}
	if gotIP != "" {
		t.Fatalf("a private IP was leaked to the provider: %q", gotIP)
	}
}

func TestBogusCodeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"country_code":"Germany"}`) // not alpha-2
	}))
	defer srv.Close()
	withProviders(t, []Provider{{srv.URL + "/%s", "country_code"}})
	if _, err := LookupCountry(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("a non-alpha2 code should be rejected, not returned")
	}
}

// Guarded live check against the real services.
func TestLiveLookup(t *testing.T) {
	if os.Getenv("GEOIP_LIVE") == "" {
		t.Skip("set GEOIP_LIVE=1 to hit real geoip services")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if cc, err := LookupCountry(ctx, "8.8.8.8"); err != nil || cc != "US" {
		t.Fatalf("8.8.8.8 -> %q err=%v, want US", cc, err)
	}
}
