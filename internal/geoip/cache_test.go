package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A country lookup must not hit the network twice for the same host.
//
// Without a cache every call reached three third-party services — and the panel
// asks per inbound, on every render of a list. That is slow everywhere and fails
// outright on the censored networks this panel exists for.
func TestASecondLookupDoesNotHitTheNetwork(t *testing.T) {
	ResetCache()
	t.Cleanup(ResetCache)

	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		_, _ = w.Write([]byte("NL"))
	}))
	defer srv.Close()

	oldP, oldC := Providers, HTTPClient
	Providers = []Provider{{srv.URL + "/%s", ""}}
	HTTPClient = srv.Client()
	t.Cleanup(func() { Providers, HTTPClient = oldP, oldC })

	for i := 0; i < 3; i++ {
		cc, err := LookupCountry(context.Background(), "198.51.100.7")
		if err != nil {
			t.Fatal(err)
		}
		if cc != "NL" {
			t.Fatalf("got %q", cc)
		}
	}
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Errorf("three lookups of the same host made %d network calls, want 1", n)
	}
}

// A stale answer must eventually be refreshed, or a corrected country is never
// picked up for the life of the process.
func TestAnExpiredEntryIsLookedUpAgain(t *testing.T) {
	ResetCache()
	t.Cleanup(ResetCache)

	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		_, _ = w.Write([]byte("DE"))
	}))
	defer srv.Close()

	oldP, oldC, oldNow := Providers, HTTPClient, timeNow
	Providers = []Provider{{srv.URL + "/%s", ""}}
	HTTPClient = srv.Client()
	base := time.Unix(1700000000, 0)
	timeNow = func() time.Time { return base }
	t.Cleanup(func() { Providers, HTTPClient, timeNow = oldP, oldC, oldNow })

	if _, err := LookupCountry(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	timeNow = func() time.Time { return base.Add(cacheTTL + time.Minute) }
	if _, err := LookupCountry(context.Background(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt64(&calls); n != 2 {
		t.Errorf("an expired entry made %d calls, want 2 — the cache never expires", n)
	}
}

// The map is bounded. Importing a large subscription looks up many hosts, and an
// unbounded map would grow for the life of the process.
func TestTheCacheIsBounded(t *testing.T) {
	ResetCache()
	t.Cleanup(ResetCache)
	now := time.Unix(1700000000, 0)
	for i := 0; i < cacheMax+50; i++ {
		cachePut(string(rune('a'+i%26))+string(rune(i)), "NL", now)
	}
	cache.Lock()
	n := len(cache.m)
	cache.Unlock()
	if n > cacheMax {
		t.Errorf("cache holds %d entries, above the %d bound", n, cacheMax)
	}
}
