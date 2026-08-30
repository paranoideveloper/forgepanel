// Package netegress is the one place the panel builds an HTTP client for a
// request it makes to the internet.
//
// Every such call — the update check, Telegram, the DNS providers, GeoIP, the
// ForgeEdge and WARP APIs, geodata downloads — was a bare &http.Client{Timeout}
// with a nil Transport. Go's zero Transport does consult HTTP_PROXY, so the
// environment would at least have worked; but nothing in the tree ever set those
// variables, no packaging or unit file exported them, and there was no way to
// configure a proxy from the panel at all.
//
// That matters most exactly where the panel is most useful. On a censored
// network the panel is typically the one machine that can already reach the
// outside — it is running the tunnels — and yet its own outbound calls went
// direct and failed: no update check, no Telegram alerts, no certificate
// issuance through a provider API, and a GeoIP lookup that hit three
// third-party services on every call with no cache.
//
// The proxy is read per request rather than baked into a Transport at
// construction, so changing it in the panel takes effect immediately instead of
// at the next restart.
package netegress

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.RWMutex
	current *url.URL
	raw     string
)

// Set configures the egress proxy. An empty string clears it, which restores
// the environment-variable behaviour (including NO_PROXY).
func Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		mu.Lock()
		current, raw = nil, ""
		mu.Unlock()
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("egress proxy %q is not a URL: %w", s, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("egress proxy scheme %q is not supported; use http, https, socks5 or socks5h", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("egress proxy %q has no host", s)
	}
	mu.Lock()
	current, raw = u, s
	mu.Unlock()
	return nil
}

// Current reports the configured proxy, empty when none is set.
func Current() string {
	mu.RLock()
	defer mu.RUnlock()
	return raw
}

// proxyFor is consulted on EVERY request rather than once at construction, so a
// proxy changed in the panel applies to the next call instead of the next
// restart. Falling back to the environment keeps NO_PROXY and any existing
// deployment's HTTP_PROXY working when nothing is configured here.
func proxyFor(req *http.Request) (*url.URL, error) {
	mu.RLock()
	u := current
	mu.RUnlock()
	if u != nil {
		return u, nil
	}
	return http.ProxyFromEnvironment(req)
}

// Transport returns a transport that routes through the configured proxy.
func Transport() *http.Transport {
	base, _ := http.DefaultTransport.(*http.Transport)
	t := base.Clone()
	t.Proxy = proxyFor
	return t
}

// Client is the constructor every internet-bound call site uses.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: Transport(), Timeout: timeout}
}

// Probe checks that a target is reachable the way the panel would reach it —
// through the proxy if one is set. It is what the settings page's test button
// calls, so an operator finds out the proxy is wrong there rather than from a
// missing Telegram alert days later.
func Probe(ctx context.Context, target string) error {
	if strings.TrimSpace(target) == "" {
		target = "https://api.github.com/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return err
	}
	resp, err := Client(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%s answered %s", target, resp.Status)
	}
	return nil
}
