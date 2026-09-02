// Package geoip resolves a host to its ISO-3166 alpha-2 country code, so the
// panel can auto-fill an inbound's country for the {FLAG}/{COUNTRY} naming
// tokens instead of the operator typing it. It uses public, key-less geoip
// services with graceful fallback; when they are all unreachable (a locked-down
// network), the caller keeps the manual country field. No database is bundled.
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"strings"
	"sync"
	"time"
)

// Providers are tried in order; the first to return a plausible 2-letter code
// wins. Passing an empty ip asks the provider for the CALLER's own public IP —
// used when the host resolves to a private address (the panel behind NAT), so
// "detect" still reports the server's real egress country. Vars so tests can
// point them at a mock.
var (
	// HTTPClient is the client used for lookups (overridable in tests).
	HTTPClient = netegress.Client(6 * time.Second)
	// Providers: {url-with-%s-for-ip, json-field-or-"" for plain-text body}.
	Providers = []Provider{
		{"https://ipwho.is/%s", "country_code"},
		{"https://ipapi.co/%s/country/", ""},
		{"http://ip-api.com/json/%s?fields=countryCode", "countryCode"},
	}
)

// timeNow is a variable so a test can age the cache without sleeping.
var timeNow = time.Now

// Provider is a keyless geoip endpoint. URLTmpl has a single %s for the IP; Field
// is the JSON field to read, or "" when the whole (trimmed) body is the code.
type Provider struct {
	URLTmpl string
	Field   string
}

// cacheTTL is how long a country code is trusted. A server does not change
// country, so this is long; it is bounded at all only so a corrected answer is
// eventually picked up.
const cacheTTL = 24 * time.Hour

// cacheMax bounds the map. Country lookups are keyed by host, and an importer
// pulling in a large subscription would otherwise grow this without limit for
// the life of the process.
const cacheMax = 4096

type cacheEntry struct {
	code string
	at   time.Time
}

var cache = struct {
	sync.Mutex
	m map[string]cacheEntry
}{m: map[string]cacheEntry{}}

// ResetCache clears the cache. Tests use it; nothing in the panel does.
func ResetCache() {
	cache.Lock()
	cache.m = map[string]cacheEntry{}
	cache.Unlock()
}

func cacheGet(host string, now time.Time) (string, bool) {
	cache.Lock()
	defer cache.Unlock()
	e, ok := cache.m[host]
	if !ok || now.Sub(e.at) > cacheTTL {
		return "", false
	}
	return e.code, true
}

func cachePut(host, code string, now time.Time) {
	cache.Lock()
	defer cache.Unlock()
	if len(cache.m) >= cacheMax {
		cache.m = map[string]cacheEntry{}
	}
	cache.m[host] = cacheEntry{code: code, at: now}
}

// LookupCountry resolves host (an IP or a domain) to an alpha-2 country code.
//
// Answers are cached. Without it every call reached three third-party services
// over the network — on a panel listing inbounds, once per inbound per render —
// which is slow everywhere and fails outright on the censored networks where
// this panel is most used.
func LookupCountry(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("no host to look up")
	}
	now := timeNow()
	if cc, ok := cacheGet(host, now); ok {
		return cc, nil
	}
	ip := resolvePublicIP(ctx, host)
	// ip == "" → let the provider geolocate the panel's own egress IP.

	var lastErr error
	for _, p := range Providers {
		cc, err := p.lookup(ctx, ip)
		if err != nil {
			lastErr = err
			continue
		}
		if isAlpha2(cc) {
			out := strings.ToUpper(cc)
			cachePut(host, out, now)
			return out, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no provider returned a country code")
	}
	return "", lastErr
}

func (p Provider) lookup(ctx context.Context, ip string) (string, error) {
	url := fmt.Sprintf(p.URLTmpl, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "forgepanel-geoip")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if p.Field == "" {
		return strings.TrimSpace(string(body)), nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", err
	}
	if v, ok := m[p.Field].(string); ok {
		return v, nil
	}
	return "", fmt.Errorf("%s: no %q in response", url, p.Field)
}

// resolvePublicIP turns host into a public IP string, or "" if host is a private
// or loopback address (so the provider falls back to the caller's egress IP).
func resolvePublicIP(ctx context.Context, host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivate(ip) {
			return ""
		}
		return ip.String()
	}
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return ""
	}
	// Prefer a public IPv4, then any public IP.
	for _, ip := range ips {
		if ip.To4() != nil && !isPrivate(ip) {
			return ip.String()
		}
	}
	for _, ip := range ips {
		if !isPrivate(ip) {
			return ip.String()
		}
	}
	return ""
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func isAlpha2(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}
