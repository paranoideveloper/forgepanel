package api

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// loginLimiter enforces progressive login rate limiting per source IP (spec
// §12): after a burst of failures a source is locked out for an increasing
// window, blunting credential-stuffing without a dependency.
//
// State is bounded: entries carry a last-seen timestamp, idle entries expire
// after entryTTL, and a throttled inline sweep (plus capacity-based eviction)
// keeps the map from growing without bound under distributed probes. There is no
// per-IP goroutine or timer — cleanup piggybacks on ordinary calls.
type loginLimiter struct {
	mu         sync.Mutex
	entries    map[string]*limEntry
	now        func() time.Time
	maxEntries int
	entryTTL   time.Duration
	lastSweep  time.Time

	mEvictions atomic.Int64
	mBlocked   atomic.Int64
	mSweeps    atomic.Int64
}

type limEntry struct {
	fails      int
	lockedTill time.Time
	lastSeen   time.Time
}

const (
	limiterMaxEntries = 50000
	limiterEntryTTL   = 1 * time.Hour
	limiterSweepEvery = 1 * time.Minute
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		entries:    map[string]*limEntry{},
		now:        time.Now,
		maxEntries: limiterMaxEntries,
		entryTTL:   limiterEntryTTL,
	}
}

// normalizeIP canonicalizes a client IP so equivalent representations (IPv4,
// IPv6, IPv4-mapped IPv6, differing case/zeros) collapse to one key. host:port
// is reduced to the host; malformed input is returned trimmed so it still keys
// deterministically rather than silently sharing the "" bucket.
func normalizeIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return s
}

func (l *loginLimiter) Allowed(ip string) bool {
	ip = normalizeIP(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked()
	e := l.entries[ip]
	if e == nil {
		return true
	}
	e.lastSeen = l.now()
	if l.now().Before(e.lockedTill) {
		l.mBlocked.Add(1)
		return false
	}
	return true
}

func (l *loginLimiter) Fail(ip string) time.Duration {
	ip = normalizeIP(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked()
	e := l.entries[ip]
	if e == nil {
		l.evictIfFullLocked()
		e = &limEntry{}
		l.entries[ip] = e
	}
	now := l.now()
	e.lastSeen = now
	e.fails++
	if e.fails <= 4 {
		return 0
	}
	backoff := time.Duration(1<<uint(min(e.fails-4, 6))) * 5 * time.Second
	e.lockedTill = now.Add(backoff)
	return backoff
}

func (l *loginLimiter) Success(ip string) {
	ip = normalizeIP(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

// maybeSweepLocked removes expired entries at most once per limiterSweepEvery, so
// cleanup happens on any request without a dedicated goroutine. Holds l.mu.
func (l *loginLimiter) maybeSweepLocked() {
	now := l.now()
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < limiterSweepEvery {
		return
	}
	l.lastSweep = now
	l.mSweeps.Add(1)
	for k, e := range l.entries {
		if now.After(e.lockedTill) && now.Sub(e.lastSeen) >= l.entryTTL {
			delete(l.entries, k)
			l.mEvictions.Add(1)
		}
	}
}

// evictIfFullLocked frees room at capacity: expired entries first, then the
// least-recently-seen. Holds l.mu.
func (l *loginLimiter) evictIfFullLocked() {
	if len(l.entries) < l.maxEntries {
		return
	}
	now := l.now()
	for k, e := range l.entries {
		if now.After(e.lockedTill) && now.Sub(e.lastSeen) >= l.entryTTL {
			delete(l.entries, k)
			l.mEvictions.Add(1)
		}
	}
	if len(l.entries) < l.maxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range l.entries {
		if first || e.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, e.lastSeen, false
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
		l.mEvictions.Add(1)
	}
}

// Metrics snapshots the limiter counters for observability.
func (l *loginLimiter) Metrics() map[string]int64 {
	l.mu.Lock()
	cur := int64(len(l.entries))
	l.mu.Unlock()
	return map[string]int64{
		"entries":   cur,
		"evictions": l.mEvictions.Load(),
		"blocked":   l.mBlocked.Load(),
		"sweeps":    l.mSweeps.Load(),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
