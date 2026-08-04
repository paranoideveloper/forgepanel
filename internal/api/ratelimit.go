package api

import (
	"sync"
	"time"
)

// loginLimiter enforces progressive login rate limiting per source IP (spec
// §12): after a burst of failures a source is locked out for an increasing
// window, blunting credential-stuffing without a dependency.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*limEntry
	now     func() time.Time
}

type limEntry struct {
	fails      int
	lockedTill time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: map[string]*limEntry{}, now: time.Now}
}

// Allowed reports whether ip may attempt a login now.
func (l *loginLimiter) Allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		return true
	}
	return !l.now().Before(e.lockedTill)
}

// Fail records a failed attempt and returns the lockout applied (0 if none yet).
// Lockout grows with the failure count: none for the first 4, then 5s, 15s, 60s…
func (l *loginLimiter) Fail(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		e = &limEntry{}
		l.entries[ip] = e
	}
	e.fails++
	if e.fails <= 4 {
		return 0
	}
	backoff := time.Duration(1<<uint(min(e.fails-4, 6))) * 5 * time.Second // 5s,10s,...,320s
	e.lockedTill = l.now().Add(backoff)
	return backoff
}

// Success clears the counter for ip.
func (l *loginLimiter) Success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
