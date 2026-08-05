package api

import (
	"sync"
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	base := time.Unix(1700000000, 0)
	l.now = func() time.Time { return base }
	ip := "1.2.3.4"
	for i := 0; i < 4; i++ {
		if !l.Allowed(ip) {
			t.Fatalf("should allow attempt %d", i)
		}
		if d := l.Fail(ip); d != 0 {
			t.Fatalf("no lockout in first 4, got %v", d)
		}
	}
	if d := l.Fail(ip); d == 0 {
		t.Fatal("5th failure should lock out")
	}
	if l.Allowed(ip) {
		t.Fatal("should be locked out now")
	}
	// success clears
	l.Success(ip)
	if !l.Allowed(ip) {
		t.Fatal("success must clear lockout")
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4": "1.2.3.4", "1.2.3.4:5678": "1.2.3.4",
		"::ffff:1.2.3.4": "1.2.3.4", "[::1]:80": "::1",
		"2001:DB8::1": "2001:db8::1", "[2001:db8::1]:443": "2001:db8::1",
		"  1.2.3.4  ": "1.2.3.4", "garbage": "garbage", "": "",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLimiterExpirationAndCapacity(t *testing.T) {
	l := newLoginLimiter()
	clk := time.Unix(1000, 0)
	l.now = func() time.Time { return clk }
	ip := "8.8.8.8"
	for i := 0; i < 6; i++ {
		l.Fail(ip)
	}
	if l.Allowed(ip) {
		t.Fatal("should be locked out")
	}
	clk = clk.Add(limiterEntryTTL + 2*time.Hour)
	l.Allowed("1.1.1.1") // unrelated call triggers the throttled sweep
	if _, ok := l.entries[ip]; ok {
		t.Fatalf("idle entry should be swept; entries=%d", len(l.entries))
	}
	// Capacity: never grows past maxEntries.
	l2 := newLoginLimiter()
	l2.maxEntries = 100
	c2 := time.Unix(0, 0)
	l2.now = func() time.Time { return c2 }
	for i := 0; i < 500; i++ {
		c2 = c2.Add(time.Second)
		l2.Fail(fmtIP(i))
	}
	if len(l2.entries) > l2.maxEntries {
		t.Fatalf("map grew past cap: %d", len(l2.entries))
	}
	if l2.mEvictions.Load() == 0 {
		t.Fatal("expected evictions under pressure")
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := newLoginLimiter()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ip := fmtIP2(g, i)
				l.Fail(ip)
				l.Allowed(ip)
			}
		}(g)
	}
	wg.Wait()
	_ = l.Metrics()
}

func fmtIP(i int) string     { return "10.0." + itoa(i/256) + "." + itoa(i%256) }
func fmtIP2(g, i int) string { return "172.16." + itoa(g) + "." + itoa(i%256) }
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
