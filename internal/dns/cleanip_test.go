package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSampleIPsSpreadsAcrossRanges(t *testing.T) {
	ips, err := SampleIPs([]string{"10.0.0.0/24", "192.168.5.0/24"}, 20)
	requireNoError(t, err)
	if len(ips) != 20 {
		t.Fatalf("expected 20 samples, got %d", len(ips))
	}
	first, second := 0, 0
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Fatalf("duplicate sample %q", ip)
		}
		seen[ip] = true
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("%q is not an IP", ip)
		}
		switch {
		case strings.HasPrefix(ip, "10.0.0."):
			first++
		case strings.HasPrefix(ip, "192.168.5."):
			second++
		default:
			t.Fatalf("sample %q is outside both ranges", ip)
		}
	}
	// Round-robin sampling must draw from both, not exhaust one first.
	if first == 0 || second == 0 {
		t.Fatalf("expected samples from both ranges, got %d and %d", first, second)
	}
}

func TestSampleIPsSkipsNetworkAndBroadcast(t *testing.T) {
	// A /30 has exactly two usable addresses.
	ips, err := SampleIPs([]string{"10.1.2.0/30"}, 10)
	requireNoError(t, err)
	if len(ips) != 2 {
		t.Fatalf("a /30 has 2 usable addresses, got %d: %v", len(ips), ips)
	}
	for _, ip := range ips {
		if ip == "10.1.2.0" || ip == "10.1.2.3" {
			t.Fatalf("network/broadcast address %q must be skipped", ip)
		}
	}
}

func TestSampleIPsRejectsBadInput(t *testing.T) {
	_, err := SampleIPs([]string{"not-a-cidr"}, 5)
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "104.16.0.0/13", "bad CIDR remediation")

	_, err = SampleIPs([]string{"2606:4700::/32"}, 5)
	requireKind(t, err, KindUnsupported)
}

func TestCloudflareRangesAreParseable(t *testing.T) {
	for _, cidr := range CloudflareIPv4Ranges {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			t.Errorf("shipped range %q does not parse: %v", cidr, err)
		}
	}
	ips, err := SampleIPs(nil, 32)
	requireNoError(t, err)
	if len(ips) != 32 {
		t.Fatalf("expected the default ranges to yield 32 samples, got %d", len(ips))
	}
}

func TestScanRequiresSNI(t *testing.T) {
	_, err := Scan(context.Background(), ScanConfig{})
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "--scan-sni", "missing SNI remediation")
}

// The scanner is proven against a real TLS 1.3 listener: both phases run, the
// handshake actually completes, and the result carries measured latency.
func TestScanTwoPhaseAgainstRealTLS13Listener(t *testing.T) {
	srv := newTLSTestServer(t, "ws.example.com")
	report, err := Scan(context.Background(), ScanConfig{
		SNI: "ws.example.com", Port: srv.Port,
		Addresses:          []string{"104.16.0.1", "104.16.0.2", "104.16.0.3"},
		Probes:             2,
		DialContext:        srv.dialer(),
		InsecureSkipVerify: true,
	})
	requireNoError(t, err)

	if report.Sampled != 3 {
		t.Fatalf("expected 3 sampled, got %d", report.Sampled)
	}
	if report.TCPPassed != 3 {
		t.Fatalf("phase one should have connected to all 3, got %d", report.TCPPassed)
	}
	if report.TLSPassed != 3 {
		t.Fatalf("phase two should have handshaken with all 3, got %d", report.TLSPassed)
	}
	working := report.Working()
	if len(working) != 3 {
		t.Fatalf("expected 3 working addresses, got %d", len(working))
	}
	for _, r := range working {
		if !r.TLS13 {
			t.Fatalf("the listener only offers TLS 1.3, so %s should report it: %+v", r.IP, r)
		}
		if r.Attempts != 2 || r.Successes != 2 {
			t.Fatalf("expected 2/2 probes for %s, got %d/%d", r.IP, r.Successes, r.Attempts)
		}
		if r.LossPct != 0 {
			t.Fatalf("expected zero loss against a local listener, got %.1f%%", r.LossPct)
		}
		if r.Score >= 1e9 {
			t.Fatalf("a working address must not carry the unreachable score: %+v", r)
		}
	}
}

// Phase one must reject unreachable addresses cheaply, and phase two must never
// see them.
func TestScanPhaseOneRejectsUnreachable(t *testing.T) {
	report, err := Scan(context.Background(), ScanConfig{
		SNI: "ws.example.com", Port: 443,
		Addresses:  []string{"104.16.0.1", "104.16.0.2"},
		TCPTimeout: 200 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
		},
	})
	requireNoError(t, err)
	if report.TCPPassed != 0 || report.TLSPassed != 0 {
		t.Fatalf("expected nothing to pass, got tcp=%d tls=%d", report.TCPPassed, report.TLSPassed)
	}
	for _, r := range report.Results {
		requireContains(t, r.Error, "typically a blocked address", "timeout is explained in censorship terms")
	}
}

// TCP connecting but TLS failing is the classic SNI-based block, and must be
// reported as such rather than as a generic error.
func TestScanTCPPassesButTLSFailsIsExplained(t *testing.T) {
	// A plain TCP listener that never speaks TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and immediately close: TCP works, TLS cannot.
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	report, err := Scan(context.Background(), ScanConfig{
		SNI: "ws.example.com", Port: port,
		Addresses:  []string{"104.16.0.1"},
		Probes:     1,
		TLSTimeout: time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, ln.Addr().String())
		},
	})
	requireNoError(t, err)
	if report.TCPPassed != 1 {
		t.Fatalf("expected phase one to pass, got %d", report.TCPPassed)
	}
	if report.TLSPassed != 0 {
		t.Fatalf("expected phase two to fail, got %d", report.TLSPassed)
	}
	if report.Results[0].Error == "" {
		t.Fatal("expected a phase-two error explanation")
	}
}

func TestScanRanksWorkingFirst(t *testing.T) {
	srv := newTLSTestServer(t, "ws.example.com")
	blocked := "104.16.9.9"
	report, err := Scan(context.Background(), ScanConfig{
		SNI: "ws.example.com", Port: srv.Port,
		Addresses: []string{blocked, "104.16.0.1"},
		Probes:    1, TCPTimeout: 300 * time.Millisecond,
		InsecureSkipVerify: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, blocked+":") {
				return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
			}
			d := net.Dialer{}
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", itoaTest(srv.Port)))
		},
	})
	requireNoError(t, err)
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}
	if !report.Results[0].TLSOK {
		t.Fatalf("the working address must rank first, got %+v", report.Results)
	}
	if report.Results[1].TLSOK {
		t.Fatalf("the blocked address must rank last, got %+v", report.Results)
	}
	if got := report.WorkingIPs(); len(got) != 1 || got[0] != "104.16.0.1" {
		t.Fatalf("unexpected working set: %v", got)
	}
}

func TestScanKeepBoundsResults(t *testing.T) {
	srv := newTLSTestServer(t, "ws.example.com")
	report, err := Scan(context.Background(), ScanConfig{
		SNI: "ws.example.com", Port: srv.Port, Keep: 2, Probes: 1,
		Addresses:          []string{"104.16.0.1", "104.16.0.2", "104.16.0.3", "104.16.0.4"},
		DialContext:        srv.dialer(),
		InsecureSkipVerify: true,
	})
	requireNoError(t, err)
	if len(report.Results) != 2 {
		t.Fatalf("expected Keep to trim to 2, got %d", len(report.Results))
	}
}

func TestScanJobStoresWorkingSet(t *testing.T) {
	srv := newTLSTestServer(t, "ws.example.com")
	store := NewMemStore()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	set, report, err := ScanJob{
		Name: "ws.example.com", Repo: store, Keep: 5, Now: fixedNow(now),
		Config: ScanConfig{
			SNI: "ws.example.com", Port: srv.Port, Probes: 1,
			Addresses:          []string{"104.16.0.1", "104.16.0.2"},
			DialContext:        srv.dialer(),
			InsecureSkipVerify: true,
		},
	}.Run(context.Background())
	requireNoError(t, err)
	if len(set.IPs) != 2 || report.TLSPassed != 2 {
		t.Fatalf("unexpected scan result: set=%+v report=%+v", set, report)
	}

	loaded, err := store.LoadCleanIPs("ws.example.com")
	requireNoError(t, err)
	if loaded == nil || len(loaded.IPs) != 2 {
		t.Fatalf("expected the set to be persisted, got %+v", loaded)
	}
	if loaded.SNI != "ws.example.com" {
		t.Fatalf("the set must record which hostname it was verified against, got %q", loaded.SNI)
	}
	if best := loaded.Best(); best == "" {
		t.Fatal("expected a best address")
	}
}

// "TCP passed but TLS did not" and "nothing connected at all" need different
// advice, and the job must give the right one.
func TestScanJobShortfallRemediationIsPhaseSpecific(t *testing.T) {
	store := NewMemStore()

	t.Run("nothing connected", func(t *testing.T) {
		_, _, err := ScanJob{Repo: store, Config: ScanConfig{
			SNI: "ws.example.com", Port: 443, Addresses: []string{"104.16.0.1"},
			TCPTimeout: 100 * time.Millisecond,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
			},
		}}.Run(context.Background())
		e := requireKind(t, err, KindNetwork)
		requireContains(t, e.Remediation, "no route to the CDN's ranges", "phase-one shortfall")
	})

	t.Run("tcp only", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		requireNoError(t, err)
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()
		_, _, err = ScanJob{Repo: store, Config: ScanConfig{
			SNI: "ws.example.com", Port: 443, Addresses: []string{"104.16.0.1"},
			Probes: 1, TLSTimeout: time.Second,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, network, ln.Addr().String())
			},
		}}.Run(context.Background())
		e := requireKind(t, err, KindNetwork)
		requireContains(t, e.Remediation, "not actually proxied at the provider", "phase-two shortfall")
	})
}

func TestCleanIPSetStaleness(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	fresh := CleanIPSet{UpdatedAt: now.Add(-time.Hour)}
	if fresh.Stale(now, 24*time.Hour) {
		t.Fatal("an hour-old set is fresh within a 24h window")
	}
	old := CleanIPSet{UpdatedAt: now.Add(-48 * time.Hour)}
	if !old.Stale(now, 24*time.Hour) {
		t.Fatal("a two-day-old set is stale within a 24h window")
	}
	if !(CleanIPSet{}).Stale(now, 24*time.Hour) {
		t.Fatal("a never-scanned set is stale")
	}
}

// A stale set must be returned with a warning rather than silently trusted:
// addresses clean last month are routinely blocked today.
func TestLoadFreshCleanIPsWarnsOnStale(t *testing.T) {
	store := NewMemStore()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	requireNoError(t, store.SaveCleanIPs(CleanIPSet{
		Name: "ws.example.com", SNI: "ws.example.com",
		IPs: []CleanIP{{IP: "104.16.0.1"}}, UpdatedAt: now.Add(-72 * time.Hour),
	}))

	set, err := LoadFreshCleanIPs(store, "ws.example.com", 24*time.Hour, now)
	if set == nil {
		t.Fatal("a stale set must still be returned so the caller can decide")
	}
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "frequently blocked now", "stale remediation")

	_, err = LoadFreshCleanIPs(store, "missing.example.com", 24*time.Hour, now)
	e = requireKind(t, err, KindNotFound)
	requireContains(t, e.Remediation, "run a scan first", "missing set remediation")
}
