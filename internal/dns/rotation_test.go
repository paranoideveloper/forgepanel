package dns

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedProber returns a fixed verdict per domain, and counts probes.
type scriptedProber struct {
	mu      sync.Mutex
	Healthy map[string]bool
	Latency map[string]time.Duration
	Calls   map[string]int
}

func newScriptedProber() *scriptedProber {
	return &scriptedProber{
		Healthy: map[string]bool{}, Latency: map[string]time.Duration{}, Calls: map[string]int{},
	}
}

func (p *scriptedProber) Probe(_ context.Context, domain string) ProbeResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Calls[domain]++
	if p.Healthy[domain] {
		lat := p.Latency[domain]
		if lat == 0 {
			lat = 20 * time.Millisecond
		}
		return ProbeResult{OK: true, Latency: lat, Detail: "TLS 1.3 handshake with " + domain}
	}
	return ProbeResult{Detail: "tls " + domain + ": handshake reset (an in-path device rejected the SNI)"}
}

func newTestPool(t *testing.T, cfg PoolConfig) (*Pool, *MemStore) {
	t.Helper()
	store := NewMemStore()
	if cfg.Name == "" {
		cfg.Name = "edge"
	}
	if cfg.Now == nil {
		cfg.Now = fixedNow(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC))
	}
	pool, err := NewPool(cfg, store)
	requireNoError(t, err)
	return pool, store
}

func TestPoolCheckRetiresAfterThreshold(t *testing.T) {
	prober := newScriptedProber()
	prober.Healthy["good.example.com"] = true
	pool, _ := newTestPool(t, PoolConfig{Prober: prober, FailureThreshold: 3})

	requireNoError(t, pool.Add(PoolEntry{Domain: "good.example.com"}))
	requireNoError(t, pool.Add(PoolEntry{Domain: "bad.example.com"}))

	ctx := context.Background()
	// One failure degrades but does not retire — a single blip must not burn a
	// name that is otherwise fine.
	report, err := pool.Check(ctx)
	requireNoError(t, err)
	if report.Healthy != 2 {
		t.Fatalf("after one failure both entries are still usable, got %d healthy", report.Healthy)
	}
	if len(report.Retired) != 0 {
		t.Fatalf("nothing should retire on the first failure, got %v", report.Retired)
	}

	report, err = pool.Check(ctx)
	requireNoError(t, err)
	if len(report.Retired) != 0 {
		t.Fatalf("nothing should retire on the second failure, got %v", report.Retired)
	}

	report, err = pool.Check(ctx)
	requireNoError(t, err)
	if len(report.Retired) != 1 || report.Retired[0] != "bad.example.com" {
		t.Fatalf("expected the third failure to retire it, got %v", report.Retired)
	}
	if report.Healthy != 1 {
		t.Fatalf("expected 1 healthy entry, got %d", report.Healthy)
	}

	active, err := pool.Active()
	requireNoError(t, err)
	if len(active) != 1 || active[0].Domain != "good.example.com" {
		t.Fatalf("only the healthy entry should be handed out, got %+v", active)
	}
}

// A name that starts working again must come back, so a transient outage does
// not permanently shrink the pool.
func TestPoolRecoversAName(t *testing.T) {
	prober := newScriptedProber()
	pool, _ := newTestPool(t, PoolConfig{Prober: prober, FailureThreshold: 1})
	requireNoError(t, pool.Add(PoolEntry{Domain: "flaky.example.com"}))

	ctx := context.Background()
	report, err := pool.Check(ctx)
	requireNoError(t, err)
	if len(report.Retired) != 1 {
		t.Fatalf("expected retirement at threshold 1, got %v", report.Retired)
	}

	prober.Healthy["flaky.example.com"] = true
	report, err = pool.Check(ctx)
	requireNoError(t, err)
	if len(report.Recovered) != 1 || report.Recovered[0] != "flaky.example.com" {
		t.Fatalf("expected recovery, got %+v", report)
	}
	entries, err := pool.Entries()
	requireNoError(t, err)
	if entries[0].State != PoolActive || entries[0].Failures != 0 {
		t.Fatalf("a recovered entry must reset its failure count, got %+v", entries[0])
	}
}

func TestPoolRanksHealthyAndFastestFirst(t *testing.T) {
	prober := newScriptedProber()
	for _, d := range []string{"slow.example.com", "fast.example.com", "dead.example.com"} {
		requireNoError(t, nil)
		_ = d
	}
	prober.Healthy["slow.example.com"] = true
	prober.Healthy["fast.example.com"] = true
	prober.Latency["slow.example.com"] = 200 * time.Millisecond
	prober.Latency["fast.example.com"] = 10 * time.Millisecond

	pool, _ := newTestPool(t, PoolConfig{Prober: prober, FailureThreshold: 1})
	for _, d := range []string{"slow.example.com", "fast.example.com", "dead.example.com"} {
		requireNoError(t, pool.Add(PoolEntry{Domain: d}))
	}
	report, err := pool.Check(context.Background())
	requireNoError(t, err)
	if report.Entries[0].Domain != "fast.example.com" {
		t.Fatalf("the fastest healthy entry must rank first, got %+v", report.Entries)
	}
	if report.Entries[len(report.Entries)-1].Domain != "dead.example.com" {
		t.Fatalf("the retired entry must rank last, got %+v", report.Entries)
	}
}

// The point of a pool: when names die, fresh subdomains are created to replace
// them without an operator touching anything.
func TestPoolRotateCreatesReplacements(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	prober := newScriptedProber()
	prober.Healthy["alive.example.com"] = true

	pool, store := newTestPool(t, PoolConfig{
		Prober: prober, FailureThreshold: 1, MinHealthy: 3,
		Provider: m.client(), ZoneRef: "zone1", Domain: "example.com",
		Template: "{proto}-{rand:6}", Target: "203.0.113.10", Proxied: true,
		Vars: TemplateVars{Proto: "ws"},
	})
	requireNoError(t, pool.Add(PoolEntry{Domain: "alive.example.com"}))
	requireNoError(t, pool.Add(PoolEntry{Domain: "dead.example.com"}))

	result, err := pool.Rotate(context.Background())
	requireNoError(t, err)

	if len(result.Report.Retired) != 1 {
		t.Fatalf("expected one retirement, got %v", result.Report.Retired)
	}
	// One healthy entry, minimum of three: two replacements.
	if len(result.Added) != 2 {
		t.Fatalf("expected 2 replacements, got %d (%+v) note=%q", len(result.Added), result.Added, result.Note)
	}
	if result.Shortfall != 0 {
		t.Fatalf("expected no shortfall, got %d (%s)", result.Shortfall, result.Note)
	}
	for _, added := range result.Added {
		if !strings.HasPrefix(added.Domain, "ws-") || !strings.HasSuffix(added.Domain, ".example.com") {
			t.Fatalf("replacement %q does not follow the template", added.Domain)
		}
		if added.RecordID == "" {
			t.Fatalf("replacement %q has no provider record id, so it can never be cleaned up", added.Domain)
		}
		if !added.Proxied {
			t.Fatalf("replacement %q should inherit the proxy flag", added.Domain)
		}
	}
	if len(m.Records["zone1"]) != 2 {
		t.Fatalf("expected 2 records created at the provider, got %d", len(m.Records["zone1"]))
	}
	entries, err := store.ListPoolEntries("edge")
	requireNoError(t, err)
	if len(entries) != 4 {
		t.Fatalf("expected 4 stored entries (2 original + 2 new), got %d", len(entries))
	}
}

// A burned name must not linger in DNS when the pool is configured to clean up.
func TestPoolRotateDeletesRetiredRecords(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	dead, err := m.client().CreateRecord(context.Background(), "zone1", Record{
		Type: TypeA, Name: "dead.example.com", Content: "203.0.113.10",
	})
	requireNoError(t, err)

	prober := newScriptedProber()
	pool, _ := newTestPool(t, PoolConfig{
		Prober: prober, FailureThreshold: 1, MinHealthy: 0, DeleteRetired: true,
		Provider: m.client(), ZoneRef: "zone1",
	})
	requireNoError(t, pool.Add(PoolEntry{Domain: "dead.example.com", Zone: "zone1", RecordID: dead.ID}))

	result, err := pool.Rotate(context.Background())
	requireNoError(t, err)
	if len(result.Deleted) != 1 || result.Deleted[0] != "dead.example.com" {
		t.Fatalf("expected the retired record to be deleted, got %v (%s)", result.Deleted, result.Note)
	}
	if len(m.Records["zone1"]) != 0 {
		t.Fatalf("expected the record to be gone at the provider, got %d", len(m.Records["zone1"]))
	}
	entries, err := pool.Entries()
	requireNoError(t, err)
	if len(entries) != 0 {
		t.Fatalf("expected the entry to be dropped from the pool, got %+v", entries)
	}
}

// With no provider, a shortfall must be reported plainly rather than silently
// leaving the pool short.
func TestPoolRotateWithoutProviderReportsShortfall(t *testing.T) {
	prober := newScriptedProber()
	pool, _ := newTestPool(t, PoolConfig{Prober: prober, FailureThreshold: 1, MinHealthy: 3})
	requireNoError(t, pool.Add(PoolEntry{Domain: "dead.example.com"}))

	result, err := pool.Rotate(context.Background())
	requireNoError(t, err)
	if result.Shortfall != 3 {
		t.Fatalf("expected a shortfall of 3, got %d", result.Shortfall)
	}
	requireContains(t, result.Note, "no DNS provider is configured", "shortfall note")
	requireContains(t, result.Note, "Register a credential", "shortfall note suggests a fix")
}

// A provider failure during healing must be reported with its remediation, not
// swallowed.
func TestPoolRotateSurfacesProviderFailure(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	m.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	prober := newScriptedProber()
	pool, _ := newTestPool(t, PoolConfig{
		Prober: prober, FailureThreshold: 1, MinHealthy: 2,
		Provider: m.client(), ZoneRef: "zone1", Domain: "example.com",
		Template: "{proto}-{rand:6}", Target: "203.0.113.10",
		Vars: TemplateVars{Proto: "ws"},
	})
	result, err := pool.Rotate(context.Background())
	requireNoError(t, err)
	if result.Shortfall != 2 {
		t.Fatalf("expected the full shortfall, got %d", result.Shortfall)
	}
	requireContains(t, result.Note, "Zone Resources", "provider failure note carries remediation")
}

func TestPoolRotateNoopWhenHealthy(t *testing.T) {
	prober := newScriptedProber()
	prober.Healthy["a.example.com"] = true
	prober.Healthy["b.example.com"] = true
	pool, _ := newTestPool(t, PoolConfig{Prober: prober, MinHealthy: 2})
	requireNoError(t, pool.Add(PoolEntry{Domain: "a.example.com"}))
	requireNoError(t, pool.Add(PoolEntry{Domain: "b.example.com"}))

	result, err := pool.Rotate(context.Background())
	requireNoError(t, err)
	if len(result.Added) != 0 || result.Shortfall != 0 {
		t.Fatalf("a healthy pool needs no work, got %+v", result)
	}
}

func TestPoolRemove(t *testing.T) {
	pool, _ := newTestPool(t, PoolConfig{Prober: newScriptedProber()})
	requireNoError(t, pool.Add(PoolEntry{Domain: "a.example.com"}))
	requireNoError(t, pool.Remove("A.Example.COM"))
	entries, err := pool.Entries()
	requireNoError(t, err)
	if len(entries) != 0 {
		t.Fatalf("expected removal to be case-insensitive, got %+v", entries)
	}
}

func TestPoolRejectsInvalidDomain(t *testing.T) {
	pool, _ := newTestPool(t, PoolConfig{Prober: newScriptedProber()})
	err := pool.Add(PoolEntry{Domain: "not-a-fqdn"})
	requireKind(t, err, KindValidation)
}

// The default prober completes a real TLS handshake, so a name that resolves
// but whose edge refuses the SNI is correctly reported as unhealthy.
func TestTLSProberAgainstRealListener(t *testing.T) {
	srv := newTLSTestServer(t, "ws.example.com")
	prober := TLSProber{
		Port: srv.Port, Timeout: 3 * time.Second,
		DialContext: srv.dialer(), InsecureSkipVerify: true,
	}
	res := prober.Probe(context.Background(), "ws.example.com")
	if !res.OK {
		t.Fatalf("expected the handshake to succeed, got %q", res.Detail)
	}
	requireContains(t, res.Detail, "TLS 1.3", "prober reports the negotiated version")
	if res.Latency <= 0 {
		t.Fatal("expected a measured latency")
	}
}

func TestTLSProberReportsConnectFailure(t *testing.T) {
	prober := TLSProber{Port: 1, Timeout: 250 * time.Millisecond}
	res := prober.Probe(context.Background(), "127.0.0.1")
	if res.OK {
		t.Fatal("expected the probe to fail")
	}
	requireContains(t, res.Detail, "connect", "connect failure detail")
}
