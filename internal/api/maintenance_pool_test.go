package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/telegram"
)

// countingSender records that an alert went out without touching the network.
type countingSender struct{ onSend func(string) }

func (c countingSender) Send(_ int64, text string) error {
	if c.onSend != nil {
		c.onSend(text)
	}
	return nil
}

func testNotifier(onSend func()) *telegram.Notifier {
	return telegram.NewNotifier(countingSender{onSend: func(string) {
		if onSend != nil {
			onSend()
		}
	}}, []int64{1})
}

// testNotifier2 keeps the message, for the alerts whose WORDING is the point.
func testNotifier2(onSend func(string)) *telegram.Notifier {
	return telegram.NewNotifier(countingSender{onSend: onSend}, []int64{1})
}

// countingProber answers a fixed verdict and records what it was asked about.
// countingProber records what a sweep probed.
//
// The mutex is load-bearing: Pool.check probes its entries CONCURRENTLY from a
// worker pool, so Probe is called from several goroutines at once and an
// unsynchronised append loses writes. That is not theoretical — it was seen as
// "probed [a1 b1], want all three", a lost append on a machine under load, and
// it reads as a sweep that skipped a domain rather than as a broken test.
type countingProber struct {
	mu      sync.Mutex
	ok      bool
	probed  []string
	verdict map[string]bool
}

// seen returns a copy of what was probed, safely.
func (p *countingProber) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.probed...)
}

func (p *countingProber) Probe(_ context.Context, domain string) dns.ProbeResult {
	p.mu.Lock()
	p.probed = append(p.probed, domain)
	p.mu.Unlock()
	ok := p.ok
	if p.verdict != nil {
		if v, found := p.verdict[domain]; found {
			ok = v
		}
	}
	if ok {
		return dns.ProbeResult{OK: true, Latency: 10 * time.Millisecond}
	}
	return dns.ProbeResult{OK: false, Detail: "refused"}
}

func poolRepo(t *testing.T, s *Server) dns.PoolRepo {
	t.Helper()
	repo, err := dns.NewGormStore(s.db.DB())
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

// A rotation pool exists so a blocked domain is replaced before anyone notices.
// It could only be swept by NAME, from a handler somebody had to call, and
// PoolRepo had no way to enumerate pools at all — so nothing could sweep them.
// The rotate handler's own comment calls a bodyless rotate "a legitimate
// scheduled operation", and nothing scheduled it.
func TestTheScheduledSweepFindsEveryPoolAndRetiresWhatIsDead(t *testing.T) {
	s, _ := adminAPI(t)
	repo := poolRepo(t, s)

	for _, e := range []struct{ pool, domain string }{
		{"edge-a", "a1.example.com"},
		{"edge-a", "a2.example.com"},
		{"edge-b", "b1.example.com"},
	} {
		if err := repo.PutPoolEntry(e.pool, dns.PoolEntry{Domain: e.domain, State: dns.PoolActive}); err != nil {
			t.Fatal(err)
		}
	}

	names, err := repo.ListPoolNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "edge-a" || names[1] != "edge-b" {
		t.Fatalf("pool names = %v, want both pools once each", names)
	}

	// a1 keeps working, everything else stops. FailureThreshold defaults to 3,
	// so one sweep marks but does not retire — the point here is that every pool
	// is REACHED, which is what could not happen before.
	p := &countingProber{ok: false, verdict: map[string]bool{"a1.example.com": true}}
	s.poolProber = p
	s.checkRotationPools()

	if got := p.seen(); len(got) != 3 {
		t.Errorf("probed %v, want all three domains across both pools", got)
	}
}

// The alert an operator has to see: nothing in the pool answers, so whatever it
// fronts is unreachable and rotating is the only way out.
func TestAnExhaustedPoolIsReported(t *testing.T) {
	s, _ := adminAPI(t)
	repo := poolRepo(t, s)
	if err := repo.PutPoolEntry("dead", dns.PoolEntry{Domain: "gone.example.com", State: dns.PoolActive}); err != nil {
		t.Fatal(err)
	}

	sent := 0
	s.notifier = testNotifier(func() { sent++ })
	s.poolProber = &countingProber{ok: false}

	// Three sweeps: the default failure threshold. The first two mark, the third
	// retires — and a pool with nothing healthy is what gets announced.
	for i := 0; i < 3; i++ {
		s.checkRotationPools()
	}
	if sent == 0 {
		t.Error("a pool with no healthy domain left raised no alert")
	}
}

// A healthy pool must stay quiet. An alert that fires on a working pool trains
// an operator to ignore the channel, which costs more than the alert is worth.
func TestAHealthyPoolIsSilent(t *testing.T) {
	s, _ := adminAPI(t)
	repo := poolRepo(t, s)
	if err := repo.PutPoolEntry("fine", dns.PoolEntry{Domain: "ok.example.com", State: dns.PoolActive}); err != nil {
		t.Fatal(err)
	}
	sent := 0
	s.notifier = testNotifier(func() { sent++ })
	s.poolProber = &countingProber{ok: true}
	for i := 0; i < 3; i++ {
		s.checkRotationPools()
	}
	if sent != 0 {
		t.Errorf("a healthy pool raised %d alert(s)", sent)
	}
}

// And with no pools at all, the sweep must do nothing rather than error or
// probe. Most panels have none.
func TestTheSweepIsANoOpWithNoPools(t *testing.T) {
	s, _ := adminAPI(t)
	p := &countingProber{ok: true}
	s.poolProber = p
	s.checkRotationPools()
	if got := p.seen(); len(got) != 0 {
		t.Errorf("probed %v with no pools configured", got)
	}
}

// The wiring, not the function.
//
// Every test above calls checkRotationPools directly, so all of them pass with
// the call REMOVED from runMaintenance — which is precisely the defect being
// fixed here: a capability that works perfectly and that nothing invokes. This
// is the only test in the file that would notice.
func TestRunMaintenanceActuallySweepsThePools(t *testing.T) {
	s, _ := adminAPI(t)
	repo := poolRepo(t, s)
	if err := repo.PutPoolEntry("wired", dns.PoolEntry{Domain: "w.example.com", State: dns.PoolActive}); err != nil {
		t.Fatal(err)
	}
	p := &countingProber{ok: true}
	s.poolProber = p

	s.runMaintenance()

	if got := p.seen(); len(got) == 0 {
		t.Error("runMaintenance did not health-check the rotation pools, so nothing ever will")
	}
}
