package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A clean-IP set decays: addresses that completed a handshake through the edge
// last month are routinely blocked today. The scanner existed, ran once when an
// operator clicked it, and CleanIPSet.Stale — the function whose entire job is
// noticing a set has aged — had no caller anywhere. So sets aged silently and
// the first sign of trouble was users reporting that configs stopped working.

func storedSet(t *testing.T, repo CleanIPRepo, name string, age time.Duration, ips ...string) {
	t.Helper()
	set := CleanIPSet{Name: name, SNI: "edge.example", Port: 443,
		UpdatedAt: time.Now().Add(-age).UTC()}
	for _, ip := range ips {
		set.IPs = append(set.IPs, CleanIP{IP: ip, Score: 1})
	}
	if err := repo.SaveCleanIPs(set); err != nil {
		t.Fatal(err)
	}
}

func TestFreshSetIsNotRescanned(t *testing.T) {
	repo := NewMemStore()
	storedSet(t, repo, "cf", time.Minute, "1.1.1.1")

	res, err := RefreshCleanIPs(context.Background(), repo, "cf", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Re-verifying on every tick would mean a handshake per stored address per
	// minute, from a server whose whole purpose is to be inconspicuous.
	if res.Skipped == "" {
		t.Fatalf("a fresh set was re-verified: %+v", res)
	}
	if res.After != 1 {
		t.Errorf("after = %d, want the set left alone", res.After)
	}
}

func TestNeverScannedSetIsNotAnError(t *testing.T) {
	repo := NewMemStore()
	res, err := RefreshCleanIPs(context.Background(), repo, "absent", time.Hour, time.Now())
	// "Nothing to do" is not a failure. A scheduler logging it as one trains an
	// operator to ignore the log.
	if err != nil {
		t.Fatalf("a panel that never scanned reported an error: %v", err)
	}
	if !strings.Contains(res.Skipped, "no set") {
		t.Errorf("skipped = %q, want an explanation", res.Skipped)
	}
}

func TestStaleSetDropsAddressesThatStoppedWorking(t *testing.T) {
	// One address that answers a TLS handshake, one that refuses to connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen")
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Not a TLS server: the handshake fails, so this address is treated
			// as no longer working. That is the case under test — an address
			// that still accepts TCP but no longer serves the edge.
			c.Close()
		}
	}()

	repo := NewMemStore()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	set := CleanIPSet{Name: "cf", SNI: "edge.example", UpdatedAt: time.Now().Add(-48 * time.Hour)}
	set.IPs = []CleanIP{{IP: host, Score: 1}}
	// The stored port is where the refresh will probe.
	set.Port = atoiOrZero(port)
	if err := repo.SaveCleanIPs(set); err != nil {
		t.Fatal(err)
	}

	res, err := RefreshCleanIPs(context.Background(), repo, "cf", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.After != 0 || len(res.Dropped) != 1 {
		t.Fatalf("result = %+v, want the dead address dropped", res)
	}

	// The empty result must be WRITTEN. Keeping the old set because the new one
	// is empty would hand clients addresses just proven blocked — the exact
	// state this exists to prevent — and hide the outage.
	stored, err := repo.LoadCleanIPs("cf")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.IPs) != 0 {
		t.Fatalf("stored set still has %d addresses; the refresh was not persisted", len(stored.IPs))
	}
}

func atoiOrZero(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
