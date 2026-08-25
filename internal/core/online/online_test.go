package online

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// These lines were CAPTURED from a live Xray 26.2.6, not written from memory of
// the format. The two shapes differ in ways that break a parser written against
// only one of them.
const (
	realVLESSLine = `2026/08/25 17:58:56.880563 from 127.0.0.1:64792 accepted tcp:[2606:4700:10::6814:179a]:80 [vless-in >> direct] email: alice@forgepanel`
	realSOCKSLine = `2026/08/25 17:58:23.673870 from tcp:127.0.0.1:43522 accepted tcp:[2606:4700:10::ac42:93f3]:80 [in-socks >> direct]`
)

func TestParsesRealCapturedLines(t *testing.T) {
	e, ok := ParseAccessLine(realVLESSLine)
	if !ok {
		t.Fatal("the VLESS line from a live core did not parse")
	}
	if e.IP != "127.0.0.1" {
		t.Errorf("source IP = %q, want 127.0.0.1", e.IP)
	}
	if e.User != "alice@forgepanel" {
		t.Errorf("user = %q, want alice@forgepanel", e.User)
	}
	if e.Inbound != "vless-in" {
		t.Errorf("inbound = %q, want vless-in", e.Inbound)
	}
	if e.Target != "tcp:[2606:4700:10::6814:179a]:80" {
		t.Errorf("target = %q", e.Target)
	}

	// The SOCKS line carries a "tcp:" prefix on the SOURCE that the VLESS line
	// does not. A parser that assumes one shape drops every line of the other,
	// and a presence list missing half its connections still looks complete.
	e2, ok := ParseAccessLine(realSOCKSLine)
	if !ok {
		t.Fatal("the SOCKS-shaped line did not parse")
	}
	if e2.IP != "127.0.0.1" {
		t.Errorf("prefixed source IP = %q, want 127.0.0.1", e2.IP)
	}
	if e2.User != "" {
		t.Errorf("user = %q, want empty for an inbound with no email", e2.User)
	}
	if e2.Inbound != "in-socks" {
		t.Errorf("inbound = %q, want in-socks", e2.Inbound)
	}
}

func TestParsesIPv6Sources(t *testing.T) {
	cases := map[string]string{
		`x from [2001:db8::1]:443 accepted tcp:a.b:80 [in >> direct] email: u`:     "2001:db8::1",
		`x from tcp:[2001:db8::1]:443 accepted tcp:a.b:80 [in >> direct] email: u`: "2001:db8::1",
		`x from 203.0.113.9:1234 accepted tcp:a.b:80 [in >> direct] email: u`:      "203.0.113.9",
	}
	for line, want := range cases {
		e, ok := ParseAccessLine(line)
		if !ok {
			t.Fatalf("did not parse: %s", line)
		}
		if e.IP != want {
			t.Errorf("IP = %q, want %q (from %s)", e.IP, want, line)
		}
	}
}

func TestRejectsNonConnectionLines(t *testing.T) {
	// The same pipe carries banners, warnings and DNS chatter. Treating any of
	// them as a connection invents sessions for users who are not there.
	for _, line := range []string{
		"Xray 26.2.6 (Xray, Penetrates Everything.) 12ee51e (go1.25.7 linux/amd64)",
		"2026/08/25 17:58:21 [Warning] core: Xray 26.2.6 started",
		"2026/08/25 17:58:21 [Info] infra/conf/serial: Reading config",
		"",
		"from",
		"2026/08/25 17:58:21 from 1.2.3.4:5 rejected something",
	} {
		if _, ok := ParseAccessLine(line); ok {
			t.Errorf("parsed a non-connection line as a connection: %q", line)
		}
	}
}

func TestTrackerReportsPresence(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base }

	tr.Observe(Entry{At: base, IP: "1.1.1.1", User: "alice", Inbound: "in1"}, "local")
	tr.Observe(Entry{At: base.Add(time.Second), IP: "2.2.2.2", User: "alice", Inbound: "in1"}, "local")
	tr.Observe(Entry{At: base, IP: "3.3.3.3", User: "bob", Inbound: "in2"}, "local")

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("presence entries = %d, want 2", len(snap))
	}
	// Most recently seen first: an operator scanning the list wants the live
	// ones at the top, not alphabetical order.
	if snap[0].User != "alice" {
		t.Errorf("first = %q, want alice (most recent)", snap[0].User)
	}
	if len(snap[0].Sessions) != 2 {
		t.Fatalf("alice sessions = %d, want 2", len(snap[0].Sessions))
	}
	if snap[0].Sessions[0].IP != "2.2.2.2" {
		t.Errorf("alice's newest session = %q, want 2.2.2.2", snap[0].Sessions[0].IP)
	}
}

func TestRepeatedConnectionsUpdateRatherThanDuplicate(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base.Add(time.Second) }

	for i := 0; i < 50; i++ {
		tr.Observe(Entry{At: base.Add(time.Duration(i) * time.Millisecond),
			IP: "1.1.1.1", User: "alice", Inbound: "in1"}, "local")
	}
	snap := tr.Snapshot()
	if len(snap[0].Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1 — one address is one session however many connections it makes",
			len(snap[0].Sessions))
	}
	if snap[0].Sessions[0].Count != 50 {
		t.Errorf("connection count = %d, want 50", snap[0].Sessions[0].Count)
	}
	if !snap[0].Sessions[0].First.Equal(base) {
		t.Errorf("first-seen moved; it must stay the first time this address appeared")
	}
}

func TestExpiredSessionsDisappear(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base }
	tr.Observe(Entry{At: base, IP: "1.1.1.1", User: "alice"}, "local")

	if len(tr.Snapshot()) != 1 {
		t.Fatal("alice should be present immediately after connecting")
	}

	tr.now = func() time.Time { return base.Add(2 * time.Minute) }
	if got := tr.Snapshot(); len(got) != 0 {
		t.Fatalf("presence after the TTL = %v, want empty", got)
	}
	// The user's map must be dropped, not left empty: empty maps accumulating
	// for every user who ever connected is a slow leak in a months-long process.
	tr.mu.Lock()
	n := len(tr.users)
	tr.mu.Unlock()
	if n != 0 {
		t.Errorf("internal user maps = %d, want 0", n)
	}
}

func TestAddressCountIsWhatALimitWouldUse(t *testing.T) {
	tr := NewTracker(time.Minute)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base }

	for i := 1; i <= 4; i++ {
		tr.Observe(Entry{At: base, IP: fmt.Sprintf("10.0.0.%d", i), User: "alice"}, "local")
	}
	if got := tr.AddressCount("alice"); got != 4 {
		t.Errorf("address count = %d, want 4", got)
	}
	if got := tr.AddressCount("nobody"); got != 0 {
		t.Errorf("unknown user count = %d, want 0", got)
	}

	tr.now = func() time.Time { return base.Add(2 * time.Minute) }
	if got := tr.AddressCount("alice"); got != 0 {
		t.Errorf("address count after expiry = %d, want 0 — a limit enforced against stale addresses locks out a user who has already gone away", got)
	}
}

func TestAddressesPerUserAreCapped(t *testing.T) {
	tr := NewTracker(time.Hour)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base.Add(time.Minute) }

	// A CGNAT egress that rotates per connection would otherwise grow this map
	// without limit for as long as the panel runs.
	for i := 0; i < maxAddressesPerUser*3; i++ {
		tr.Observe(Entry{At: base.Add(time.Duration(i) * time.Second),
			IP: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), User: "alice"}, "local")
	}
	if got := tr.AddressCount("alice"); got != maxAddressesPerUser {
		t.Errorf("tracked addresses = %d, want the cap %d", got, maxAddressesPerUser)
	}
	// Eviction takes the OLDEST, so what survives is the current picture.
	snap := tr.Snapshot()
	newest := snap[0].Sessions[0]
	if !newest.Last.Equal(base.Add(time.Duration(maxAddressesPerUser*3-1) * time.Second)) {
		t.Errorf("newest session was evicted; the cap must drop stale addresses, not current ones")
	}
}

func TestUnauthenticatedConnectionsAreNotAUser(t *testing.T) {
	tr := NewTracker(time.Minute)
	// The panel's own api dokodemo-door and any local SOCKS listener log with no
	// email. Filing those under "" invents a user whose sessions are the panel's
	// own machinery.
	e, _ := ParseAccessLine(realSOCKSLine)
	tr.Observe(e, "local")
	if got := tr.Snapshot(); len(got) != 0 {
		t.Errorf("presence = %v, want empty for a connection with no user", got)
	}
}

func TestForgetDropsAUser(t *testing.T) {
	tr := NewTracker(time.Minute)
	tr.Observe(Entry{IP: "1.1.1.1", User: "alice"}, "local")
	tr.Forget("alice")
	if got := tr.Snapshot(); len(got) != 0 {
		t.Errorf("presence after Forget = %v, want empty", got)
	}
}

func TestObserveLineToleratesAnyInput(t *testing.T) {
	tr := NewTracker(time.Minute)
	hook := tr.ObserveLine("node-1")
	// This hook runs inside the supervisor's log pump. A panic there would take
	// the engine's output — and its crash diagnostics — with it.
	for _, line := range []string{realVLESSLine, "", "garbage", "from  accepted  [", realSOCKSLine} {
		hook(line)
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].User != "alice@forgepanel" {
		t.Fatalf("snapshot = %+v, want just alice@forgepanel", snap)
	}
	if snap[0].Sessions[0].Node != "node-1" {
		t.Errorf("node = %q, want node-1 — presence is useless without knowing where", snap[0].Sessions[0].Node)
	}
}

func TestConcurrentObserveAndSnapshot(t *testing.T) {
	// The supervisor pumps stdout and stderr on two goroutines while the API
	// reads snapshots. Run under -race, this is the test that catches a missing
	// lock before it corrupts the map in production.
	tr := NewTracker(time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tr.Observe(Entry{IP: fmt.Sprintf("10.0.%d.%d", g, i%8),
					User: fmt.Sprintf("u%d", i%3), Inbound: "in"}, "local")
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = tr.Snapshot()
			_ = tr.AddressCount("u1")
		}
	}()
	wg.Wait()
}
