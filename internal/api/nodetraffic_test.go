package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The node agent used to post DELTAS and reset its counters only after a
// successful response. If the panel received the post and accounted it but the
// response was lost — a dropped link, a panel restart mid-reply, a client
// timeout — the agent never reset, sent the same bytes again, and the user was
// charged twice. A flaky link inflated usage and cut people off early, with
// nothing anywhere to show for it.
//
// Cumulative reporting makes a heartbeat idempotent, which is what these pin.

func trafficTestUser(t *testing.T, s *Server) *store.User {
	t.Helper()
	u := &store.User{Username: "nt", Status: store.StatusActive, SubToken: "ntt"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRepeatedCumulativeHeartbeatDoesNotDoubleCharge(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := trafficTestUser(t, s)
	key := job.UserEmail(u.ID)

	// First contact only establishes the baseline; see the handler for why the
	// panel refuses to bill a counter whose starting point it never saw.
	s.accountNodeTraffic(7, map[string]int64{key: 1_000_000}, true)
	got, _ := s.db.UserByID(u.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("first contact billed %d; it must only set the baseline", got.UsedTraffic)
	}

	// The response was lost, so the agent re-sends the SAME totals.
	s.accountNodeTraffic(7, map[string]int64{key: 1_000_000}, true)
	got, _ = s.db.UserByID(u.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("a repeated heartbeat double-charged the user: used=%d, want 0", got.UsedTraffic)
	}

	// Real usage since the baseline.
	s.accountNodeTraffic(7, map[string]int64{key: 1_500_000}, true)
	got, _ = s.db.UserByID(u.ID)
	if got.UsedTraffic != 500_000 {
		t.Fatalf("increment: used=%d, want 500000", got.UsedTraffic)
	}

	// And re-sending THAT total must add nothing either.
	s.accountNodeTraffic(7, map[string]int64{key: 1_500_000}, true)
	got, _ = s.db.UserByID(u.ID)
	if got.UsedTraffic != 500_000 {
		t.Fatalf("a repeated heartbeat double-charged: used=%d, want 500000", got.UsedTraffic)
	}
}

// A node that has been serving for a month must not bill that month in one
// heartbeat the first time the panel sees it — that could exhaust a user's
// quota instantly, on traffic already counted or never owed.
func TestFirstContactDoesNotBillTheNodesWholeHistory(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := trafficTestUser(t, s)
	key := job.UserEmail(u.ID)

	s.accountNodeTraffic(11, map[string]int64{key: 900_000_000_000}, true)
	got, _ := s.db.UserByID(u.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("first contact billed %d bytes of pre-existing counter", got.UsedTraffic)
	}
	snaps, _ := s.db.TrafficSnapshots(store.NodeScope(11))
	if snaps[key] != 900_000_000_000 {
		t.Fatalf("the baseline was not recorded: %v", snaps)
	}
}

// A node restart resets its counters to near zero. That must count as usage
// since the restart, not as a negative delta and not as nothing.
func TestNodeRestartCountsFromZero(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := trafficTestUser(t, s)
	key := job.UserEmail(u.ID)

	s.accountNodeTraffic(3, map[string]int64{key: 0}, true)    // baseline
	s.accountNodeTraffic(3, map[string]int64{key: 5000}, true) // 5000 used
	s.accountNodeTraffic(3, map[string]int64{key: 300}, true)  // core restarted
	got, _ := s.db.UserByID(u.ID)
	if got.UsedTraffic != 5300 {
		t.Fatalf("after a node restart: used=%d, want 5300", got.UsedTraffic)
	}
}

// Two nodes report independently. Their counters must not share a baseline, or
// one node's restart would look like the other's.
func TestEachNodeKeepsItsOwnBaseline(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := trafficTestUser(t, s)
	key := job.UserEmail(u.ID)

	// Baselines first, then equal usage on each node.
	s.accountNodeTraffic(1, map[string]int64{key: 0}, true)
	s.accountNodeTraffic(2, map[string]int64{key: 0}, true)
	s.accountNodeTraffic(1, map[string]int64{key: 1000}, true)
	s.accountNodeTraffic(2, map[string]int64{key: 1000}, true)
	got, _ := s.db.UserByID(u.ID)
	if got.UsedTraffic != 2000 {
		t.Fatalf("two nodes at 1000 each should total 2000, got %d", got.UsedTraffic)
	}

	// Node 1 climbs; node 2 is unchanged and must add nothing.
	s.accountNodeTraffic(1, map[string]int64{key: 1500}, true)
	s.accountNodeTraffic(2, map[string]int64{key: 1000}, true)
	got, _ = s.db.UserByID(u.ID)
	if got.UsedTraffic != 2500 {
		t.Fatalf("expected 2500 after node 1 added 500, got %d", got.UsedTraffic)
	}
}

// An agent from before the change omits the flag and still reports deltas. A
// panel upgraded ahead of its fleet must keep counting those correctly rather
// than treating small deltas as running totals.
func TestLegacyAgentStillReportsDeltas(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := trafficTestUser(t, s)
	key := job.UserEmail(u.ID)

	s.accountNodeTraffic(9, map[string]int64{key: 400}, false)
	s.accountNodeTraffic(9, map[string]int64{key: 400}, false)
	got, _ := s.db.UserByID(u.ID)
	if got.UsedTraffic != 800 {
		t.Fatalf("legacy delta reporting: used=%d, want 800", got.UsedTraffic)
	}
}

// Quota enforcement still has to fire on the remote plane, or a user who
// exhausts their allowance entirely on nodes stays active until the local
// poller happens to see traffic that by definition is not passing through it.
func TestRemoteTrafficStillTripsTheQuota(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := &store.User{Username: "q", Status: store.StatusActive, DataLimit: 1000, SubToken: "qtt"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s.accountNodeTraffic(4, map[string]int64{job.UserEmail(u.ID): 0}, true) // baseline
	s.accountNodeTraffic(4, map[string]int64{job.UserEmail(u.ID): 1500}, true)
	got, _ := s.db.UserByID(u.ID)
	if got.Status != store.StatusLimited {
		t.Fatalf("a user past their limit on a remote node should be limited, got %s", got.Status)
	}
}

// An on-hold user whose only traffic is remote must still start their clock,
// or they stay on hold forever and never activate.
func TestRemoteTrafficStartsTheOnHoldClock(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	u := &store.User{Username: "h", Status: store.StatusOnHold, OnHoldDuration: 3600, SubToken: "htt"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s.accountNodeTraffic(5, map[string]int64{job.UserEmail(u.ID): 0}, true) // baseline
	s.accountNodeTraffic(5, map[string]int64{job.UserEmail(u.ID): 2048}, true)
	got, _ := s.db.UserByID(u.ID)
	if got.FirstConnectAt == nil {
		t.Fatal("remote traffic did not start the on-hold clock")
	}
}
