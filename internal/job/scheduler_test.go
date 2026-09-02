package job

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

func TestQuotaEnforcement(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "bob", Status: store.StatusActive, DataLimit: 1000, SubToken: "t"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	reloaded := false
	s := New(Config{
		DB:         db,
		ReloadHook: func() { reloaded = true },
		PollTraffic: func(reset bool) (map[string]store.TrafficSplit, error) {
			// Report traffic that exceeds the 1000-byte limit.
			return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: 1500}}, nil
		},
	})
	s.pollAndAccount()

	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 1500 {
		t.Fatalf("used traffic not accounted: %d", got.UsedTraffic)
	}
	if got.Status != store.StatusLimited {
		t.Fatalf("over-quota user not limited: status=%s", got.Status)
	}
	if !reloaded {
		t.Fatal("engine reload not triggered on quota breach")
	}
}

func TestExpirySweep(t *testing.T) {
	db, _ := store.Open(":memory:")
	past := time.Now().Add(-time.Hour)
	u := &store.User{Username: "carol", Status: store.StatusActive, ExpireAt: &past, SubToken: "t2"}
	_ = db.CreateUser(u)

	s := New(Config{DB: db})
	s.sweep()

	got, _ := db.UserByID(u.ID)
	if got.Status != store.StatusExpired {
		t.Fatalf("expired user not swept: status=%s", got.Status)
	}
}

func TestUserEmailRoundTrip(t *testing.T) {
	for _, id := range []uint{1, 42, 99999} {
		if got := parseUserEmail(UserEmail(id)); got != id {
			t.Fatalf("email round-trip failed for %d: got %d", id, got)
		}
	}
	if parseUserEmail("notauser") != 0 {
		t.Fatal("non-user email should parse to 0")
	}
}

func TestPeriodStart(t *testing.T) {
	// A Wednesday: 2026-08-05 12:34:56 UTC.
	now := time.Date(2026, 8, 5, 12, 34, 56, 0, time.UTC)
	check := func(st store.ResetStrategy, want time.Time) {
		got, ok := periodStart(now, st)
		if !ok || !got.Equal(want) {
			t.Fatalf("%s: got %v ok=%v want %v", st, got, ok, want)
		}
	}
	check(store.ResetDay, time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC))
	check(store.ResetWeek, time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)) // Monday
	check(store.ResetMonth, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	check(store.ResetYear, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if _, ok := periodStart(now, store.ResetNo); ok {
		t.Fatal("no_reset should not have a period")
	}
}

func TestPeriodicResetIdempotent(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "d", Status: store.StatusActive, ResetStrategy: store.ResetDay, UsedTraffic: 100, SubToken: "rt"}
	_ = db.CreateUser(u)
	s := New(Config{DB: db})
	day1 := time.Date(2026, 8, 5, 8, 0, 0, 0, time.UTC)
	s.sweepAt(day1)
	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 0 || got.LifetimeTraffic != 100 {
		t.Fatalf("first reset wrong: used=%d lifetime=%d", got.UsedTraffic, got.LifetimeTraffic)
	}
	// Same day, more usage, sweep again -> NOT reset again (idempotent).
	got.UsedTraffic = 50
	_ = db.SaveUser(got)
	s.sweepAt(day1.Add(6 * time.Hour))
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 50 {
		t.Fatalf("double reset within period: used=%d", got.UsedTraffic)
	}
	// Next day -> reset again, lifetime accumulates. (Also proves missed-run
	// recovery: a single sweep on day 2 catches up regardless of gaps.)
	s.sweepAt(day1.AddDate(0, 0, 1))
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 0 || got.LifetimeTraffic != 150 {
		t.Fatalf("second period reset wrong: used=%d lifetime=%d", got.UsedTraffic, got.LifetimeTraffic)
	}
}

func TestOnHoldTransition(t *testing.T) {
	db, _ := store.Open(":memory:")
	fc := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	u := &store.User{Username: "h", Status: store.StatusOnHold, OnHoldDuration: 3600, FirstConnectAt: &fc, SubToken: "ht"}
	_ = db.CreateUser(u)
	s := New(Config{DB: db})
	s.sweepAt(fc.Add(time.Minute))
	got, _ := db.UserByID(u.ID)
	if got.Status != store.StatusActive {
		t.Fatalf("on_hold should transition to active, got %s", got.Status)
	}
	if got.ExpireAt == nil || !got.ExpireAt.Equal(fc.Add(time.Hour)) {
		t.Fatalf("expire not set to firstconnect+duration: %v", got.ExpireAt)
	}
}

func TestResetDoesNotReviveExpired(t *testing.T) {
	db, _ := store.Open(":memory:")
	past := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	u := &store.User{Username: "e", Status: store.StatusExpired, ResetStrategy: store.ResetDay, ExpireAt: &past, SubToken: "et"}
	_ = db.CreateUser(u)
	s := New(Config{DB: db})
	s.sweepAt(time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC))
	got, _ := db.UserByID(u.ID)
	if got.Status != store.StatusExpired {
		t.Fatalf("expired user must stay expired, got %s", got.Status)
	}
}

func TestSchedulerStartStop(t *testing.T) {
	s := New(Config{PollEvery: 5 * time.Millisecond, SweepEvery: 5 * time.Millisecond})
	s.Start()
	time.Sleep(15 * time.Millisecond)
	s.Stop()
}

func TestUserEmailHelper(t *testing.T) {
	tag := UserEmail(42)
	if tag != "u42" {
		t.Fatalf("UserEmail(42) = %s, want u42", tag)
	}

	if id := parseUserEmail("u42"); id != 42 {
		t.Fatalf("parseUserEmail(u42) = %d, want 42", id)
	}

	if id := parseUserEmail("invalid"); id != 0 {
		t.Fatalf("parseUserEmail(invalid) = %d, want 0", id)
	}
}

// TestLastSeenStampedOnTraffic: the "online" indicator is built on LastSeenAt,
// which the poll cycle must stamp whenever a user actually moves bytes — and
// leave untouched for a user with no delta (who is not online).
func TestLastSeenStampedOnTraffic(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	active := &store.User{Username: "active", Status: store.StatusActive, SubToken: "a"}
	idle := &store.User{Username: "idle", Status: store.StatusActive, SubToken: "b"}
	if err := db.CreateUser(active); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(idle); err != nil {
		t.Fatal(err)
	}

	s := New(Config{
		DB: db,
		PollTraffic: func(reset bool) (map[string]store.TrafficSplit, error) {
			return map[string]store.TrafficSplit{UserEmail(active.ID): store.TrafficSplit{Down: 4096}}, nil // only 'active' moved bytes
		},
	})
	s.pollAndAccount()

	got, _ := db.UserByID(active.ID)
	if got.LastSeenAt == nil {
		t.Fatal("a user who transferred bytes must have LastSeenAt stamped")
	}
	gotIdle, _ := db.UserByID(idle.ID)
	if gotIdle.LastSeenAt != nil {
		t.Fatal("a user with no traffic delta must not be marked seen")
	}
}

// The on-hold plan type was entirely inert. sweep() reads FirstConnectAt to
// materialise ExpireAt = FirstConnectAt + OnHoldDuration, and NOTHING wrote it,
// so an on-hold user stayed on hold forever: never activated, never expired,
// never billed. TestOnHoldTransition above did not catch it because it sets
// FirstConnectAt by hand — which is precisely the field the product could not
// set for itself.
//
// This drives the real path: a fresh on-hold user, traffic observed, then a
// sweep.
func TestOnHoldClockStartsOnFirstTraffic(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "hold", Status: store.StatusOnHold, OnHoldDuration: 3600, SubToken: "ht2"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if u.FirstConnectAt != nil {
		t.Fatal("a fresh on-hold user must not already have a first-connect stamp")
	}

	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: 1024}}, nil
	}})
	s.now = func() time.Time { return start }

	s.pollAndAccount()

	got, _ := db.UserByID(u.ID)
	if got.FirstConnectAt == nil {
		t.Fatalf("first traffic did not start the on-hold clock, so the user can never activate")
	}
	if !got.FirstConnectAt.Equal(start) {
		t.Fatalf("first-connect stamp = %v, want %v", got.FirstConnectAt, start)
	}

	// And the sweep must now do its half of the job.
	s.sweepAt(start.Add(time.Minute))
	got, _ = db.UserByID(u.ID)
	if got.Status != store.StatusActive {
		t.Fatalf("on-hold user did not activate after first use, status = %s", got.Status)
	}
	if got.ExpireAt == nil || !got.ExpireAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("expiry = %v, want first-connect + 1h (%v)", got.ExpireAt, start.Add(time.Hour))
	}
}

// The stamp must be taken ONCE. Re-stamping on every cycle would push the
// expiry further out each time the user sent a packet, so the plan would never
// end.
func TestOnHoldClockIsNotRestartedByLaterTraffic(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "hold2", Status: store.StatusOnHold, OnHoldDuration: 3600, SubToken: "ht3"}
	_ = db.CreateUser(u)

	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	now := start
	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: 512}}, nil
	}})
	s.now = func() time.Time { return now }

	s.pollAndAccount()
	now = start.Add(30 * time.Minute)
	s.pollAndAccount()

	got, _ := db.UserByID(u.ID)
	if !got.FirstConnectAt.Equal(start) {
		t.Fatalf("the clock restarted on later traffic: %v, want %v", got.FirstConnectAt, start)
	}
}

// An ACTIVE user has no hold to start, and stamping one would be meaningless
// state on a row that never reads it.
func TestActiveUserGetsNoFirstConnectStamp(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "act", Status: store.StatusActive, SubToken: "at1"}
	_ = db.CreateUser(u)

	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: 2048}}, nil
	}})
	s.pollAndAccount()

	got, _ := db.UserByID(u.ID)
	if got.FirstConnectAt != nil {
		t.Fatalf("an active user was given an on-hold stamp: %v", got.FirstConnectAt)
	}
	if got.LastSeenAt == nil {
		t.Fatalf("last-seen should still be stamped for an active user")
	}
}

// The poller used to read the engine's counters with -reset: one call both read
// the numbers and zeroed them, making the in-flight value the only copy. A panel
// killed between the read and the write lost that traffic permanently. Reading
// cumulatively makes a cycle idempotent — a re-read returns the same number and
// the delta is recomputed.
func TestTrafficIsNotLostWhenACycleIsInterrupted(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "t", Status: store.StatusActive, SubToken: "tt1"}
	_ = db.CreateUser(u)

	// The engine's counter keeps climbing; it is never reset by the panel.
	cumulative := int64(0)
	reads := 0
	s := New(Config{DB: db, PollTraffic: func(reset bool) (map[string]store.TrafficSplit, error) {
		if reset {
			t.Fatal("the poller must never ask the engine to reset its counters: " +
				"that makes the read the only copy of the data")
		}
		reads++
		return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: cumulative}}, nil
	}})

	cumulative = 1000
	s.pollAndAccount()
	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 1000 {
		t.Fatalf("first cycle: used=%d, want 1000", got.UsedTraffic)
	}

	// A cycle that reads the same total again must add nothing. Under the old
	// destructive read this could not even be expressed.
	s.pollAndAccount()
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 1000 {
		t.Fatalf("a repeated read double-counted: used=%d, want 1000", got.UsedTraffic)
	}

	// More traffic: only the increment counts.
	cumulative = 2500
	s.pollAndAccount()
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 2500 {
		t.Fatalf("second cycle: used=%d, want 2500", got.UsedTraffic)
	}
}

// The panel restarts the engine on every config change, and its counters come
// back at zero. Treating that as a negative delta — or as nothing — would
// discard real usage on the most common event in a running panel.
func TestEngineRestartCountsFromZeroInsteadOfLosingUsage(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "r", Status: store.StatusActive, SubToken: "rt1"}
	_ = db.CreateUser(u)

	cumulative := int64(5000)
	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: cumulative}}, nil
	}})
	s.pollAndAccount()

	// Engine restarted: the counter is back near zero and climbing again.
	cumulative = 300
	s.pollAndAccount()

	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 5300 {
		t.Fatalf("usage after an engine restart = %d, want 5300 (5000 before + 300 since)", got.UsedTraffic)
	}

	// And the new baseline must be the post-restart value, not the old one.
	cumulative = 800
	s.pollAndAccount()
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 5800 {
		t.Fatalf("usage after the restart baseline settled = %d, want 5800", got.UsedTraffic)
	}
}

// A counter whose key resolves to no user must still be remembered. Otherwise,
// if that key later becomes a real user, the counter's entire history lands on
// them as a single delta.
func TestUnknownCounterIsStillSnapshotted(t *testing.T) {
	db, _ := store.Open(":memory:")
	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return map[string]store.TrafficSplit{"u99999": store.TrafficSplit{Down: 4242}}, nil
	}})
	s.pollAndAccount()

	snaps, err := db.TrafficSnapshots(store.ScopeLocalEngine)
	if err != nil {
		t.Fatal(err)
	}
	if snaps["u99999"] != 4242 {
		t.Fatalf("an unknown counter was not recorded: %v", snaps)
	}
}

// Crossing the data limit must still stop the user, and must do it once.
func TestQuotaStillTripsAndOnlyReloadsOnTheTransition(t *testing.T) {
	db, _ := store.Open(":memory:")
	u := &store.User{Username: "q", Status: store.StatusActive, DataLimit: 1000, SubToken: "qt1"}
	_ = db.CreateUser(u)

	reloads := 0
	cumulative := int64(1500)
	s := New(Config{
		DB:         db,
		ReloadHook: func() { reloads++ },
		PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
			return map[string]store.TrafficSplit{UserEmail(u.ID): store.TrafficSplit{Down: cumulative}}, nil
		},
	})

	s.pollAndAccount()
	got, _ := db.UserByID(u.ID)
	if got.Status != store.StatusLimited {
		t.Fatalf("a user past their limit should be limited, got %s", got.Status)
	}
	if reloads != 1 {
		t.Fatalf("crossing the limit should reload once, got %d", reloads)
	}

	// Still over, still limited — but nothing changed, so no further reloads.
	cumulative = 2000
	s.pollAndAccount()
	if reloads != 1 {
		t.Fatalf("an already-limited user triggered another reload: %d", reloads)
	}
}
