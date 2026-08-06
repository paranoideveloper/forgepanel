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
		PollTraffic: func(reset bool) (map[string]int64, error) {
			// Report traffic that exceeds the 1000-byte limit.
			return map[string]int64{UserEmail(u.ID): 1500}, nil
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
