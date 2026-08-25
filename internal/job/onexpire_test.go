package job

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// ResetStrategy "on_expire" was ACCEPTED by the API validator and had no case in
// the scheduler, so it returned "this strategy does not reset" and usage never
// did. An operator chose "reset when the subscription expires", the panel took
// the setting, and the counter kept climbing across every renewal — with no
// error, no log, nothing to see.

func onExpireUser(t *testing.T, db *store.Store, name string, expireAt *time.Time, used int64) *store.User {
	t.Helper()
	u := &store.User{
		Username: name, SubToken: name, Status: store.StatusActive,
		ResetStrategy: store.ResetOnExpire, ExpireAt: expireAt, UsedTraffic: used,
	}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOnExpireResetsUsageOnceTheExpiryPasses(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db})
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	exp := base.Add(time.Hour)
	u := onExpireUser(t, db, "renewer", &exp, 5_000_000)

	// Before the expiry: nothing resets.
	s.sweepAt(base)
	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 5_000_000 {
		t.Fatalf("usage reset before the expiry: %d", got.UsedTraffic)
	}

	// The expiry passes: usage resets, so a renewal starts from zero.
	s.sweepAt(exp.Add(time.Minute))
	s.sweepAt(exp.Add(2 * time.Minute)) // the expiry transition consumes one tick
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("usage = %d after the expiry passed, want 0 — the strategy does nothing", got.UsedTraffic)
	}
	// Lifetime traffic is preserved: a reset is a billing-period boundary, not
	// an erasure of what the account ever used.
	if got.LifetimeTraffic != 5_000_000 {
		t.Errorf("lifetime = %d, want the usage carried over", got.LifetimeTraffic)
	}
	// The account stays expired. Zeroing usage must not hand someone a working
	// subscription they have not renewed.
	if got.Status != store.StatusExpired {
		t.Errorf("status = %q, want expired", got.Status)
	}
}

func TestOnExpireResetsOnlyOnce(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db})
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	exp := base.Add(-time.Hour) // already expired
	u := onExpireUser(t, db, "once", &exp, 1_000)

	for i := 0; i < 5; i++ {
		s.sweepAt(base.Add(time.Duration(i) * time.Minute))
	}
	got, _ := db.UserByID(u.ID)
	// The compare-and-set is keyed on the expiry date, so repeated sweeps cannot
	// keep folding usage into lifetime over and over.
	if got.LifetimeTraffic != 1_000 {
		t.Fatalf("lifetime = %d after five sweeps, want 1000 — the reset fired more than once", got.LifetimeTraffic)
	}
}

func TestOnExpireWithNoExpiryNeverResets(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db})
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	u := onExpireUser(t, db, "eternal", nil, 9_999)

	for i := 0; i < 3; i++ {
		s.sweepAt(base.Add(time.Duration(i) * time.Hour))
	}
	got, _ := db.UserByID(u.ID)
	// "Reset on expire" with no expiry date has no boundary to reset at. Guessing
	// some other cadence would silently wipe a counter the operator is watching.
	if got.UsedTraffic != 9_999 {
		t.Fatalf("usage = %d, want it untouched when there is no expiry to reset at", got.UsedTraffic)
	}
}

func TestOtherStrategiesStillWork(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db})
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	u := &store.User{Username: "daily", SubToken: "daily", Status: store.StatusActive,
		ResetStrategy: store.ResetDay, UsedTraffic: 4_242}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s.sweepAt(now)
	got, _ := db.UserByID(u.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("the daily strategy stopped working: usage = %d", got.UsedTraffic)
	}
}
