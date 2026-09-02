package job

import (
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The panel told an operator when a quota had ALREADY tripped and an account had
// ALREADY expired — both of which the customer discovers at the same moment, by
// their connection failing. Nobody was told while there was still time to act.

type remFixture struct {
	s      *Scheduler
	db     *store.Store
	alerts []capturedAlert
	now    time.Time
}

func newRemFixture(t *testing.T) *remFixture {
	t.Helper()
	f := &remFixture{db: ipTestStore(t), now: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	f.s = New(Config{DB: f.db,
		Notify: func(e, subj, msg string) { f.alerts = append(f.alerts, capturedAlert{e, subj, msg}) }})
	f.s.now = func() time.Time { return f.now }
	return f
}

func (f *remFixture) user(t *testing.T, name string, limit, used int64, expire *time.Time) *store.User {
	t.Helper()
	u := &store.User{Username: name, SubToken: name, Status: store.StatusActive,
		DataLimit: limit, UsedTraffic: used, ExpireAt: expire}
	if err := f.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *remFixture) sweep() { f.s.sweepAt(f.now) }

func TestAUsageWarningFiresOnceNotEverySweep(t *testing.T) {
	f := newRemFixture(t)
	f.user(t, "heavy", 1000, 850, nil) // 85%

	f.sweep()
	if len(f.alerts) != 1 || f.alerts[0].event != "usage-reminder" {
		t.Fatalf("alerts = %+v, want one usage reminder", f.alerts)
	}
	if !strings.Contains(f.alerts[0].message, "85%") {
		t.Errorf("the warning does not say how much is used: %q", f.alerts[0].message)
	}

	// Sitting at 85% must not re-warn. A message every sweep gets filtered, and
	// the filter takes the useful ones with it.
	for i := 0; i < 20; i++ {
		f.now = f.now.Add(time.Minute)
		f.sweep()
	}
	if len(f.alerts) != 1 {
		t.Fatalf("alerts = %d, want 1 — the same warning was re-sent", len(f.alerts))
	}
}

func TestCrossingAHigherThresholdWarnsAgain(t *testing.T) {
	f := newRemFixture(t)
	u := f.user(t, "climbing", 1000, 850, nil)
	f.sweep()

	// 95% is a different thing to say than 80%: it is "about to stop working"
	// rather than "start thinking about it".
	if err := f.db.UpdateUserFields(u.ID, map[string]any{"used_traffic": 960}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	f.sweep()

	if len(f.alerts) != 2 {
		t.Fatalf("alerts = %+v, want a second one for the higher threshold", f.alerts)
	}
	if !strings.Contains(f.alerts[1].message, "96%") {
		t.Errorf("second warning = %q", f.alerts[1].message)
	}
}

func TestALeapPastBothThresholdsReportsTheHigherOne(t *testing.T) {
	f := newRemFixture(t)
	// 70% to 96% between two polls, which is ordinary for a heavy user.
	f.user(t, "jumper", 1000, 960, nil)
	f.sweep()

	if len(f.alerts) != 1 {
		t.Fatalf("alerts = %+v, want one", f.alerts)
	}
	// Telling them they have passed 80% when they are nearly out is the less
	// useful of the two things that are true.
	if !strings.Contains(f.alerts[0].message, "96%") {
		t.Errorf("warning = %q, want the 95%% threshold", f.alerts[0].message)
	}
}

func TestAResetLetsTheWarningFireAgainNextPeriod(t *testing.T) {
	f := newRemFixture(t)
	u := f.user(t, "monthly", 1000, 850, nil)
	if err := f.db.UpdateUserFields(u.ID, map[string]any{"reset_strategy": string(store.ResetDay)}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if len(f.alerts) != 1 {
		t.Fatalf("setup: %+v", f.alerts)
	}

	// A new day resets usage; the user climbs back to 85%.
	f.now = f.now.Add(25 * time.Hour)
	f.sweep() // performs the reset and clears the latch
	if err := f.db.UpdateUserFields(u.ID, map[string]any{"used_traffic": 850}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	f.sweep()

	// Without clearing, the latch that stops duplicates becomes the thing that
	// stops the feature working at all.
	if len(f.alerts) != 2 {
		t.Fatalf("alerts = %+v, want a warning in the new period too", f.alerts)
	}
}

func TestAnExpiryWarningFiresOncePerThreshold(t *testing.T) {
	f := newRemFixture(t)
	exp := f.now.Add(50 * time.Hour) // just over two days
	f.user(t, "lapsing", 0, 0, &exp)

	f.sweep()
	if len(f.alerts) != 1 || f.alerts[0].event != "expiry-reminder" {
		t.Fatalf("alerts = %+v, want one expiry reminder", f.alerts)
	}
	// At two days left, "3 days" is the threshold crossed and "1 day" is not.
	if !strings.Contains(f.alerts[0].message, "2 days") {
		t.Errorf("warning = %q", f.alerts[0].message)
	}

	for i := 0; i < 10; i++ {
		f.now = f.now.Add(time.Minute)
		f.sweep()
	}
	if len(f.alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(f.alerts))
	}

	// Crossing the 1-day mark is worth saying again.
	f.now = f.now.Add(30 * time.Hour)
	f.sweep()
	if len(f.alerts) != 2 {
		t.Fatalf("alerts = %+v, want a second reminder at the closer threshold", f.alerts)
	}
}

func TestNoWarningForAnAccountThatHasAlreadyStopped(t *testing.T) {
	f := newRemFixture(t)
	u := f.user(t, "done", 1000, 990, nil)
	if err := f.db.UpdateUserFields(u.ID, map[string]any{"status": string(store.StatusLimited)}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	// Warning somebody that they are about to be cut off, after they have been
	// cut off, is absurd.
	if len(f.alerts) != 0 {
		t.Fatalf("alerts = %+v, want none for a suspended account", f.alerts)
	}
}

func TestNoWarningWithoutALimitOrAnExpiry(t *testing.T) {
	f := newRemFixture(t)
	f.user(t, "unlimited", 0, 999999, nil)
	f.sweep()
	// No limit means nothing to approach.
	if len(f.alerts) != 0 {
		t.Fatalf("alerts = %+v, want none", f.alerts)
	}
}
