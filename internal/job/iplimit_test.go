package job

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// IPLimit was stored and editable from the day it was added and NOTHING read it:
// an operator capped an account at two devices and the panel did nothing with
// the number. These tests are what stop that returning, and what stop the
// enforcement being so eager that it locks out a phone changing network.

type ipFixture struct {
	s      *Scheduler
	db     *store.Store
	counts map[string]int
	audits []string
	now    time.Time
}

func ipTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newIPFixture(t *testing.T) *ipFixture {
	t.Helper()
	db := ipTestStore(t)
	f := &ipFixture{db: db, counts: map[string]int{}, now: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	f.s = New(Config{
		DB:              db,
		ActiveAddresses: func(email string) int { return f.counts[email] },
		AuditIPLimit: func(action, target string, seen, limit int) {
			f.audits = append(f.audits, action+":"+target)
		},
	})
	f.s.now = func() time.Time { return f.now }
	return f
}

func (f *ipFixture) user(t *testing.T, name string, limit int) *store.User {
	t.Helper()
	u := &store.User{Username: name, SubToken: name, Status: store.StatusActive, IPLimit: limit}
	if err := f.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *ipFixture) reload(t *testing.T, id uint) *store.User {
	t.Helper()
	u, err := f.db.UserByID(id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOneBreachIsToleratedTwoIsNot(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "alice", 2)
	f.counts[UserEmail(u.ID)] = 5

	// A phone moving from wi-fi to cellular is briefly at two addresses through
	// no fault of its own. Locking it out for that is a worse failure than
	// briefly tolerating a shared account.
	if f.s.enforceIPLimits() {
		t.Fatal("acted on a single sweep; a device that changed network would be locked out")
	}
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("user was held after one observation")
	}

	if !f.s.enforceIPLimits() {
		t.Fatal("a second consecutive breach was not acted on; the limit does nothing")
	}
	held := f.reload(t, u.ID)
	if held.IPLimitedUntil == nil {
		t.Fatal("user over their limit across two sweeps was not held")
	}
	if !held.IPLimitedUntil.After(f.now) {
		t.Fatal("the hold is already in the past")
	}
	if len(f.audits) != 1 || f.audits[0] != "user.ip_limit.enforced:alice" {
		t.Fatalf("audits = %v; an account that stops working needs a findable reason", f.audits)
	}
}

func TestBreachesMustBeConsecutive(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "roamer", 1)
	email := UserEmail(u.ID)

	// A device that changes network once an hour would otherwise accumulate its
	// way to a lockout over a day.
	for i := 0; i < 6; i++ {
		f.counts[email] = 3
		f.s.enforceIPLimits()
		f.counts[email] = 1
		f.s.enforceIPLimits()
	}
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("alternating breaches accumulated into a lockout; breaches must be consecutive")
	}
}

func TestAtTheLimitIsNotOverIt(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "exact", 3)
	f.counts[UserEmail(u.ID)] = 3

	f.s.enforceIPLimits()
	f.s.enforceIPLimits()
	// An off-by-one here means an operator who allows three devices gets two.
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("a user exactly AT their limit was held; the limit is a maximum, not a threshold to stay under")
	}
}

func TestZeroMeansUnlimited(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "free", 0)
	f.counts[UserEmail(u.ID)] = 500

	f.s.enforceIPLimits()
	f.s.enforceIPLimits()
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("a user with no limit was held")
	}
}

func TestHoldIsReleasedWhenItExpires(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "held", 1)
	f.counts[UserEmail(u.ID)] = 4
	f.s.enforceIPLimits()
	f.s.enforceIPLimits()
	if f.reload(t, u.ID).IPLimitedUntil == nil {
		t.Fatal("setup: user should be held")
	}

	// Still held before the cooldown passes.
	f.now = f.now.Add(ipLimitCooldown - time.Second)
	f.s.enforceIPLimits()
	if f.reload(t, u.ID).IPLimitedUntil == nil {
		t.Fatal("the hold was released early")
	}

	f.now = f.now.Add(2 * time.Second)
	if !f.s.enforceIPLimits() {
		t.Fatal("releasing a user did not report a change; the engines would never be reloaded and the user would stay locked out")
	}
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("the hold outlived its cooldown; nothing else would ever clear it")
	}
}

func TestRemovingTheLimitReleasesAHeldUser(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "reprieved", 1)
	f.counts[UserEmail(u.ID)] = 9
	f.s.enforceIPLimits()
	f.s.enforceIPLimits()
	if f.reload(t, u.ID).IPLimitedUntil == nil {
		t.Fatal("setup: user should be held")
	}

	// An operator deciding the limit was wrong must not have to wait out a rule
	// they have just deleted.
	if err := f.db.UpdateUserFields(u.ID, map[string]any{"ip_limit": 0}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !f.s.enforceIPLimits() {
		t.Fatal("clearing the limit did not release the user")
	}
	if f.reload(t, u.ID).IPLimitedUntil != nil {
		t.Fatal("the user is still held under a limit that no longer exists")
	}
}

func TestNoPresenceSourceMeansNoEnforcement(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db}) // ActiveAddresses is nil
	u := &store.User{Username: "x", SubToken: "x", Status: store.StatusActive, IPLimit: 1}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	held := time.Now().Add(time.Hour)
	if err := db.UpdateUserFields(u.ID, map[string]any{"ip_limited_until": held}, time.Time{}); err != nil {
		t.Fatal(err)
	}

	if s.enforceIPLimits() {
		t.Fatal("enforcement ran without a presence source")
	}
	// Enforcing against a count of zero would release every held user the moment
	// the core went away — turning an engine outage into a silent lifting of
	// every limit on the panel.
	got, err := db.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IPLimitedUntil == nil {
		t.Fatal("a held user was released because the count was unavailable")
	}
}

func TestHeldUsersAreNotRemeasured(t *testing.T) {
	f := newIPFixture(t)
	u := f.user(t, "quiet", 1)
	email := UserEmail(u.ID)
	f.counts[email] = 5
	f.s.enforceIPLimits()
	f.s.enforceIPLimits()

	// While held they cannot connect, so their address count decays to zero.
	// Reading that as compliance and immediately re-admitting them would make
	// the cooldown meaningless.
	f.counts[email] = 0
	f.now = f.now.Add(time.Minute)
	f.s.enforceIPLimits()
	if f.reload(t, u.ID).IPLimitedUntil == nil {
		t.Fatal("a held user was released early because they had stopped connecting — which is what being held means")
	}
}
