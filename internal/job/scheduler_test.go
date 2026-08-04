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
