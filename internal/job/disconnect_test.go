package job

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// A disconnect hold runs out on its own; an unexpired one is left alone.
func TestAnExpiredDisconnectHoldIsReleased(t *testing.T) {
	db := ipTestStore(t)
	s := New(Config{DB: db})
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	expired := &store.User{Username: "done", SubToken: "tk-done", UUID: "11111111-2222-4333-8444-555555555555",
		Status: store.StatusActive, DisconnectedUntil: &past}
	active := &store.User{Username: "held", SubToken: "tk-held", UUID: "11111111-2222-4333-8444-555555555556",
		Status: store.StatusActive, DisconnectedUntil: &future}
	for _, u := range []*store.User{expired, active} {
		if err := db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	users, err := db.ListUsers(0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.releaseDisconnects(users, now) {
		t.Fatal("an expired hold was not released")
	}
	got1, _ := db.UserByID(expired.ID)
	got2, _ := db.UserByID(active.ID)
	if got1.DisconnectedUntil != nil {
		t.Fatal("expired hold still set")
	}
	if got2.DisconnectedUntil == nil {
		t.Fatal("an unexpired hold was released early")
	}
}
