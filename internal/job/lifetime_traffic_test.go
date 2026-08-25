package job_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

func TestLifetimeTrafficAccumulationAndReset(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	u := &store.User{
		Username:      "user_bob",
		DataLimit:     10 * 1024 * 1024 * 1024,
		ResetStrategy: store.ResetMonth,
		Status:        store.StatusActive,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	email := job.UserEmail(u.ID)

	sched := job.New(job.Config{
		DB: s,
		PollTraffic: func(reset bool) (map[string]store.TrafficSplit, error) {
			return map[string]store.TrafficSplit{
				email: {Down: 2 * 1024 * 1024 * 1024}, // 2 GB
			}, nil
		},
	})

	// Run traffic accounting pass
	sched.PollAndAccountForTest()

	uReloaded, err := s.UserByID(u.ID)
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}

	if uReloaded.UsedTraffic != 2*1024*1024*1024 {
		t.Errorf("expected UsedTraffic = 2GB, got %d", uReloaded.UsedTraffic)
	}

	// Trigger periodic sweep reset at 1 month later
	future := time.Now().AddDate(0, 1, 1)
	sched.SweepAtForTest(future)

	uAfterReset, err := s.UserByID(u.ID)
	if err != nil {
		t.Fatalf("failed to reload user after reset: %v", err)
	}

	if uAfterReset.UsedTraffic != 0 {
		t.Errorf("expected UsedTraffic reset to 0, got %d", uAfterReset.UsedTraffic)
	}
	if uAfterReset.LifetimeTraffic != 2*1024*1024*1024 {
		t.Errorf("expected LifetimeTraffic accumulated to 2GB on reset, got %d", uAfterReset.LifetimeTraffic)
	}
}
