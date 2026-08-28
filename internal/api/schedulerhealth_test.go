package api

import (
	"errors"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The scheduler drives traffic accounting, expiry and the periodic data-limit
// reset. When it wedges nothing outwardly breaks — the panel serves, the UI
// looks normal, quotas just stop being enforced — and it used to expose no
// status at all, so the health indicator was blind to the one failure that
// costs money. These tests cover the three states an operator can be in.

// TestSchedulerSubsystemIsReported: the report must carry the scheduler at all.
func TestSchedulerSubsystemIsReported(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	rep := s.healthReport()

	var found *Subsystem
	for i := range rep.Subsystems {
		if rep.Subsystems[i].Key == "scheduler" {
			found = &rep.Subsystems[i]
		}
	}
	if found == nil {
		t.Fatal("health reports no scheduler subsystem, so a wedged job stays invisible")
	}
	if found.Summary == "" {
		t.Error("the scheduler subsystem carries no human-readable summary")
	}
	// A freshly started scheduler has registered its jobs and none is overdue,
	// so this must not cry wolf on every fresh panel.
	if found.State != HealthOK {
		t.Errorf("a running scheduler reports %q, want healthy (%s / %s)",
			found.State, found.Summary, found.Detail)
	}
}

// TestSchedulerAbsenceIsNotAFault: the light constructor runs without one, which
// is a supported deployment rather than a red light.
func TestSchedulerAbsenceIsNotAFault(t *testing.T) {
	sub := (&Server{}).healthScheduler()
	if sub.State != HealthNotConfigured {
		t.Fatalf("no scheduler reported as %q, want not_configured (%s)", sub.State, sub.Summary)
	}
	if sub.Summary == "" {
		t.Fatal("no summary — colour would be the only signal")
	}
}

// TestStoppedSchedulerIsCritical: a scheduler that is not running enforces no
// quota and expires nobody. That is the failure this subsystem exists for.
func TestStoppedSchedulerIsCritical(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &Server{sched: job.New(job.Config{DB: db})} // built, never started

	sub := s.healthScheduler()
	if sub.State != HealthCritical {
		t.Fatalf("a scheduler that never started reports %q, want critical (%s)", sub.State, sub.Summary)
	}
	if sub.Detail == "" {
		t.Error("nothing tells the operator what stopped working")
	}
}

// TestFailingSchedulerJobIsAWarning: the loop is alive and the next tick
// retries, which is a different situation from a stopped scheduler — but a poll
// that fails every cycle still means quotas are not being enforced, and it used
// to return bare with nothing recorded anywhere.
func TestFailingSchedulerJobIsAWarning(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sched := job.New(job.Config{
		DB:        db,
		PollEvery: 5 * time.Millisecond,
		PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
			return nil, errors.New("stats api unreachable")
		},
	})
	sched.Start()
	t.Cleanup(sched.Stop)

	// Wait for the accounting loop to have actually ticked once. Asserting on
	// the health report before the first tick would pass for the wrong reason:
	// a freshly started scheduler is healthy precisely because nothing has run.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ran := false
		for _, j := range sched.Status().Jobs {
			if j.Name == job.JobAccounting && j.Runs > 0 {
				ran = true
			}
		}
		if ran {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the accounting job never ran")
		}
		time.Sleep(5 * time.Millisecond)
	}

	sub := (&Server{sched: sched}).healthScheduler()
	if sub.State != HealthWarning {
		t.Fatalf("a job failing every cycle reports %q, want warning (%s / %s)",
			sub.State, sub.Summary, sub.Detail)
	}
	if sub.Detail == "" {
		t.Fatal("the failure carries no reason an operator could act on")
	}
}
