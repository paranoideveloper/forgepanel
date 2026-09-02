package job

import (
	"sync/atomic"
	"testing"
	"time"
)

// EvictIdle carried the comment "(called by the scheduler)" and had no caller
// outside tests, so every ForgeDNS session lived until the process restarted.
// This is the guard: the scheduler must actually run its maintenance hook.

func TestMaintenanceHookIsActuallyCalled(t *testing.T) {
	var calls atomic.Int64
	s := New(Config{
		PollEvery:   time.Hour, // keep the other loops out of the way
		SweepEvery:  10 * time.Millisecond,
		Maintenance: func() { calls.Add(1) },
	})
	s.Start()
	defer s.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the scheduler never called its maintenance hook; housekeeping that is documented as scheduled but never runs is how sessions leak until a restart")
}

func TestMaintenancePanicDoesNotStopLaterRuns(t *testing.T) {
	var calls atomic.Int64
	s := New(Config{
		PollEvery:  time.Hour,
		SweepEvery: 10 * time.Millisecond,
		Maintenance: func() {
			if calls.Add(1) == 1 {
				panic("first run explodes")
			}
		},
	})
	s.Start()
	defer s.Stop()

	// A panic on a long-lived goroutine would silently stop every future run,
	// and the resulting leak shows up hours later as memory growth with nothing
	// pointing at the cause.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("maintenance ran %d times; a panic stopped the loop", calls.Load())
}

func TestNilMaintenanceIsFine(t *testing.T) {
	s := New(Config{PollEvery: time.Hour, SweepEvery: 10 * time.Millisecond})
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}
