package job

import (
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// silenceSchedulerLog keeps the deliberate panic stacks these tests provoke out
// of the test output. The log line itself is asserted on indirectly, via the
// message that ends up on the job's status.
func silenceSchedulerLog(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

func jobStatusNamed(t *testing.T, st Status, name string) JobStatus {
	t.Helper()
	for _, j := range st.Jobs {
		if j.Name == name {
			return j
		}
	}
	t.Fatalf("job %q missing from scheduler status %+v", name, st.Jobs)
	return JobStatus{}
}

// TestSchedulerPanicIsRecordedNotSwallowed: the job runner's recovery used to be
// `if r := recover(); r != nil { }` with an empty body, so a job that panicked
// on every single tick was indistinguishable from one that was working. Quotas
// would stop being enforced with nothing anywhere to show for it.
func TestSchedulerPanicIsRecordedNotSwallowed(t *testing.T) {
	silenceSchedulerLog(t)
	s := New(Config{})
	s.registerJob("probe", time.Minute)

	s.runJob("probe", func() error { panic("boom") })

	j := jobStatusNamed(t, s.Status(), "probe")
	if j.Panics != 1 {
		t.Errorf("panics = %d, want 1: a swallowed panic leaves no trace", j.Panics)
	}
	if j.Failures != 1 {
		t.Errorf("failures = %d, want 1", j.Failures)
	}
	if !strings.Contains(j.LastError, "boom") {
		t.Errorf("last error = %q, want it to carry the panic value", j.LastError)
	}
	if j.Running {
		t.Error("job still marked running after the panic unwound it")
	}

	// A later success clears the message but keeps the history: an operator
	// needs to know it is working NOW, and that it panicked once.
	s.runJob("probe", func() error { return nil })
	j = jobStatusNamed(t, s.Status(), "probe")
	if j.LastError != "" {
		t.Errorf("last error = %q after a successful run, want cleared", j.LastError)
	}
	if j.Panics != 1 || j.Runs != 2 {
		t.Errorf("panics = %d, runs = %d, want 1 and 2", j.Panics, j.Runs)
	}
	if j.LastSuccess.IsZero() {
		t.Error("no last-success time recorded")
	}
}

// TestAccountingPollFailureIsReported: pollAndAccount returned bare when the
// engine's stats API failed, so a poll that errored every cycle looked exactly
// like an idle panel — while every quota went unenforced.
func TestAccountingPollFailureIsReported(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		DB: db,
		PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
			return nil, errors.New("stats api unreachable")
		},
	})
	s.registerJob(JobAccounting, s.pollEvery)

	s.runJob(JobAccounting, s.pollAndAccount)

	j := jobStatusNamed(t, s.Status(), JobAccounting)
	if j.Failures != 1 {
		t.Fatalf("failures = %d, want 1: the poll error was dropped", j.Failures)
	}
	if !strings.Contains(j.LastError, "stats api unreachable") {
		t.Fatalf("last error = %q, want the engine's reason", j.LastError)
	}
}

// TestSweepFailureIsReported: the lifecycle sweep returned bare when it could
// not read the user list, so a panel that expired nobody and reset nobody
// reported itself perfectly healthy.
func TestSweepFailureIsReported(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// Closing the handle is the cheapest way to make every store call fail the
	// way a broken database actually does.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db})
	s.registerJob(JobSweep, s.sweepEvery)

	s.runJob(JobSweep, s.sweep)

	j := jobStatusNamed(t, s.Status(), JobSweep)
	if j.Failures != 1 || j.LastError == "" {
		t.Fatalf("failures = %d, last error = %q; a sweep that read nothing reported success",
			j.Failures, j.LastError)
	}
}

// TestOverdueJobsDetectsAStalledLoop covers the three shapes an operator cares
// about and, just as importantly, the two that must NOT raise an alarm.
func TestOverdueJobsDetectsAStalledLoop(t *testing.T) {
	now := time.Now()
	st := Status{Running: true, StartedAt: now.Add(-3 * time.Hour), Jobs: []JobStatus{
		// Healthy: completed within its cadence.
		{Name: "ticking", IntervalSeconds: 60, LastRun: now.Add(-30 * time.Second)},
		// Healthy: event-driven, so "has not fired" is normal.
		{Name: "eventdriven", IntervalSeconds: 0},
		// Healthy: has never completed, but is inside its first long run right
		// now. Judged by completion alone this would read as three hours dead.
		{Name: "firstlongrun", IntervalSeconds: 3600, Running: true, LastStart: now.Add(-10 * time.Second)},
		// Stalled: the loop stopped ticking.
		{Name: "stalled", IntervalSeconds: 60, LastRun: now.Add(-5 * time.Minute)},
		// Wedged: started and never returned.
		{Name: "wedged", IntervalSeconds: 60, Running: true,
			LastStart: now.Add(-10 * time.Minute), LastRun: now.Add(-10*time.Minute - time.Second)},
		// Never ran at all: the goroutine is gone.
		{Name: "never", IntervalSeconds: 60},
	}}

	var got []string
	for _, j := range st.OverdueJobs(now) {
		got = append(got, j.Name)
	}
	want := []string{"stalled", "wedged", "never"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("overdue jobs = %v, want %v", got, want)
	}
}

// TestOverdueGraceHasAFloor: the accounting poll runs every ten seconds, and a
// bare "twice the interval" rule would call the scheduler wedged after twenty —
// well inside the jitter of a loaded box. An alarm that fires under normal load
// is one operators learn to ignore.
func TestOverdueGraceHasAFloor(t *testing.T) {
	now := time.Now()
	st := Status{Running: true, StartedAt: now.Add(-time.Hour), Jobs: []JobStatus{
		{Name: JobAccounting, IntervalSeconds: 10, LastRun: now.Add(-25 * time.Second)},
	}}
	if late := st.OverdueJobs(now); len(late) != 0 {
		t.Fatalf("a 10s job that ran 25s ago reported overdue: %v", late)
	}
	st.Jobs[0].LastRun = now.Add(-45 * time.Second)
	if late := st.OverdueJobs(now); len(late) != 1 {
		t.Fatalf("a 10s job that ran 45s ago is not reported overdue: %v", late)
	}
}

// TestStatusRecordsResponseTime: the probe is only useful if it says how long
// the worker took, so a loop degrading towards a wedge can be seen coming.
func TestStatusRecordsResponseTime(t *testing.T) {
	var mu sync.Mutex
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{})
	// Every read advances 250ms, so one run spans exactly one step.
	s.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(250 * time.Millisecond)
		return clock
	}
	s.registerJob("probe", time.Minute)

	s.runJob("probe", func() error { return nil })

	j := jobStatusNamed(t, s.Status(), "probe")
	if j.LastDurationMS != 250 {
		t.Fatalf("last duration = %vms, want 250", j.LastDurationMS)
	}
	if j.LastStart.IsZero() || j.LastRun.IsZero() {
		t.Fatal("start/completion times not recorded")
	}
}

// TestStartRegistersEveryJobBeforeItRuns: a status list built only from jobs
// that have already reported can never contain the one that never started,
// which is the failure most worth seeing.
func TestStartRegistersEveryJobBeforeItRuns(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := New(Config{
		DB:     db,
		Notify: func(string, string, string) {},
	})
	s.Start()

	st := s.Status()
	if !st.Running {
		t.Fatal("scheduler reports itself as not running after Start")
	}
	if st.StartedAt.IsZero() {
		t.Fatal("no start time recorded")
	}
	for _, name := range []string{JobAccounting, JobSweep, JobRetention, JobMaintenance, JobNotify} {
		j := jobStatusNamed(t, st, name)
		if j.Runs != 0 {
			t.Errorf("%s already reports %d runs", name, j.Runs)
		}
	}
	// The poll and sweep intervals are the ones the overdue check divides by.
	if got := jobStatusNamed(t, st, JobAccounting).IntervalSeconds; got != s.pollEvery.Seconds() {
		t.Errorf("accounting interval = %v, want %v", got, s.pollEvery.Seconds())
	}

	s.Stop()
	if s.Status().Running {
		t.Fatal("scheduler still reports itself running after Stop")
	}
}

// TestNotifierPanicIsCounted: alert() recovered into an empty body, so a bot
// that panicked on every send was a silent no-op — every quota trip and expiry
// went unannounced while the panel looked fine.
func TestNotifierPanicIsCounted(t *testing.T) {
	silenceSchedulerLog(t)
	s := New(Config{Notify: func(string, string, string) { panic("telegram exploded") }})

	s.alert("expiry", "bob", "message")

	j := jobStatusNamed(t, s.Status(), JobNotify)
	if j.Panics != 1 || !strings.Contains(j.LastError, "telegram exploded") {
		t.Fatalf("notify job: panics = %d, last error = %q", j.Panics, j.LastError)
	}
	// It must still be excluded from the overdue check: a notifier that has not
	// fired is a quiet panel, not a broken one.
	if late := s.Status().OverdueJobs(time.Now()); len(late) != 0 {
		t.Fatalf("event-driven notifier reported overdue: %v", late)
	}
}
