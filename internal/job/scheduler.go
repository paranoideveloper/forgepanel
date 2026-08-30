// Package job is the panel's cron scheduler (spec §11): it polls engine stats,
// rolls traffic into the store, enforces quotas and expiry within a poll cycle,
// resets traffic by strategy, and sweeps on-hold users. Jobs are plain
// closures on a ticker so the core build needs no scheduler dependency.
package job

import (
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"

	"context"
	"github.com/forgepanel/forgepanel/internal/backup"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/version"
)

// StatsSource abstracts the engine controller for testability.
type StatsSource interface {
	QueryUserStats(reset bool) (map[string]*UserTrafficDelta, error)
}

// UserTrafficDelta is the per-user delta the scheduler consumes. It mirrors the
// controller's UserTraffic to avoid an import cycle (core imports job for wiring
// via an adapter in the api layer).
type UserTrafficDelta struct {
	Email    string
	Uplink   int64
	Downlink int64
}

// Scheduler runs the recurring panel jobs.
type Scheduler struct {
	db         store.SchedulerStore
	pollEvery  time.Duration
	sweepEvery time.Duration
	// auditRetention is how long audit entries are kept. Zero disables pruning,
	// which is a deliberate choice an operator can make (some need an unbounded
	// trail for compliance) rather than a default that quietly fills a disk.
	auditRetention time.Duration
	// Rollup retention is TWO clocks: hourly is debug detail worth weeks, daily
	// is billing history worth years. One shared cutoff would either keep an
	// unusable amount of hourly data or destroy the long-range chart.
	rollupHourlyRetention time.Duration
	rollupDailyRetention  time.Duration
	// Scheduled backups. A backup that happens only when someone remembers is
	// not a backup policy.
	backupEvery func() (dataDir, master string, every time.Duration, keep int)
	// deliverBackup ships a freshly-written backup off the box. Nil means the
	// backup stays local, which is the default.
	deliverBackup func(path string)
	reloadHook    func()                                                  // called after a mutation to reapply engine configs
	pollTraffic   func(reset bool) (map[string]store.TrafficSplit, error) // email -> uplink/downlink
	// activeAddresses reports how many distinct source addresses a user is
	// currently connecting from. Nil disables IP-limit enforcement entirely,
	// which is the honest behaviour when there is no presence source: acting on
	// a count of zero would release every held user.
	activeAddresses func(email string) int
	auditHook       func(action, target string, seen, limit int)
	ipLimits        *ipLimitState
	reminders       *reminderState
	maintenance     func()
	notify          func(event, subject, message string)

	cancel context.CancelFunc
	wg     sync.WaitGroup
	now    func() time.Time // injectable clock (tests use a controllable one)

	// Job self-health. A scheduler that wedged or panicked used to be entirely
	// invisible: loop()'s panic recovery had an empty body and every job
	// returned bare on error, so traffic accounting, expiry and the data-limit
	// reset could stop dead while the panel kept serving and looking normal.
	// These fields are the only place that failure becomes observable, so they
	// are maintained by the runner rather than by each job.
	healthMu  sync.Mutex
	jobs      map[string]*jobHealth
	jobOrder  []string // registration order, so Status is stable across calls
	startedAt time.Time
	running   bool
}

// Config configures a Scheduler.
type Config struct {
	DB         store.SchedulerStore
	PollEvery  time.Duration
	SweepEvery time.Duration
	ReloadHook func()
	// AuditRetention bounds the audit trail. Zero keeps everything, which is a
	// choice an operator can legitimately make; it is not a default that
	// quietly fills a disk, because the pruner treats zero as "keep" rather
	// than as a cutoff of now.
	AuditRetention time.Duration
	// RollupHourlyRetention / RollupDailyRetention bound the usage history.
	// Zero keeps everything for that resolution.
	RollupHourlyRetention time.Duration
	RollupDailyRetention  time.Duration
	// BackupConfig supplies the scheduled-backup settings at run time, so an
	// operator changing them does not require a restart. Nil disables them.
	BackupConfig func() (dataDir, master string, every time.Duration, keep int)

	// DeliverBackup is called with the path of each scheduled backup as it is
	// written, for an operator who has asked for an off-box copy. Optional: a
	// nil hook leaves the backup on disk, which is what it did before.
	DeliverBackup func(path string)
	// PollTraffic returns the engine's per-user counters. The scheduler always
	// calls it with reset=false and accounts by subtraction against a stored
	// snapshot: a destructive read makes the in-flight value the only copy of
	// the data, so a panel killed mid-cycle loses that traffic for good, and
	// usage only ever fails downward — quotas stop tripping and an exhausted
	// user keeps being served, with nothing to show for it.
	// TestTrafficIsNotLostWhenACycleIsInterrupted fails if this is ever called
	// with reset=true.
	PollTraffic func(reset bool) (map[string]store.TrafficSplit, error)
	// ActiveAddresses reports a user's current distinct source-address count.
	// Nil disables IP-limit enforcement rather than enforcing against zero.
	ActiveAddresses func(email string) int
	// AuditIPLimit records enforcement actions so an account that stops working
	// has a findable reason.
	AuditIPLimit func(action, target string, seen, limit int)
	// Notify pushes an operator-facing alert. Nil disables notifications, so a
	// panel with no Telegram configured needs no checks at any call site.
	//
	// It takes the SUBJECT separately from the message because the notifier
	// deduplicates on it: an ongoing problem must not be announced every sweep.
	Notify func(event, subject, message string)
	// Maintenance is the periodic housekeeping that has no other home: evicting
	// idle tunnel sessions, re-verifying clean-IP sets. Nil disables it.
	//
	// One hook rather than several: these run on the same cadence and each is a
	// few lines, and a scheduler with a field per chore accumulates fields
	// nobody wires up — which is how EvictIdle ended up documented as "called by
	// the scheduler" with no caller anywhere.
	Maintenance func()
}

// New builds a Scheduler with sane defaults.
func New(cfg Config) *Scheduler {
	if cfg.PollEvery == 0 {
		cfg.PollEvery = 10 * time.Second
	}
	if cfg.SweepEvery == 0 {
		cfg.SweepEvery = time.Minute
	}
	return &Scheduler{
		db: cfg.DB, pollEvery: cfg.PollEvery, sweepEvery: cfg.SweepEvery,
		reloadHook: cfg.ReloadHook, pollTraffic: cfg.PollTraffic,
		auditRetention:        cfg.AuditRetention,
		rollupHourlyRetention: cfg.RollupHourlyRetention,
		rollupDailyRetention:  cfg.RollupDailyRetention,
		backupEvery:           cfg.BackupConfig,
		deliverBackup:         cfg.DeliverBackup,
		activeAddresses:       cfg.ActiveAddresses,
		auditHook:             cfg.AuditIPLimit,
		ipLimits:              newIPLimitState(),
		reminders:             newReminderState(),
		maintenance:           cfg.Maintenance,
		notify:                cfg.Notify,
		now:                   time.Now,
	}
}

// hasDB reports whether the scheduler has usable persistence.
//
// db is an interface, so a nil *store.Store handed to Config.DB lands here as a
// NON-nil interface value: `s.db == nil` is false and every job below would run
// against a nil receiver and panic inside GORM, from a stack with nothing in it
// pointing back at the caller that passed the nil. This reports false for both
// shapes — a genuinely unset field, and a typed nil concrete store.
func (s *Scheduler) hasDB() bool {
	if s == nil || s.db == nil {
		return false
	}
	if st, ok := s.db.(*store.Store); ok {
		return st != nil
	}
	return true
}

// Start launches the scheduler goroutines until Stop is called.
func (s *Scheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Register every job BEFORE its goroutine runs. A job that has never ticked
	// at all is precisely the failure worth seeing, and a status list built only
	// from jobs that have already reported could never contain one.
	s.healthMu.Lock()
	s.startedAt = s.now()
	s.running = true
	s.healthMu.Unlock()
	s.registerJob(JobAccounting, s.pollEvery)
	s.registerJob(JobSweep, s.sweepEvery)
	s.registerJob(JobRetention, time.Hour)
	s.registerJob(JobMaintenance, s.sweepEvery)
	if s.notify != nil {
		// Notification is event-driven, not periodic, so it registers with no
		// interval: its failures must be visible without it ever being called
		// overdue for not having fired.
		s.registerJob(JobNotify, 0)
	}

	s.wg.Add(4)
	go func() {
		defer s.wg.Done()
		s.loop(ctx, JobAccounting, s.pollEvery, s.pollAndAccount)
	}()
	go func() {
		defer s.wg.Done()
		s.loop(ctx, JobSweep, s.sweepEvery, s.sweep)
	}()
	go func() {
		defer s.wg.Done()
		// Hourly is often enough: retention is measured in days, and a tighter
		// cadence would delete a handful of rows over and over for no benefit.
		s.loop(ctx, JobRetention, time.Hour, func() error {
			// Joined rather than short-circuited: a failing prune must not stop
			// the scheduled backup, and the operator needs to see all of them.
			return errors.Join(s.pruneAudit(), s.pruneRollups(), s.runScheduledBackup())
		})
	}()
	go func() {
		defer s.wg.Done()
		// Housekeeping, on its own loop rather than folded into the hourly one:
		// idle sessions have to be evicted on a much tighter cadence than
		// retention pruning, and an hour of leaked sessions on a busy tunnel is
		// real memory.
		s.loop(ctx, JobMaintenance, s.sweepEvery, s.runMaintenance)
	}()
}

// alert pushes an operator-facing notification, containing any panic.
//
// Notification is a side effect of the lifecycle sweep, never a condition of it:
// a bot that is down, rate-limited or misconfigured must not stop users being
// suspended or expired.
func (s *Scheduler) alert(event, subject, message string) {
	if s.notify == nil {
		return
	}
	// The recovery stays here rather than being left to runJob: alert is called
	// from the middle of a sweep, and a notifier that panics must not abandon
	// the users that have not been looked at yet. It is now counted and named,
	// so a bot that panics on every send stops being a silent no-op.
	start := s.now()
	panicked := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = recoveredMessage(JobNotify, r)
			}
		}()
		s.notify(event, subject, message)
	}()
	s.recordRun(JobNotify, start, nil, panicked)
}

// runMaintenance calls the maintenance hook, containing any panic.
//
// It runs on a long-lived goroutine that also has no other job. A panic here
// would silently stop every future maintenance run, and the resulting leak would
// show up hours later as memory growth with nothing pointing at the cause.
func (s *Scheduler) runMaintenance() error {
	if s.maintenance == nil {
		return nil
	}
	// The panic guard moved to runJob, which counts, logs and reports it.
	// Recovering here as well would swallow the panic again before anything
	// could see it, which is how a dead maintenance loop stayed invisible.
	s.maintenance()
	return nil
}

// runScheduledBackup takes a backup when one is due.
//
// Due-ness is judged from the newest backup on disk rather than from a timer
// held in memory, so a panel that restarts every hour still produces daily
// backups instead of one per restart — and a panel that was down for a week
// takes one immediately when it returns.
func (s *Scheduler) runScheduledBackup() error {
	if s.backupEvery == nil {
		return nil
	}
	dataDir, master, every, keep := s.backupEvery()
	if every <= 0 || strings.TrimSpace(master) == "" || dataDir == "" {
		return nil
	}
	last, _, err := backup.LatestLocal(dataDir)
	if err == nil && !last.IsZero() && s.now().Sub(last) < every {
		return nil
	}
	// The manifest lets a restore refuse a database this build cannot migrate.
	// Best-effort: a backup must never be skipped because its schema version
	// could not be read.
	m := backup.Manifest{PanelVersion: version.Version}
	if s.hasDB() {
		if v, err := s.db.SchemaVersion(); err == nil {
			m.SchemaVersion = v
		}
	}
	path, err := backup.WriteLocal(master, dataDir, s.now(), m)
	if err != nil {
		// The next hour retries and the backup status endpoint shows the age of
		// the newest one, but the job's own health now carries the reason: a
		// panel whose backups have been failing for a week should not have to be
		// diagnosed from the absence of files.
		return fmt.Errorf("write scheduled backup: %w", err)
	}
	// Off-box delivery, if the operator asked for one. A backup that only exists
	// on the machine it backs up is not a backup of that machine.
	if s.deliverBackup != nil {
		s.deliverBackup(path)
	}
	if _, err := backup.PruneLocal(dataDir, keep); err != nil {
		return fmt.Errorf("prune old backups: %w", err)
	}
	return nil
}

// pruneRollups enforces the usage-history retention windows.
//
// Zero for a resolution keeps it forever, and is treated as "keep" rather than
// as a cutoff of now — read the other way it would erase the history it exists
// to preserve.
func (s *Scheduler) pruneRollups() error {
	if !s.hasDB() {
		return nil
	}
	now := s.now()
	var hourly, daily time.Time
	if s.rollupHourlyRetention > 0 {
		hourly = now.Add(-s.rollupHourlyRetention)
	}
	if s.rollupDailyRetention > 0 {
		daily = now.Add(-s.rollupDailyRetention)
	}
	if hourly.IsZero() && daily.IsZero() {
		return nil
	}
	// Losing a prune costs disk, not correctness, and the next hour retries —
	// but it is reported rather than dropped, so "the database keeps growing"
	// has an answer somewhere other than the filesystem.
	if _, err := s.db.PruneRollups(hourly, daily); err != nil {
		return fmt.Errorf("prune rollups: %w", err)
	}
	return nil
}

// pruneAudit enforces the audit retention window.
//
// The trail had no reader and no bound, so on a busy panel it becomes the
// largest thing in the database and the only sign is disk usage. Pruning is a
// deletion, so a zero or negative window is treated as "keep everything" rather
// than as a cutoff of now — the reading that would erase the entire trail.
func (s *Scheduler) pruneAudit() error {
	if !s.hasDB() || s.auditRetention <= 0 {
		return nil
	}
	cutoff := s.now().Add(-s.auditRetention)
	if _, err := s.db.PruneAuditLogs(cutoff); err != nil {
		// Failing to prune costs disk, not correctness, and the next hour tries
		// again; it is surfaced on the job's health so the growth has a cause.
		return fmt.Errorf("prune audit log: %w", err)
	}
	return nil
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.healthMu.Lock()
	s.running = false
	s.healthMu.Unlock()
}

// Job names as reported by Status. They are stable strings because the health
// endpoint, and an operator reading the report, both key off them.
const (
	JobAccounting  = "accounting"  // traffic poll, quota enforcement
	JobSweep       = "sweep"       // expiry, on-hold activation, periodic reset
	JobRetention   = "retention"   // audit/rollup pruning and scheduled backups
	JobMaintenance = "maintenance" // idle-session eviction, pool re-verification
	JobNotify      = "notify"      // operator notifications (event-driven)
)

// overdueFloor is the smallest window in which a job may be called overdue.
//
// The accounting poll runs every 10s, so a bare "twice the interval" rule would
// declare the scheduler wedged after 20s — well inside the jitter of a loaded
// box or a slow database. An alert that fires under normal load is one that
// operators learn to ignore, which costs more than the check is worth.
const overdueFloor = 30 * time.Second

// jobHealth is the mutable record kept for one scheduled job. All access is
// under Scheduler.healthMu; JobStatus is the immutable copy handed out.
type jobHealth struct {
	interval     time.Duration
	lastStart    time.Time
	lastRun      time.Time // completion, successful or not
	lastSuccess  time.Time
	lastErr      string
	lastDuration time.Duration
	runs         int64
	failures     int64
	panics       int64
	running      bool
}

// JobStatus is one background worker's externally visible health.
type JobStatus struct {
	Name string `json:"name"`
	// IntervalSeconds is the job's cadence. Zero means event-driven (the
	// notifier), which is never treated as overdue for not having fired.
	IntervalSeconds float64 `json:"interval_seconds"`
	// Running reports that the job is inside its function right now. It is what
	// separates "has not been called" from "was called and never returned".
	Running bool `json:"running"`
	// LastStart / LastRun are the start and the COMPLETION of the last run.
	// Both are needed: measured only by completion, a job that has legitimately
	// just begun a long run looks as dead as one whose loop is gone, and
	// measured only by start, a loop that stopped ticking says nothing at all.
	LastStart   time.Time `json:"last_start,omitempty"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	// LastError is the reason the last run failed, cleared by the next success
	// so the report describes the current state rather than an old scar.
	LastError string `json:"last_error,omitempty"`
	// LastDurationMS is the round-trip time of the last completed run — the
	// probe response time for this worker.
	LastDurationMS float64 `json:"last_duration_ms"`
	Runs           int64   `json:"runs"`
	Failures       int64   `json:"failures"`
	Panics         int64   `json:"panics"`
}

// Status is the scheduler's whole self-report, for the panel health indicator.
type Status struct {
	Running   bool        `json:"running"`
	StartedAt time.Time   `json:"started_at,omitempty"`
	Jobs      []JobStatus `json:"jobs"`
}

// OverdueJobs returns the jobs that have missed their cadence badly enough to
// be treated as wedged, in registration order.
//
// Two different failures have to be caught, because they look nothing alike
// from outside:
//
//   - the loop is not ticking at all — the last completion (or, for a job that
//     has never completed, the scheduler's start) is older than the grace;
//   - the job is stuck inside its own function — still marked running, having
//     started longer than the grace ago.
//
// Jobs with no interval are event-driven and are skipped: "has not fired" is
// the normal state for a notifier on a quiet panel.
func (st Status) OverdueJobs(now time.Time) []JobStatus {
	var out []JobStatus
	for _, j := range st.Jobs {
		if j.IntervalSeconds <= 0 {
			continue
		}
		grace := 2 * time.Duration(j.IntervalSeconds*float64(time.Second))
		if grace < overdueFloor {
			grace = overdueFloor
		}
		ref := j.LastRun
		switch {
		case j.Running:
			ref = j.LastStart
		case ref.IsZero():
			// Never completed a cycle: measured from when the scheduler started,
			// so a job that never ran once is reported instead of looking new
			// forever.
			ref = st.StartedAt
		}
		if ref.IsZero() || now.Sub(ref) > grace {
			out = append(out, j)
		}
	}
	return out
}

// Status reports the scheduler's own liveness and every job's last run, error
// and round-trip time. It is safe to call before Start and after Stop.
func (s *Scheduler) Status() Status {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	st := Status{Running: s.running, StartedAt: s.startedAt}
	for _, name := range s.jobOrder {
		j := s.jobs[name]
		st.Jobs = append(st.Jobs, JobStatus{
			Name:            name,
			IntervalSeconds: j.interval.Seconds(),
			Running:         j.running,
			LastStart:       j.lastStart,
			LastRun:         j.lastRun,
			LastSuccess:     j.lastSuccess,
			LastError:       j.lastErr,
			LastDurationMS:  float64(j.lastDuration) / float64(time.Millisecond),
			Runs:            j.runs,
			Failures:        j.failures,
			Panics:          j.panics,
		})
	}
	return st
}

// registerJob makes a job visible in Status before it has ever run.
func (s *Scheduler) registerJob(name string, every time.Duration) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.jobLocked(name).interval = every
}

// jobLocked returns a job's health record, creating it on first use. The caller
// must hold healthMu.
func (s *Scheduler) jobLocked(name string) *jobHealth {
	if s.jobs == nil {
		s.jobs = make(map[string]*jobHealth)
	}
	j, ok := s.jobs[name]
	if !ok {
		j = &jobHealth{}
		s.jobs[name] = j
		s.jobOrder = append(s.jobOrder, name)
	}
	return j
}

// markRunning stamps the start of a run. Without it a job stuck inside its own
// function keeps reporting the completion time of the last good run and looks
// perfectly healthy while enforcing nothing.
func (s *Scheduler) markRunning(name string, start time.Time) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	j := s.jobLocked(name)
	j.lastStart = start
	j.running = true
}

// recordRun stores the outcome of one run. A panic is recorded as a failure
// with its message, because to an operator "it crashed" and "it errored" need
// the same response and the distinction is kept in the panic counter.
func (s *Scheduler) recordRun(name string, start time.Time, err error, panicked string) {
	end := s.now()
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	j := s.jobLocked(name)
	j.running = false
	j.runs++
	j.lastRun = end
	j.lastDuration = end.Sub(start)
	switch {
	case panicked != "":
		j.panics++
		j.failures++
		j.lastErr = "panic: " + panicked
	case err != nil:
		j.failures++
		j.lastErr = err.Error()
	default:
		// Cleared on success so the report reflects the CURRENT state: a job
		// that failed once an hour ago and has worked every cycle since is not
		// broken, and a sticky message would make every transient error look
		// permanent.
		j.lastErr = ""
		j.lastSuccess = end
	}
}

func (s *Scheduler) loop(ctx context.Context, name string, every time.Duration, fn func() error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runJob(name, fn)
		}
	}
}

// runJob executes one scheduled job, contains any panic, and records what
// happened so a wedged or failing job is visible in Status().
func (s *Scheduler) runJob(name string, fn func() error) {
	start := s.now()
	s.markRunning(name, start)
	var err error
	panicked := ""
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = recoveredMessage(name, r)
			}
		}()
		err = fn()
	}()
	s.recordRun(name, start, err, panicked)
}

// recoveredMessage formats and logs a recovered scheduler panic.
//
// What was here before was `if r := recover(); r != nil { }` with a comment and
// no body, so a job that panicked on every single tick was indistinguishable
// from one that was working perfectly. The stack only exists inside the
// deferred call, so it is written to stderr immediately; the message is
// returned as well so the job's own status carries it.
func recoveredMessage(name string, r any) string {
	msg := fmt.Sprint(r)
	log.Printf("forgepanel: scheduler job %q panicked: %s\n%s", name, msg, debug.Stack())
	return msg
}

// pollAndAccount reads the engine's cumulative counters, converts them to
// per-user deltas against the last stored snapshot, and enforces data limits
// within the cycle (spec §11).
//
// It reads WITHOUT resetting. The previous form asked the engine to read and
// zero in one call, which made the in-flight value the only copy: a panel killed
// between the read and the write lost that traffic permanently, and a failed
// SaveUser lost it silently per user. Losing usage always fails the same
// direction — quotas never trip and an exhausted user keeps being served — so
// nothing looks wrong from the outside.
//
// Reading cumulatively makes the cycle idempotent: a re-read after a crash
// returns the same number and the delta is recomputed rather than lost. The
// snapshot advances in the SAME transaction as the usage it accounts for, so a
// crash between the two cannot double-count either.
func (s *Scheduler) pollAndAccount() error {
	if !s.hasDB() || s.pollTraffic == nil {
		// Nothing wired up is not a fault: the light constructor has no engine.
		return nil
	}
	totals, err := s.pollTraffic(false) // cumulative, non-destructive
	if err != nil {
		// An engine whose stats API has stopped answering means quotas are no
		// longer being enforced. This used to return bare, which made a poll
		// that failed every cycle look exactly like an idle panel.
		return fmt.Errorf("poll engine stats: %w", err)
	}
	if len(totals) == 0 {
		return nil
	}
	prevUp, upErr := s.db.TrafficSnapshots(store.UpScope(store.ScopeLocalEngine))
	prevDown, downErr := s.db.TrafficSnapshots(store.DownScope(store.ScopeLocalEngine))
	splitUsable := upErr == nil && downErr == nil

	prev, err := s.db.TrafficSnapshots(store.ScopeLocalEngine)
	if err != nil {
		// Without the baseline every cumulative total would read as a fresh
		// delta and usage would be inflated by the engine's whole lifetime.
		// Skipping the cycle keeps the numbers correct; the next one recovers,
		// because nothing was reset.
		return fmt.Errorf("read traffic snapshot: %w", err)
	}

	changed := false
	applyFailures := 0
	var applyErr error
	now := s.now()
	for email, obs := range totals {
		// The billed quantity is unchanged: the combined counter against the
		// combined baseline, exactly as before. The split is computed alongside
		// and never feeds the total, so an error in it cannot mis-bill anyone.
		total := obs.Total()
		delta := store.TrafficDelta(prev[email], total)
		u := s.userForEmail(email)
		if u == nil {
			// Remember it anyway: an unknown key that later resolves to a user
			// must not hand them the counter's entire history as one delta.
			_ = s.db.SetTrafficSnapshot(store.ScopeLocalEngine, email, total)
			continue
		}
		if delta <= 0 {
			// No usage, but the snapshot still has to track a counter that was
			// reset to a lower value, or the next real delta is measured from a
			// baseline that no longer exists.
			if total != prev[email] {
				_ = s.db.SetTrafficSnapshot(store.ScopeLocalEngine, email, total)
			}
			continue
		}
		// Only a TRANSITION into limited warrants a reload. `limited` alone is
		// true on every subsequent cycle for an already-limited user, which
		// would restart the engines forever.
		tripped := false
		split := store.TrafficSplit{}
		if splitUsable {
			split.Up = store.TrafficDelta(prevUp[email], obs.Up)
			split.Down = store.TrafficDelta(prevDown[email], obs.Down)
			// The half baselines advance whatever happens below. They are
			// bookkeeping for a breakdown, not for billing, so a failure to
			// advance them must never hold up or repeat a charge — and leaving
			// them behind would count the same bytes into the breakdown again on
			// the next cycle.
			_ = s.db.SetTrafficSnapshot(store.UpScope(store.ScopeLocalEngine), email, obs.Up)
			_ = s.db.SetTrafficSnapshot(store.DownScope(store.ScopeLocalEngine), email, obs.Down)
		}
		_, _, err := s.db.ApplyTrafficDeltaAt(store.ScopeLocalEngine, email, u.ID, delta, total, split, now,
			func(user *store.User) {
				// A non-zero delta means the user moved traffic: they are live.
				seen := now
				user.LastSeenAt = &seen
				// An on-hold user's clock starts at FIRST USE, and this is the
				// only place that observation exists. sweep() reads
				// FirstConnectAt to materialise ExpireAt; nothing wrote it, so
				// on-hold users never activated and never expired. Stamped once,
				// or a later cycle would push the expiry further out.
				if user.Status == store.StatusOnHold && user.FirstConnectAt == nil {
					first := now
					user.FirstConnectAt = &first
				}
				if user.DataLimit > 0 && user.UsedTraffic >= user.DataLimit && user.Status == store.StatusActive {
					user.Status = store.StatusLimited
					tripped = true
				}
			})
		if err != nil {
			// The snapshot did not move either, so this delta is recomputed next
			// cycle rather than silently dropped. Counted so that a store that
			// rejects every write shows up as a failing job instead of as usage
			// that simply stops climbing.
			applyFailures++
			applyErr = err
			continue
		}
		if tripped {
			changed = true
			// The moment a quota trips is the one worth telling someone about:
			// the customer is about to notice, and the operator would otherwise
			// find out from them.
			s.alert("traffic-limit", u.Username,
				fmt.Sprintf("*%s* has reached their data limit and is now suspended.", u.Username))
		}
	}
	if changed && s.reloadHook != nil {
		s.reloadHook()
	}
	if applyFailures > 0 {
		return fmt.Errorf("could not account traffic for %d user(s): %w", applyFailures, applyErr)
	}
	return nil
}

// sweep expires users past their expiry, activates on-hold users on first use,
// and resets traffic per strategy.
func (s *Scheduler) sweep() error { return s.sweepAt(s.now()) }

// sweepAt runs the full scheduled user-lifecycle pass at a given instant (split
// out so tests drive it with a controllable clock). For each user it, in order:
//
//  1. transitions an on-hold user whose hold has started (FirstConnectAt set) to
//     active, materializing ExpireAt = FirstConnectAt + OnHoldDuration;
//  2. expires an active user past its ExpireAt;
//  3. applies the periodic data-limit reset (day/week/month/year) exactly once
//     per period via a compare-and-set, catching up after downtime, never
//     double-resetting, and safe across concurrent panel instances.
func (s *Scheduler) sweepAt(now time.Time) error {
	if !s.hasDB() {
		return nil
	}
	users, err := s.db.ListUsers(0)
	if err != nil {
		// A sweep that cannot read the user list enforces nothing at all: no
		// expiry, no on-hold activation, no periodic reset. It returned bare,
		// so the panel looked healthy while doing none of it.
		return fmt.Errorf("list users: %w", err)
	}
	changed := false
	saveFailures := 0
	var saveErr error
	for i := range users {
		u := &users[i]

		// 1. On-hold -> active once the hold has actually started.
		if u.Status == store.StatusOnHold && u.FirstConnectAt != nil {
			if u.OnHoldDuration > 0 && u.ExpireAt == nil {
				exp := u.FirstConnectAt.Add(time.Duration(u.OnHoldDuration) * time.Second)
				u.ExpireAt = &exp
			}
			u.Status = store.StatusActive
			if err := s.db.SaveUser(u); err != nil {
				saveFailures++
				saveErr = err
			}
			changed = true
		}

		// 2. Expiry (an expired user must never be revived by a reset below).
		if u.Status == store.StatusActive && u.ExpireAt != nil && now.After(*u.ExpireAt) {
			u.Status = store.StatusExpired
			if err := s.db.SaveUser(u); err != nil {
				// A user the panel believes is expired but could not persist is
				// still being served, which is the one direction this failure
				// always goes. Reported rather than dropped.
				saveFailures++
				saveErr = err
			}
			changed = true
			s.alert("expiry", u.Username,
				fmt.Sprintf("*%s* has expired and is no longer being served.", u.Username))
			continue
		}

		// 3. Periodic usage reset, idempotent + multi-instance-safe.
		if ps, ok := resetPeriodStart(now, u); ok {
			if applied, _ := s.db.ResetUserUsageCAS(u.ID, ps, now); applied {
				changed = true
				// A new period starts with a clean slate, or the latch that
				// stops duplicate warnings becomes the thing that stops the
				// user ever being warned again.
				s.clearReminders(u.ID)
			}
		}
	}
	// Warn people BEFORE they are cut off. Runs on the same pass because it reads
	// the same rows, and an extra query per sweep to say the same thing would be
	// waste.
	s.checkReminders(now, users)

	// IP-limit enforcement runs on the same sweep so a hold and a release cost
	// ONE engine reload between them, not one per user. It is deliberately after
	// the lifecycle steps: a user who just expired should not also be recorded as
	// having breached an address limit they can no longer reach.
	if s.enforceIPLimits() {
		changed = true
	}
	if changed && s.reloadHook != nil {
		s.reloadHook()
	}
	if saveFailures > 0 {
		return fmt.Errorf("could not persist %d user lifecycle change(s): %w", saveFailures, saveErr)
	}
	return nil
}

// resetPeriodStart returns the compare-and-set marker for a user's reset
// strategy, and whether the strategy resets at all.
//
// "on_expire" needed its own case. The API validator has always ACCEPTED it as a
// legal strategy while periodStart had no branch for it, so it returned
// ok=false and the reset never happened — an operator chose "reset when the
// subscription expires", the panel took the setting, and usage simply never
// reset. There was nothing to see: no error, no log, just a counter that kept
// climbing across renewals.
//
// The expiry date IS the period boundary here, which makes the existing
// compare-and-set machinery fit exactly: it fires once per expiry date, catches
// up after downtime, and cannot double-reset. The reset does not revive the
// account — ResetUserUsageCAS reactivates only a StatusLimited user whose expiry
// has not passed — so an expired user's usage is zeroed while they stay expired,
// and a renewal starts from zero.
func resetPeriodStart(now time.Time, u *store.User) (time.Time, bool) {
	if u.ResetStrategy == store.ResetOnExpire {
		if u.ExpireAt == nil || now.Before(*u.ExpireAt) {
			// No expiry set, or not reached yet. A user with this strategy and no
			// expiry date never resets, which is the honest reading of "reset on
			// expire" rather than a guess at some other cadence.
			return time.Time{}, false
		}
		return u.ExpireAt.UTC(), true
	}
	return periodStart(now, u.ResetStrategy)
}

// periodStart returns the UTC start of the current reset period for a strategy,
// and whether the strategy resets at all. Boundaries: day = 00:00 UTC; week =
// Monday 00:00 UTC (ISO); month = the 1st 00:00 UTC; year = Jan 1 00:00 UTC.
// time.Date normalization makes leap years and month-length differences correct.
func periodStart(now time.Time, st store.ResetStrategy) (time.Time, bool) {
	n := now.UTC()
	y, m, d := n.Date()
	switch st {
	case store.ResetDay:
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC), true
	case store.ResetWeek:
		delta := (int(n.Weekday()) + 6) % 7
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -delta), true
	case store.ResetMonth:
		return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC), true
	case store.ResetYear:
		return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC), true
	default:
		return time.Time{}, false
	}
}

// userForEmail resolves the stats email tag ("u<ID>") back to a user.
func (s *Scheduler) userForEmail(email string) *store.User {
	id := parseUserEmail(email)
	if id == 0 {
		return nil
	}
	u, err := s.db.UserByID(id)
	if err != nil {
		return nil
	}
	return u
}

// PollAndAccountForTest exposes pollAndAccount for internal package testing.
func (s *Scheduler) PollAndAccountForTest() { _ = s.pollAndAccount() }

// SweepAtForTest exposes sweepAt for internal package testing.
func (s *Scheduler) SweepAtForTest(now time.Time) { _ = s.sweepAt(now) }

// RunScheduledBackupForTest exposes runScheduledBackup for cross-package tests
// that need to drive the REAL scheduler the server constructed, rather than one
// the test wired itself. The only other way in is the hourly retention loop, and
// a test cannot wait an hour — which is exactly why the delivery hook could be
// replaced with a destination that is never called and nothing would notice.
func (s *Scheduler) RunScheduledBackupForTest() error { return s.runScheduledBackup() }
