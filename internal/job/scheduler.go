// Package job is the panel's cron scheduler (spec §11): it polls engine stats,
// rolls traffic into the store, enforces quotas and expiry within a poll cycle,
// resets traffic by strategy, and sweeps on-hold users. Jobs are plain
// closures on a ticker so the core build needs no scheduler dependency.
package job

import (
	"strings"

	"context"
	"github.com/forgepanel/forgepanel/internal/backup"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
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
	db         *store.Store
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
	reloadHook  func()                                     // called after a mutation to reapply engine configs
	pollTraffic func(reset bool) (map[string]int64, error) // email -> up+down delta bytes
	// activeAddresses reports how many distinct source addresses a user is
	// currently connecting from. Nil disables IP-limit enforcement entirely,
	// which is the honest behaviour when there is no presence source: acting on
	// a count of zero would release every held user.
	activeAddresses func(email string) int
	auditHook       func(action, target string, seen, limit int)
	ipLimits        *ipLimitState
	maintenance     func()

	cancel context.CancelFunc
	wg     sync.WaitGroup
	now    func() time.Time // injectable clock (tests use a controllable one)
}

// Config configures a Scheduler.
type Config struct {
	DB         *store.Store
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
	// PollTraffic returns the engine's per-user counters. The scheduler always
	// calls it with reset=false and accounts by subtraction against a stored
	// snapshot: a destructive read makes the in-flight value the only copy of
	// the data, so a panel killed mid-cycle loses that traffic for good, and
	// usage only ever fails downward — quotas stop tripping and an exhausted
	// user keeps being served, with nothing to show for it.
	// TestTrafficIsNotLostWhenACycleIsInterrupted fails if this is ever called
	// with reset=true.
	PollTraffic func(reset bool) (map[string]int64, error)
	// ActiveAddresses reports a user's current distinct source-address count.
	// Nil disables IP-limit enforcement rather than enforcing against zero.
	ActiveAddresses func(email string) int
	// AuditIPLimit records enforcement actions so an account that stops working
	// has a findable reason.
	AuditIPLimit func(action, target string, seen, limit int)
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
		activeAddresses:       cfg.ActiveAddresses,
		auditHook:             cfg.AuditIPLimit,
		ipLimits:              newIPLimitState(),
		maintenance:           cfg.Maintenance,
		now:                   time.Now,
	}
}

// Start launches the scheduler goroutines until Stop is called.
func (s *Scheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(3)
	go func() {
		defer s.wg.Done()
		s.loop(ctx, s.pollEvery, s.pollAndAccount)
	}()
	go func() {
		defer s.wg.Done()
		s.loop(ctx, s.sweepEvery, s.sweep)
	}()
	go func() {
		defer s.wg.Done()
		// Hourly is often enough: retention is measured in days, and a tighter
		// cadence would delete a handful of rows over and over for no benefit.
		s.loop(ctx, time.Hour, func() {
			s.pruneAudit()
			s.pruneRollups()
			s.runScheduledBackup()
		})
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Housekeeping, on its own loop rather than folded into the hourly one:
		// idle sessions have to be evicted on a much tighter cadence than
		// retention pruning, and an hour of leaked sessions on a busy tunnel is
		// real memory.
		s.loop(ctx, s.sweepEvery, s.runMaintenance)
	}()
}

// runMaintenance calls the maintenance hook, containing any panic.
//
// It runs on a long-lived goroutine that also has no other job. A panic here
// would silently stop every future maintenance run, and the resulting leak would
// show up hours later as memory growth with nothing pointing at the cause.
func (s *Scheduler) runMaintenance() {
	if s.maintenance == nil {
		return
	}
	defer func() { _ = recover() }()
	s.maintenance()
}

// runScheduledBackup takes a backup when one is due.
//
// Due-ness is judged from the newest backup on disk rather than from a timer
// held in memory, so a panel that restarts every hour still produces daily
// backups instead of one per restart — and a panel that was down for a week
// takes one immediately when it returns.
func (s *Scheduler) runScheduledBackup() {
	if s.backupEvery == nil {
		return
	}
	dataDir, master, every, keep := s.backupEvery()
	if every <= 0 || strings.TrimSpace(master) == "" || dataDir == "" {
		return
	}
	last, _, err := backup.LatestLocal(dataDir)
	if err == nil && !last.IsZero() && s.now().Sub(last) < every {
		return
	}
	if _, err := backup.WriteLocal(master, dataDir, s.now()); err != nil {
		// Nothing to escalate to from here; the next hour retries, and the
		// backup status endpoint shows the age of the newest one.
		return
	}
	_, _ = backup.PruneLocal(dataDir, keep)
}

// pruneRollups enforces the usage-history retention windows.
//
// Zero for a resolution keeps it forever, and is treated as "keep" rather than
// as a cutoff of now — read the other way it would erase the history it exists
// to preserve.
func (s *Scheduler) pruneRollups() {
	if s.db == nil {
		return
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
		return
	}
	// Losing a prune costs disk, not correctness, and the next hour retries.
	_, _ = s.db.PruneRollups(hourly, daily)
}

// pruneAudit enforces the audit retention window.
//
// The trail had no reader and no bound, so on a busy panel it becomes the
// largest thing in the database and the only sign is disk usage. Pruning is a
// deletion, so a zero or negative window is treated as "keep everything" rather
// than as a cutoff of now — the reading that would erase the entire trail.
func (s *Scheduler) pruneAudit() {
	if s.db == nil || s.auditRetention <= 0 {
		return
	}
	cutoff := s.now().Add(-s.auditRetention)
	if _, err := s.db.PruneAuditLogs(cutoff); err != nil {
		// Nothing to escalate to: failing to prune costs disk, not correctness,
		// and the next hour tries again.
		return
	}
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						// recover gracefully from scheduler job panic
					}
				}()
				fn()
			}()
		}
	}
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
func (s *Scheduler) pollAndAccount() {
	if s.db == nil || s.pollTraffic == nil {
		return
	}
	totals, err := s.pollTraffic(false) // cumulative, non-destructive
	if err != nil || len(totals) == 0 {
		return
	}
	prev, err := s.db.TrafficSnapshots(store.ScopeLocalEngine)
	if err != nil {
		// Without the baseline every cumulative total would read as a fresh
		// delta and usage would be inflated by the engine's whole lifetime.
		// Skipping the cycle keeps the numbers correct; the next one recovers,
		// because nothing was reset.
		return
	}

	changed := false
	now := s.now()
	for email, total := range totals {
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
		_, _, err := s.db.ApplyTrafficDelta(store.ScopeLocalEngine, email, u.ID, delta, total,
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
			// cycle rather than silently dropped.
			continue
		}
		if tripped {
			changed = true
		}
	}
	if changed && s.reloadHook != nil {
		s.reloadHook()
	}
}

// sweep expires users past their expiry, activates on-hold users on first use,
// and resets traffic per strategy.
func (s *Scheduler) sweep() { s.sweepAt(s.now()) }

// sweepAt runs the full scheduled user-lifecycle pass at a given instant (split
// out so tests drive it with a controllable clock). For each user it, in order:
//
//  1. transitions an on-hold user whose hold has started (FirstConnectAt set) to
//     active, materializing ExpireAt = FirstConnectAt + OnHoldDuration;
//  2. expires an active user past its ExpireAt;
//  3. applies the periodic data-limit reset (day/week/month/year) exactly once
//     per period via a compare-and-set, catching up after downtime, never
//     double-resetting, and safe across concurrent panel instances.
func (s *Scheduler) sweepAt(now time.Time) {
	if s.db == nil {
		return
	}
	users, err := s.db.ListUsers(0)
	if err != nil {
		return
	}
	changed := false
	for i := range users {
		u := &users[i]

		// 1. On-hold -> active once the hold has actually started.
		if u.Status == store.StatusOnHold && u.FirstConnectAt != nil {
			if u.OnHoldDuration > 0 && u.ExpireAt == nil {
				exp := u.FirstConnectAt.Add(time.Duration(u.OnHoldDuration) * time.Second)
				u.ExpireAt = &exp
			}
			u.Status = store.StatusActive
			_ = s.db.SaveUser(u)
			changed = true
		}

		// 2. Expiry (an expired user must never be revived by a reset below).
		if u.Status == store.StatusActive && u.ExpireAt != nil && now.After(*u.ExpireAt) {
			u.Status = store.StatusExpired
			_ = s.db.SaveUser(u)
			changed = true
			continue
		}

		// 3. Periodic usage reset, idempotent + multi-instance-safe.
		if ps, ok := periodStart(now, u.ResetStrategy); ok {
			if applied, _ := s.db.ResetUserUsageCAS(u.ID, ps, now); applied {
				changed = true
			}
		}
	}
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
func (s *Scheduler) PollAndAccountForTest() { s.pollAndAccount() }

// SweepAtForTest exposes sweepAt for internal package testing.
func (s *Scheduler) SweepAtForTest(now time.Time) { s.sweepAt(now) }
