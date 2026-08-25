// Package job is the panel's cron scheduler (spec §11): it polls engine stats,
// rolls traffic into the store, enforces quotas and expiry within a poll cycle,
// resets traffic by strategy, and sweeps on-hold users. Jobs are plain
// closures on a ticker so the core build needs no scheduler dependency.
package job

import (
	"context"
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
	db          *store.Store
	pollEvery   time.Duration
	sweepEvery  time.Duration
	reloadHook  func()                                     // called after a mutation to reapply engine configs
	pollTraffic func(reset bool) (map[string]int64, error) // email -> up+down delta bytes
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	now         func() time.Time // injectable clock (tests use a controllable one)
}

// Config configures a Scheduler.
type Config struct {
	DB         *store.Store
	PollEvery  time.Duration
	SweepEvery time.Duration
	ReloadHook func()
	// PollTraffic returns the engine's per-user counters. The scheduler always
	// calls it with reset=false and accounts by subtraction against a stored
	// snapshot: a destructive read makes the in-flight value the only copy of
	// the data, so a panel killed mid-cycle loses that traffic for good, and
	// usage only ever fails downward — quotas stop tripping and an exhausted
	// user keeps being served, with nothing to show for it.
	// TestTrafficIsNotLostWhenACycleIsInterrupted fails if this is ever called
	// with reset=true.
	PollTraffic func(reset bool) (map[string]int64, error)
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
		now: time.Now,
	}
}

// Start launches the scheduler goroutines until Stop is called.
func (s *Scheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.loop(ctx, s.pollEvery, s.pollAndAccount)
	}()
	go func() {
		defer s.wg.Done()
		s.loop(ctx, s.sweepEvery, s.sweep)
	}()
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
