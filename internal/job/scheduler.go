// Package job is the panel's cron scheduler (spec §11): it polls engine stats,
// rolls traffic into the store, enforces quotas and expiry within a poll cycle,
// resets traffic by strategy, and sweeps on-hold users. Jobs are plain
// closures on a ticker so the core build needs no scheduler dependency.
package job

import (
	"context"
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
	now         func() time.Time // injectable clock (tests use a controllable one)
}

// Config configures a Scheduler.
type Config struct {
	DB          *store.Store
	PollEvery   time.Duration
	SweepEvery  time.Duration
	ReloadHook  func()
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
	go s.loop(ctx, s.pollEvery, s.pollAndAccount)
	go s.loop(ctx, s.sweepEvery, s.sweep)
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Scheduler) loop(ctx context.Context, every time.Duration, fn func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// pollAndAccount reads traffic deltas, adds them to each user's UsedTraffic, and
// enforces data limits within the cycle (spec §11).
func (s *Scheduler) pollAndAccount() {
	if s.db == nil || s.pollTraffic == nil {
		return
	}
	deltas, err := s.pollTraffic(true) // reset counters => value is the delta
	if err != nil || len(deltas) == 0 {
		return
	}
	changed := false
	for email, bytes := range deltas {
		if bytes <= 0 {
			continue
		}
		u := s.userForEmail(email)
		if u == nil {
			continue
		}
		u.UsedTraffic += bytes
		if u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit && u.Status == store.StatusActive {
			u.Status = store.StatusLimited
			changed = true
		}
		_ = s.db.SaveUser(u)
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
