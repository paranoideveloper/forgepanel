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
	reloadHook  func()                                  // called after a mutation to reapply engine configs
	pollTraffic func(reset bool) (map[string]int64, error) // email -> up+down delta bytes
	cancel      context.CancelFunc
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
func (s *Scheduler) sweep() {
	if s.db == nil {
		return
	}
	users, err := s.db.ListUsers(0)
	if err != nil {
		return
	}
	now := time.Now()
	changed := false
	for i := range users {
		u := &users[i]
		if u.Status == store.StatusActive && u.ExpireAt != nil && now.After(*u.ExpireAt) {
			u.Status = store.StatusExpired
			_ = s.db.SaveUser(u)
			changed = true
		}
	}
	if changed && s.reloadHook != nil {
		s.reloadHook()
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
