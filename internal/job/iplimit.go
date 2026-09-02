package job

// Per-user concurrent-address limiting, actually enforced.
//
// store.User.IPLimit has been stored and editable since the day it was added and
// NOTHING read it. An operator capped an account at two devices, the panel
// accepted the number, and the account stayed unlimited. That is worse than not
// offering the field at all: the operator believes the limit is in force and
// stops watching.
//
// WHAT A "CONCURRENT ADDRESS" IS HERE. The count comes from the presence
// tracker, which is fed by the cores' access logs. An address counts while it
// has opened a connection within the tracker's window (two minutes). That is the
// honest definition and it has to be stated, because it is NOT "sockets
// currently open": a client holding one long-lived connection and opening no new
// ones eventually stops being counted.
//
// RECONNECTION TOLERANCE. A phone moving from wi-fi to cellular is briefly at
// two addresses through no fault of its own, and a limit of one would lock it
// out every time it walked out of the house. So a breach must persist across
// consecutive sweeps before anything happens. A genuinely shared account stays
// over the limit; a roaming device does not.
//
// WHAT ENFORCEMENT DOES. The user is excluded from every generated core config
// until a cooldown passes. Since the core learns this through the hot-apply
// path, enforcement no longer costs every other user their connection — which
// is precisely why this was not worth building before that existed.

import (
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

const (
	// ipLimitCooldown is how long an over-limit user is held out of the config.
	//
	// Long enough to be a real consequence and to let the tracker's window drain
	// so the next measurement starts clean; short enough that an operator is not
	// fielding a support call about it. If they are still over the limit when it
	// lifts, they are held again — which is the enforcement working, not a bug.
	ipLimitCooldown = 5 * time.Minute

	// ipLimitBreachesBeforeAction is how many CONSECUTIVE sweeps must see a user
	// over their limit.
	//
	// Two, not one. One sweep cannot tell a shared account from a phone that
	// changed network thirty seconds ago, and locking out the second is a worse
	// failure than briefly tolerating the first.
	ipLimitBreachesBeforeAction = 2
)

// ipLimitState is the per-user breach counter, held in memory.
//
// In memory deliberately: it is a couple of sweeps' worth of hysteresis, and a
// panel restart legitimately starts the observation over rather than acting on
// evidence it can no longer see.
type ipLimitState struct {
	breaches map[uint]int
}

func newIPLimitState() *ipLimitState {
	return &ipLimitState{breaches: map[uint]int{}}
}

// enforceIPLimits holds users who are consistently over their address limit, and
// releases those whose cooldown has passed.
//
// It returns true when anything changed, so the caller reloads the engines once
// for the whole sweep rather than once per user.
func (s *Scheduler) enforceIPLimits() bool {
	if !s.hasDB() || s.activeAddresses == nil {
		// No presence source: the limit cannot be measured. Doing nothing is
		// correct — acting on a count of zero would release every held user, and
		// acting on a missing count would hold every limited one.
		return false
	}

	users, err := s.db.ListUsers(0)
	if err != nil {
		// Enforcement must not act on a partial view. Holding or releasing users
		// based on a failed read is worse than skipping one sweep.
		return false
	}

	now := s.now()
	changed := false

	for i := range users {
		u := &users[i]

		// Release first, and independently of the limit still being set: an
		// operator who removes a user's limit while they are held must not
		// leave them held forever.
		if u.IPLimitedUntil != nil && !u.IPLimitedUntil.After(now) {
			if err := s.db.UpdateUserFields(u.ID, map[string]any{"ip_limited_until": nil}, time.Time{}); err == nil {
				delete(s.ipLimits.breaches, u.ID)
				changed = true
				s.auditIPLimit(u, "user.ip_limit.released", 0)
			}
			continue
		}
		if u.IPLimit <= 0 {
			if u.IPLimitedUntil != nil {
				// The limit was removed while the user was held. Release them
				// now rather than making them wait out a rule that no longer
				// exists.
				if err := s.db.UpdateUserFields(u.ID, map[string]any{"ip_limited_until": nil}, time.Time{}); err == nil {
					changed = true
					s.auditIPLimit(u, "user.ip_limit.released", 0)
				}
			}
			delete(s.ipLimits.breaches, u.ID)
			continue
		}
		if u.IPLimitedUntil != nil {
			// Already held and the cooldown has not passed. Their addresses are
			// not being counted meaningfully — they cannot connect — so there is
			// nothing to measure.
			continue
		}

		n := s.activeAddresses(UserEmail(u.ID))
		if n <= u.IPLimit {
			// Any sweep within the limit resets the counter. Breaches have to be
			// CONSECUTIVE, or a device that changes network once an hour would
			// accumulate its way to a lockout over a day.
			delete(s.ipLimits.breaches, u.ID)
			continue
		}

		s.ipLimits.breaches[u.ID]++
		if s.ipLimits.breaches[u.ID] < ipLimitBreachesBeforeAction {
			continue
		}

		until := now.Add(ipLimitCooldown)
		if err := s.db.UpdateUserFields(u.ID, map[string]any{"ip_limited_until": until}, time.Time{}); err != nil {
			continue
		}
		delete(s.ipLimits.breaches, u.ID)
		changed = true
		s.auditIPLimit(u, "user.ip_limit.enforced", n)
	}

	return changed
}

// auditIPLimit records an enforcement action.
//
// An account that stops working needs a reason an operator can find. Without
// this the user reports an outage, the panel shows them active, and nothing
// anywhere says the panel did it deliberately.
func (s *Scheduler) auditIPLimit(u *store.User, action string, seen int) {
	if s.auditHook == nil {
		return
	}
	s.auditHook(action, u.Username, seen, u.IPLimit)
}
