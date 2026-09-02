package job

// Warning people BEFORE they are cut off.
//
// The panel told an operator when a quota had already tripped and an account had
// already expired — both of which the customer discovers at the same moment, by
// their connection failing. Nobody was told at 80% used or three days out, when
// there is still time to top up or renew and nothing has broken yet.
//
// THRESHOLDS, NOT PERCENTAGES, AND THEY LATCH. A reminder that re-fires while a
// user sits at 81% would send a message every sweep; one that re-fires because
// usage briefly dipped would send the same warning twice. Each threshold is
// crossed at most once per period, and the crossing is what is remembered — not
// the value.

import (
	"fmt"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// usageThresholds are the fractions of a data limit worth a warning.
//
// Two, not five. A reminder at every tenth is noise that gets filtered, and the
// filter takes the useful ones with it. 80% is "start thinking about it"; 95% is
// "this is about to stop working".
var usageThresholds = []int{80, 95}

// expiryThresholds are the days-remaining marks worth a warning, SMALLEST FIRST.
//
// The order matters and getting it wrong is silent. Scanning largest-first picks
// the widest mark the user is under — at two days left that is "7 days", so the
// latch records 7, and the genuinely urgent 3-day and 1-day warnings can never
// fire afterwards. Smallest-first picks the closest mark not yet passed, which
// is the one worth saying.
var expiryThresholds = []int{1, 3, 7}

// reminderState remembers which thresholds have already been announced.
//
// In memory: a restart legitimately re-warns rather than staying silent about a
// user who is still at 95%, and persisting it would mean a schema for something
// whose worst failure is one duplicate message.
type reminderState struct {
	// sent maps "<kind>:<user>:<threshold>" to when it fired, so a reset can
	// clear a user's marks without walking every key.
	sent map[string]time.Time
}

func newReminderState() *reminderState {
	return &reminderState{sent: map[string]time.Time{}}
}

func reminderKey(kind string, userID uint, threshold int) string {
	return fmt.Sprintf("%s:%d:%d", kind, userID, threshold)
}

// checkReminders warns users approaching a limit or an expiry.
func (s *Scheduler) checkReminders(now time.Time, users []store.User) {
	if s.notify == nil {
		return
	}
	for i := range users {
		u := &users[i]
		if u.Status != store.StatusActive {
			// A suspended or expired account has already had the thing happen.
			// Warning them that it is about to would be absurd.
			continue
		}
		s.checkUsageReminder(u)
		s.checkExpiryReminder(now, u)
	}
}

func (s *Scheduler) checkUsageReminder(u *store.User) {
	if u.DataLimit <= 0 || u.UsedTraffic <= 0 {
		// No limit means nothing to approach.
		return
	}
	pct := int(u.UsedTraffic * 100 / u.DataLimit)

	// Highest threshold first: a user who jumps from 70% to 96% in one poll
	// should be told they are nearly out, not that they have passed 80%.
	for i := len(usageThresholds) - 1; i >= 0; i-- {
		th := usageThresholds[i]
		if pct < th {
			continue
		}
		key := reminderKey("usage", u.ID, th)
		if _, already := s.reminders.sent[key]; already {
			return
		}
		s.reminders.sent[key] = s.now()
		s.alert("usage-reminder", u.Username, fmt.Sprintf(
			"*%s* has used %d%% of their data (%s of %s).",
			u.Username, pct, humanBytes(u.UsedTraffic), humanBytes(u.DataLimit)))
		return
	}
}

func (s *Scheduler) checkExpiryReminder(now time.Time, u *store.User) {
	if u.ExpireAt == nil {
		return
	}
	left := u.ExpireAt.Sub(now)
	if left <= 0 {
		// Already expired; the sweep announces that separately and this would be
		// a second message about the same event.
		return
	}
	days := int(left.Hours() / 24)

	// The closest mark the user is under: at two days left that is 3, not 7.
	for _, th := range expiryThresholds {
		if days >= th {
			continue
		}
		key := reminderKey("expiry", u.ID, th)
		if _, already := s.reminders.sent[key]; already {
			return
		}
		s.reminders.sent[key] = s.now()
		s.alert("expiry-reminder", u.Username, fmt.Sprintf(
			"*%s* expires in %s.", u.Username, humanDuration(left)))
		return
	}
}

// clearReminders forgets a user's marks, so a renewal or a quota reset can warn
// again next period.
//
// Without this a user who tops up, uses another 80% and approaches the limit a
// second time is never warned again — the latch that stops duplicates becomes
// the thing that stops the feature working.
func (s *Scheduler) clearReminders(userID uint) {
	for _, th := range usageThresholds {
		delete(s.reminders.sent, reminderKey("usage", userID, th))
	}
	for _, th := range expiryThresholds {
		delete(s.reminders.sent, reminderKey("expiry", userID, th))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %sB", float64(n)/float64(div), []string{"K", "M", "G", "T", "P"}[exp])
}

func humanDuration(d time.Duration) string {
	if days := int(d.Hours() / 24); days >= 1 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if h := int(d.Hours()); h >= 1 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	return "less than an hour"
}
