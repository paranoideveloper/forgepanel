package job

import (
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// releaseDisconnects clears the hold on users an administrator disconnected
// once it has run out, so the next engine reload puts their credential back.
// It returns true when anything changed, so the sweep reloads once for all.
func (s *Scheduler) releaseDisconnects(users []store.User, now time.Time) bool {
	changed := false
	for i := range users {
		u := &users[i]
		if u.DisconnectedUntil == nil || u.DisconnectedUntil.After(now) {
			continue
		}
		if err := s.db.UpdateUserFields(u.ID, map[string]any{"disconnected_until": nil}, time.Time{}); err == nil {
			changed = true
		}
	}
	return changed
}
