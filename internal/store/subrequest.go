package store

// Subscription-fetch telemetry.
//
// The panel could not answer the first question an operator asks when a customer
// says "the VPN does not work": has this person's client ever actually pulled
// their subscription? handleSub read the User-Agent twice and threw it away both
// times, and no path out of it wrote anything, so "imported the link and it is
// broken" and "never imported the link" looked identical from the panel.

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// SubRequest is one fetch of a subscription URL.
//
// The TOKEN is deliberately not stored: it is a bearer credential, and the
// resolved UserID is the identity. A history table carrying the token would turn
// an operator's reporting view into a credential dump.
//
// It carries its own ID/CreatedAt rather than embedding Base: the record is
// append-only, so there is no UpdatedAt to keep.
type SubRequest struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index:idx_sub_req_user_time,priority:1" json:"user_id"`
	CreatedAt time.Time `gorm:"index:idx_sub_req_user_time,priority:2" json:"created_at"`
	Format    string    `gorm:"size:32" json:"format"`
	UserAgent string    `gorm:"size:512" json:"user_agent"`
	IP        string    `gorm:"size:64" json:"ip"`
}

func (SubRequest) TableName() string { return "sub_requests" }

// subRequestKeepPerUser bounds the table from the WRITE side. /sub/:token is
// unauthenticated, so an unbounded insert here is a database-growth primitive
// anyone on the internet can drive; a scheduled prune would only ever be
// catching up with it.
const subRequestKeepPerUser = 100

// RecordSubRequest appends one fetch and stamps the denormalised pair on the
// user, in a single transaction so the "last fetch" shown next to a user can
// never disagree with the newest row of their history.
func (s *Store) RecordSubRequest(r *SubRequest) error {
	if r == nil || r.UserID == 0 {
		return fmt.Errorf("record sub request: no user")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(r).Error; err != nil {
			return fmt.Errorf("record sub request: %w", err)
		}
		// UpdateColumns, NOT Updates: Updates auto-bumps users.updated_at, which
		// is the optimistic-concurrency token handleUpdateUser sends back as
		// ifUnchanged. A subscription fetch landing while an operator had the
		// edit form open would fail their save with "someone else edited this"
		// when nobody had.
		if err := tx.Model(&User{}).Where("id = ?", r.UserID).UpdateColumns(map[string]any{
			"sub_updated_at": r.CreatedAt,
			"sub_last_ua":    r.UserAgent,
		}).Error; err != nil {
			return fmt.Errorf("stamp last sub fetch: %w", err)
		}
		// Trim in the same transaction, by the id of the Nth-newest row: a
		// portable form that works on SQLite, where DELETE ... LIMIT is not
		// available. Pluck leaves cutoff zero when the user has fewer rows than
		// the cap, which is the common case and costs one indexed lookup.
		var cutoff uint
		if err := tx.Model(&SubRequest{}).Where("user_id = ?", r.UserID).
			Order("created_at desc, id desc").
			Offset(subRequestKeepPerUser-1).Limit(1).
			Pluck("id", &cutoff).Error; err != nil {
			return fmt.Errorf("find sub request cutoff: %w", err)
		}
		if cutoff == 0 {
			return nil
		}
		if err := tx.Where("user_id = ? AND id < ?", r.UserID, cutoff).
			Delete(&SubRequest{}).Error; err != nil {
			return fmt.Errorf("trim sub requests: %w", err)
		}
		return nil
	})
}

// ListSubRequests returns a page of one user's fetches, newest first, plus the
// total so a page means something.
func (s *Store) ListSubRequests(userID uint, limit, offset int) ([]SubRequest, int64, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}
	if offset < 0 {
		offset = 0
	}
	var total int64
	if err := s.db.Model(&SubRequest{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count sub requests: %w", err)
	}
	// id as the tiebreaker: created_at has second resolution in some drivers, and
	// a client that retries twice in one second would otherwise page unstably.
	var items []SubRequest
	if err := s.db.Model(&SubRequest{}).Where("user_id = ?", userID).
		Order("created_at desc, id desc").Limit(limit).Offset(offset).
		Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("read sub requests: %w", err)
	}
	return items, total, nil
}
