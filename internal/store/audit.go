package store

// Reading the audit trail.
//
// Audit() wrote rows from the day it was added and nothing ever read them: no
// store method, no route, no view. An audit log that cannot be read is not an
// audit log — it is a table that grows forever. The one consumer that looked
// like a reader (SystemHealthView) fetched /admin/stats, which returns counts,
// typed as AuditLog[], so it iterated nothing.
//
// Retention matters for the same reason nobody noticed: the table had no bound
// and no reader, so on a busy panel it is the largest thing in the database and
// the only evidence of that is disk usage.

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AuditFilter narrows a query. The zero value means "everything, newest first",
// capped by DefaultAuditLimit.
type AuditFilter struct {
	// Actor and Action match exactly when set. Exact, not prefix: an operator
	// filtering for "login" wants logins, not "login.failed" as well, and the
	// action vocabulary is dotted so a prefix match would silently widen.
	Actor  string
	Action string
	// ActionPrefix matches a family ("2fa." covers every 2FA event). Separate
	// from Action so the caller chooses which it meant.
	ActionPrefix string
	// AdminID scopes to one account.
	AdminID uint
	// Since and Until bound the window, inclusive of Since and exclusive of
	// Until, so consecutive pages of a time range cannot double-count an entry.
	Since time.Time
	Until time.Time
	// Limit and Offset paginate. A zero Limit uses DefaultAuditLimit rather than
	// returning everything: the caller that forgets is the one whose panel has a
	// million rows.
	Limit  int
	Offset int
}

const (
	// DefaultAuditLimit is the page size when a caller does not choose.
	DefaultAuditLimit = 100
	// MaxAuditLimit caps what one request can pull. Without a ceiling a single
	// call can load the whole table into memory and take the panel down.
	MaxAuditLimit = 1000
)

func (f AuditFilter) apply(q *gorm.DB) *gorm.DB {
	if a := strings.TrimSpace(f.Actor); a != "" {
		q = q.Where("actor = ?", a)
	}
	if a := strings.TrimSpace(f.Action); a != "" {
		q = q.Where("action = ?", a)
	}
	if p := strings.TrimSpace(f.ActionPrefix); p != "" {
		// Escape the LIKE wildcards so an action containing % or _ cannot widen
		// the match to rows the operator did not ask for.
		esc := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(p)
		q = q.Where("action LIKE ? ESCAPE '\\'", esc+"%")
	}
	if f.AdminID != 0 {
		q = q.Where("admin_id = ?", f.AdminID)
	}
	if !f.Since.IsZero() {
		q = q.Where("created_at >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		q = q.Where("created_at < ?", f.Until)
	}
	return q
}

// ListAuditLogs returns a page of entries newest-first, plus the total number
// matching the filter.
//
// The total is what makes the page meaningful: "50 shown" tells an operator
// nothing about whether they are looking at the whole story.
func (s *Store) ListAuditLogs(f AuditFilter) (entries []AuditLog, total int64, err error) {
	if f.Limit <= 0 {
		f.Limit = DefaultAuditLimit
	}
	if f.Limit > MaxAuditLimit {
		f.Limit = MaxAuditLimit
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	if err := f.apply(s.db.Model(&AuditLog{})).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit entries: %w", err)
	}
	// id as the tiebreaker: created_at has second resolution in some drivers, and
	// entries written in the same second would otherwise page unstably — an
	// operator would see one entry twice and miss another.
	q := f.apply(s.db.Model(&AuditLog{})).Order("created_at desc, id desc").
		Limit(f.Limit).Offset(f.Offset)
	if err := q.Find(&entries).Error; err != nil {
		return nil, 0, fmt.Errorf("read audit entries: %w", err)
	}
	return entries, total, nil
}

// AuditActions returns the distinct actions present, for a filter control.
//
// Built from the data rather than a hardcoded list: the vocabulary grows
// whenever a handler adds an audit call, and a stale dropdown that omits the
// event an operator is hunting is worse than no dropdown.
func (s *Store) AuditActions() ([]string, error) {
	var out []string
	err := s.db.Model(&AuditLog{}).Distinct().Order("action asc").Pluck("action", &out).Error
	if err != nil {
		return nil, fmt.Errorf("list audit actions: %w", err)
	}
	return out, nil
}

// PruneAuditLogs deletes entries older than the cutoff and reports how many went.
//
// Retention is a deletion, so it refuses a zero cutoff rather than treating it
// as "the beginning of time" and erasing the whole trail.
func (s *Store) PruneAuditLogs(before time.Time) (int64, error) {
	if before.IsZero() {
		return 0, fmt.Errorf("prune audit: refusing a zero cutoff, which would delete every entry")
	}
	res := s.db.Where("created_at < ?", before).Delete(&AuditLog{})
	if res.Error != nil {
		return 0, fmt.Errorf("prune audit entries: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// CountAuditLogs is the cheap form of ListAuditLogs for a status card.
func (s *Store) CountAuditLogs() (int64, error) {
	var n int64
	if err := s.db.Model(&AuditLog{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("count audit entries: %w", err)
	}
	return n, nil
}
