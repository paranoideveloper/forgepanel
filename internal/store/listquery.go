package store

// Pagination, search and sorting for the list endpoints.
//
// Every list query was an unbounded Find: ListUsers, ListInbounds, ListNodes and
// ListGroups all loaded the whole table on every call, and the panel calls them
// on every page view. A deployment with a few thousand users pays that on each
// render, and there is no way to ask for less — the cost grows with the
// customer base, which is exactly the wrong direction.
//
// SORTING IS AN INJECTION SURFACE. A column name cannot be parameterised, so a
// sort field taken from a query string and interpolated into ORDER BY is a SQL
// injection. Each entity therefore declares an ALLOWLIST, and anything not on it
// falls back to the default rather than being passed through — refusing is not
// enough on its own, because a caller that ignores the error still gets a query.

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

const (
	// DefaultListLimit applies when a caller asks for a page without a size.
	DefaultListLimit = 50
	// MaxListLimit caps one request. Without a ceiling a single call can load
	// the table into memory, which is the problem pagination exists to solve.
	MaxListLimit = 500
)

// ListQuery is one page of a list, optionally narrowed and reordered.
//
// A zero Limit means "no paging" and returns everything, which is what every
// existing caller expects: adding a default page size here would silently
// truncate the lists the panel already renders.
type ListQuery struct {
	Search string
	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// Paged reports whether the caller actually asked for a page.
func (q ListQuery) Paged() bool { return q.Limit > 0 || q.Offset > 0 }

// normalize clamps a page request into the supported range.
func (q ListQuery) normalize() ListQuery {
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.Offset > 0 && q.Limit <= 0 {
		q.Limit = DefaultListLimit
	}
	if q.Limit > MaxListLimit {
		q.Limit = MaxListLimit
	}
	return q
}

// orderBy resolves a requested sort against an allowlist.
//
// Returns the default when the request names a column the entity does not
// expose. That is deliberate: the alternative is either interpolating an
// unvalidated identifier (an injection) or erroring on a cosmetic preference
// (a list that will not load because a saved sort refers to a renamed column).
func orderBy(requested string, desc bool, allowed map[string]string, def string) string {
	col, ok := allowed[strings.TrimSpace(strings.ToLower(requested))]
	if !ok {
		return def
	}
	if desc {
		return col + " desc"
	}
	return col + " asc"
}

// applyPage adds LIMIT/OFFSET when a page was requested.
func applyPage(db *gorm.DB, q ListQuery) *gorm.DB {
	if q.Limit > 0 {
		db = db.Limit(q.Limit)
	}
	if q.Offset > 0 {
		db = db.Offset(q.Offset)
	}
	return db
}

// likeEscape neutralises LIKE wildcards in a user-supplied search term.
//
// Without it, a search for "%" matches every row and a search for "_" matches
// far more than the operator typed — the results look plausible and are wrong,
// which is worse than an error.
func likeEscape(s string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(s)
}

// userSortColumns is the allowlist for the users list.
var userSortColumns = map[string]string{
	"id": "id", "username": "username", "status": "status",
	"used_traffic": "used_traffic", "data_limit": "data_limit",
	"expire_at": "expire_at", "created_at": "created_at", "last_seen_at": "last_seen_at",
}

// ListUsersPage returns one page of users plus the total matching the filter.
//
// ownerID scopes to a reseller's own customers, exactly as ListUsers does; the
// scoping is applied before paging so a reseller's page numbers describe their
// own customers and not their offset within everyone's.
func (s *Store) ListUsersPage(ownerID uint, q ListQuery) ([]User, int64, error) {
	q = q.normalize()
	base := s.db.Model(&User{})
	if ownerID != 0 {
		base = base.Where("owner_admin_id = ?", ownerID)
	}
	if term := strings.TrimSpace(q.Search); term != "" {
		base = base.Where("username LIKE ? ESCAPE '\\'", "%"+likeEscape(term)+"%")
	}

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}
	var out []User
	err := applyPage(base.Order(orderBy(q.Sort, q.Desc, userSortColumns, "id asc")), q).Find(&out).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	return out, total, nil
}

var inboundSortColumns = map[string]string{
	"id": "id", "remark": "remark", "port": "port", "enabled": "enabled",
	"created_at": "created_at", "node_id": "node_id",
}

// ListInboundsPage returns one page of inbounds plus the total.
func (s *Store) ListInboundsPage(q ListQuery) ([]Inbound, int64, error) {
	q = q.normalize()
	base := s.db.Model(&Inbound{})
	if term := strings.TrimSpace(q.Search); term != "" {
		base = base.Where("remark LIKE ? ESCAPE '\\'", "%"+likeEscape(term)+"%")
	}
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count inbounds: %w", err)
	}
	var out []Inbound
	err := applyPage(base.Order(orderBy(q.Sort, q.Desc, inboundSortColumns, "id asc")), q).Find(&out).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list inbounds: %w", err)
	}
	return out, total, nil
}

var nodeSortColumns = map[string]string{
	"id": "id", "name": "name", "address": "address", "healthy": "healthy",
	"last_seen": "last_seen", "created_at": "created_at",
}

// ListNodesPage returns one page of nodes plus the total.
func (s *Store) ListNodesPage(q ListQuery) ([]Node, int64, error) {
	q = q.normalize()
	base := s.db.Model(&Node{})
	if term := strings.TrimSpace(q.Search); term != "" {
		base = base.Where("name LIKE ? ESCAPE '\\' OR address LIKE ? ESCAPE '\\'",
			"%"+likeEscape(term)+"%", "%"+likeEscape(term)+"%")
	}
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count nodes: %w", err)
	}
	var out []Node
	err := applyPage(base.Order(orderBy(q.Sort, q.Desc, nodeSortColumns, "id asc")), q).Find(&out).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list nodes: %w", err)
	}
	return out, total, nil
}
