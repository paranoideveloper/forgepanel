package store

import (
	"testing"
	"time"
)

// Audit() wrote rows from the day it landed and nothing ever read them. These
// cover the read path, and the two properties that make it usable: a stable
// page order, and a prune that cannot erase the whole trail by accident.

func auditStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func seedAudit(t *testing.T, s *Store, n int, actor, action string, when time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		e := &AuditLog{Actor: actor, Action: action, IP: "10.0.0.1", Target: "t"}
		if err := s.db.Create(e).Error; err != nil {
			t.Fatal(err)
		}
		if !when.IsZero() {
			if err := s.db.Model(&AuditLog{}).Where("id = ?", e.ID).
				Update("created_at", when).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestListReturnsNewestFirstWithATotal(t *testing.T) {
	s := auditStore(t)
	seedAudit(t, s, 5, "alice", "login", time.Time{})

	got, total, err := s.ListAuditLogs(AuditFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("total is %d, want 5 — a page without a total says nothing about the whole", total)
	}
	if len(got) != 2 {
		t.Fatalf("page holds %d, want 2", len(got))
	}
	// Newest first.
	if got[0].ID < got[1].ID {
		t.Errorf("entries are not newest-first: %d before %d", got[0].ID, got[1].ID)
	}
}

// created_at has second resolution in some drivers, so entries written in the
// same second would page unstably without the id tiebreaker: an operator would
// see one entry twice and miss another.
func TestPagingIsStableWithinOneSecond(t *testing.T) {
	s := auditStore(t)
	now := time.Now().Truncate(time.Second)
	seedAudit(t, s, 10, "bob", "user.update", now)

	seen := map[uint]bool{}
	for off := 0; off < 10; off += 3 {
		page, _, err := s.ListAuditLogs(AuditFilter{Limit: 3, Offset: off})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("entry %d appeared on two pages; paging is unstable", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 10 {
		t.Fatalf("saw %d distinct entries across the pages, want 10", len(seen))
	}
}

func TestFiltersNarrowExactly(t *testing.T) {
	s := auditStore(t)
	seedAudit(t, s, 3, "alice", "login", time.Time{})
	seedAudit(t, s, 2, "bob", "login.failed", time.Time{})
	seedAudit(t, s, 4, "alice", "2fa.enable", time.Time{})

	// Exact, not prefix: filtering for "login" must not also return
	// "login.failed", or a count means something other than it says.
	_, total, err := s.ListAuditLogs(AuditFilter{Action: "login"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("action=login matched %d, want 3 (login.failed must not match)", total)
	}

	// The prefix form is opt-in and covers a family.
	_, total, _ = s.ListAuditLogs(AuditFilter{ActionPrefix: "login"})
	if total != 5 {
		t.Errorf("action_prefix=login matched %d, want 5", total)
	}

	_, total, _ = s.ListAuditLogs(AuditFilter{Actor: "alice"})
	if total != 7 {
		t.Errorf("actor=alice matched %d, want 7", total)
	}
}

func TestTimeWindowIsHalfOpen(t *testing.T) {
	s := auditStore(t)
	base := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	seedAudit(t, s, 1, "a", "old", base)
	seedAudit(t, s, 1, "a", "new", base.Add(time.Hour))

	// Since is inclusive, Until exclusive, so consecutive windows cannot
	// double-count the entry on the boundary.
	_, total, err := s.ListAuditLogs(AuditFilter{Since: base, Until: base.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("a half-open window matched %d, want 1", total)
	}
}

func TestLimitIsCapped(t *testing.T) {
	s := auditStore(t)
	seedAudit(t, s, 3, "a", "x", time.Time{})
	got, _, err := s.ListAuditLogs(AuditFilter{Limit: MaxAuditLimit + 5000})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > MaxAuditLimit {
		t.Fatalf("returned %d rows, above the %d cap — one call could load the table into memory",
			len(got), MaxAuditLimit)
	}
}

// Pruning is a deletion. A zero cutoff read as "the beginning of time" would
// erase the entire trail, so it is refused.
func TestPruneRefusesAZeroCutoff(t *testing.T) {
	s := auditStore(t)
	seedAudit(t, s, 3, "a", "x", time.Time{})
	if _, err := s.PruneAuditLogs(time.Time{}); err == nil {
		t.Fatal("a zero cutoff was accepted; that would delete every entry")
	}
	if n, _ := s.CountAuditLogs(); n != 3 {
		t.Fatalf("entries were deleted anyway: %d remain", n)
	}
}

func TestPruneRemovesOnlyWhatIsOlder(t *testing.T) {
	s := auditStore(t)
	old := time.Now().Add(-100 * 24 * time.Hour)
	seedAudit(t, s, 4, "a", "old", old)
	seedAudit(t, s, 2, "a", "recent", time.Now())

	removed, err := s.PruneAuditLogs(time.Now().Add(-30 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 4 {
		t.Fatalf("pruned %d, want 4", removed)
	}
	if n, _ := s.CountAuditLogs(); n != 2 {
		t.Fatalf("%d entries remain, want 2", n)
	}
}

func TestAuditActionsAreDistinctAndSorted(t *testing.T) {
	s := auditStore(t)
	seedAudit(t, s, 2, "a", "login", time.Time{})
	seedAudit(t, s, 2, "a", "admin.create", time.Time{})

	got, err := s.AuditActions()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want two distinct actions", got)
	}
	if got[0] != "admin.create" || got[1] != "login" {
		t.Fatalf("actions are not sorted: %v", got)
	}
}
