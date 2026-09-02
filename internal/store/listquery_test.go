package store

import (
	"strings"
	"testing"
)

// Every list query was an unbounded Find, and the panel calls them on every page
// view: the cost grew with the customer base, which is the wrong direction.
// These cover paging, and the two things that make it safe.

func listStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func seedUsers(t *testing.T, s *Store, names ...string) {
	t.Helper()
	for i, n := range names {
		u := &User{Username: n, SubToken: n + "-tok", UsedTraffic: int64(i)}
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPagingReturnsAPageAndTheTotal(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "a", "b", "c", "d", "e")

	got, total, err := s.ListUsersPage(0, ListQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("total is %d, want 5", total)
	}
	if len(got) != 2 {
		t.Fatalf("page holds %d, want 2", len(got))
	}
}

// The zero value must behave exactly as the old unbounded call did, or adding
// pagination silently truncates every list the panel already renders.
func TestAZeroQueryReturnsEverything(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "a", "b", "c")
	got, total, err := s.ListUsersPage(0, ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || total != 3 {
		t.Fatalf("zero query returned %d of %d, want all 3", len(got), total)
	}
}

// A sort column cannot be parameterised, so an unvalidated one interpolated into
// ORDER BY is a SQL injection. Anything off the allowlist falls back to the
// default rather than reaching the query.
func TestAnUnknownSortColumnCannotReachTheQuery(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "a", "b")

	for _, evil := range []string{
		"id; DROP TABLE users--",
		"(SELECT 1)",
		"username, (SELECT password_hash FROM admins)",
		"nonexistent_column",
	} {
		got, _, err := s.ListUsersPage(0, ListQuery{Sort: evil})
		if err != nil {
			t.Fatalf("sort %q produced an error instead of falling back: %v", evil, err)
		}
		if len(got) != 2 {
			t.Fatalf("sort %q changed the result set", evil)
		}
	}
	// And the table is still there.
	if _, total, err := s.ListUsersPage(0, ListQuery{}); err != nil || total != 2 {
		t.Fatalf("the users table did not survive: %v total=%d", err, total)
	}
}

func TestAllowedSortColumnsWork(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "charlie", "alice", "bob")

	asc, _, err := s.ListUsersPage(0, ListQuery{Sort: "username"})
	if err != nil {
		t.Fatal(err)
	}
	if asc[0].Username != "alice" {
		t.Fatalf("ascending sort put %q first", asc[0].Username)
	}
	desc, _, _ := s.ListUsersPage(0, ListQuery{Sort: "username", Desc: true})
	if desc[0].Username != "charlie" {
		t.Fatalf("descending sort put %q first", desc[0].Username)
	}
}

// A search for "%" would otherwise match every row, and "_" far more than the
// operator typed — results that look plausible and are wrong.
func TestSearchWildcardsAreEscaped(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "alice", "bob", "a_c")

	all, _, _ := s.ListUsersPage(0, ListQuery{Search: "%"})
	if len(all) != 0 {
		t.Fatalf("a literal %% matched %d rows; wildcards are not escaped", len(all))
	}
	underscore, _, _ := s.ListUsersPage(0, ListQuery{Search: "a_c"})
	if len(underscore) != 1 || underscore[0].Username != "a_c" {
		t.Fatalf("a literal _ matched %d rows, want exactly a_c", len(underscore))
	}
}

func TestSearchNarrowsAndCountsWhatItMatched(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "alice", "alicia", "bob")
	got, total, err := s.ListUsersPage(0, ListQuery{Search: "ali"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("search matched %d of %d, want 2", len(got), total)
	}
}

// A reseller's page numbers must describe their own customers, not their offset
// within everyone's.
func TestOwnerScopingIsAppliedBeforePaging(t *testing.T) {
	s := listStore(t)
	for i, name := range []string{"mine1", "theirs1", "mine2", "theirs2"} {
		owner := uint(1)
		if strings.HasPrefix(name, "theirs") {
			owner = 2
		}
		u := &User{Username: name, SubToken: name, OwnerAdminID: owner, UsedTraffic: int64(i)}
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	got, total, err := s.ListUsersPage(1, ListQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("a reseller sees a total of %d, want only their own 2", total)
	}
	for _, u := range got {
		if u.OwnerAdminID != 1 {
			t.Fatalf("another tenant's user leaked into the page: %s", u.Username)
		}
	}
}

// Without a ceiling one request can load the table into memory, which is the
// problem pagination exists to solve.
func TestLimitIsCappedAtTheMaximum(t *testing.T) {
	s := listStore(t)
	seedUsers(t, s, "a", "b", "c")
	q := ListQuery{Limit: MaxListLimit + 10_000}.normalize()
	if q.Limit > MaxListLimit {
		t.Fatalf("limit normalised to %d, above the %d cap", q.Limit, MaxListLimit)
	}
}

// Asking for an offset without a size must not mean "everything from here".
func TestAnOffsetWithoutALimitGetsADefaultPage(t *testing.T) {
	q := ListQuery{Offset: 10}.normalize()
	if q.Limit != DefaultListLimit {
		t.Fatalf("offset without limit produced limit=%d, want the default", q.Limit)
	}
}
