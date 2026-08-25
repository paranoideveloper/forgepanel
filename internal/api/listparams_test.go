package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// Pagination is OPT-IN. Every existing caller — the panel's own views included —
// sends no paging parameters and must keep getting the bare array it always got;
// adding an envelope unconditionally would break every one of them at once.

func seedListUsers(t *testing.T, s *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		u := &store.User{Username: "u" + itoa(i), SubToken: "tok" + itoa(i)}
		if err := s.db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListWithoutParamsStillReturnsABareArray(t *testing.T) {
	s, token := adminAPI(t)
	seedListUsers(t, s, 3)

	code, body := doGET(t, s, "/api/admin/users", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	if !strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Fatalf("an unpaged request returned an envelope, breaking every existing caller: %s",
			body[:min(120, len(body))])
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 3 {
		t.Fatalf("returned %d users, want all 3", len(arr))
	}
}

func TestAPagedRequestGetsAnEnvelopeWithTheTotal(t *testing.T) {
	s, token := adminAPI(t)
	seedListUsers(t, s, 7)

	code, body := doGET(t, s, "/api/admin/users?limit=3", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var page struct {
		Items  []map[string]any `json:"items"`
		Total  int64            `json:"total"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("a paged request did not return an envelope: %v (%s)", err, body[:min(120, len(body))])
	}
	if len(page.Items) != 3 {
		t.Fatalf("page holds %d, want 3", len(page.Items))
	}
	// The total is what makes the page meaningful.
	if page.Total != 7 {
		t.Fatalf("total is %d, want 7", page.Total)
	}
	if page.Limit != 3 {
		t.Fatalf("limit reported as %d, want 3", page.Limit)
	}
}

// A UI counts pages while the API counts rows; making every caller do that
// arithmetic is how off-by-one paging bugs get written.
func TestPageParameterMapsToOffset(t *testing.T) {
	s, token := adminAPI(t)
	seedListUsers(t, s, 10)

	first, _ := pageItems(t, s, token, "/api/admin/users?limit=4&page=1")
	second, off := pageItems(t, s, token, "/api/admin/users?limit=4&page=2")
	if off != 4 {
		t.Fatalf("page=2 with limit=4 produced offset %d, want 4", off)
	}
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("pages hold %d and %d, want 4 each", len(first), len(second))
	}
	if first[0]["username"] == second[0]["username"] {
		t.Fatal("page 2 repeated page 1")
	}
}

// A search implies the caller wants the envelope: "12 matched of how many?" is
// otherwise unanswerable.
func TestSearchReturnsAnEnvelope(t *testing.T) {
	s, token := adminAPI(t)
	seedListUsers(t, s, 5)

	_, body := doGET(t, s, "/api/admin/users?search=u1", token)
	if strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Fatalf("a search returned a bare array, so the match count is unknowable: %s", body)
	}
}

// A sort field cannot be parameterised, so an unvalidated one is an injection.
// It must fall back rather than reach the query.
func TestAHostileSortIsHarmlessOverHTTP(t *testing.T) {
	s, token := adminAPI(t)
	seedListUsers(t, s, 3)

	code, body := doGET(t, s, "/api/admin/users?limit=10&sort=id%3B%20DROP%20TABLE%20users--", token)
	if code != 200 {
		t.Fatalf("a hostile sort returned %d: %s", code, body)
	}
	// And the users are still there.
	code, body = doGET(t, s, "/api/admin/users", token)
	var arr []map[string]any
	if err := json.Unmarshal([]byte(body), &arr); err != nil || len(arr) != 3 {
		t.Fatalf("the users table did not survive a hostile sort: %v (%d rows)", err, len(arr))
	}
}

func pageItems(t *testing.T, s *Server, token, url string) ([]map[string]any, int) {
	t.Helper()
	code, body := doGET(t, s, url, token)
	if code != 200 {
		t.Fatalf("%s -> %d: %s", url, code, body)
	}
	var page struct {
		Items  []map[string]any `json:"items"`
		Offset int              `json:"offset"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatalf("%s did not return an envelope: %v", url, err)
	}
	return page.Items, page.Offset
}
