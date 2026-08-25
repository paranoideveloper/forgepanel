package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The audit trail was write-only: no route, no reader. These drive the real
// router, so they also cover the authorization the trail needs — entries name
// the actor, their IP and what they did, across every admin.

func TestAuditTrailIsReadableAndPaged(t *testing.T) {
	s, token := adminAPI(t)

	// Creating an admin writes audit entries through the real handlers.
	for _, name := range []string{"r1", "r2", "r3"} {
		if code, body := realPost(t, s, "/api/admin/admins", token, map[string]any{
			"username": name, "password": "hunter2hunter2", "role": "reseller",
		}); code != 201 {
			t.Fatalf("setup %s: %d %s", name, code, body)
		}
	}

	code, body := doGET(t, s, "/api/admin/audit?limit=2", token)
	if code != 200 {
		t.Fatalf("reading the audit trail returned %d: %s", code, body)
	}
	var page auditPage
	if err := json.Unmarshal([]byte(body), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total < 3 {
		t.Fatalf("total is %d, want at least the 3 admin.create entries", page.Total)
	}
	if len(page.Items) != 2 {
		t.Fatalf("limit=2 returned %d items", len(page.Items))
	}
	// The total is what makes a page meaningful.
	if page.Total <= int64(len(page.Items)) {
		t.Errorf("total (%d) should exceed the page size, or paging is pointless", page.Total)
	}
	// Entries must carry the actor and the action, or the trail answers nothing.
	if page.Items[0].Actor == "" || page.Items[0].Action == "" {
		t.Errorf("entry is missing actor/action: %+v", page.Items[0])
	}
}

func TestAuditFilterByAction(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "filtered", "password": "hunter2hunter2", "role": "viewer",
	}); code != 201 {
		t.Fatal("setup failed")
	}

	code, body := doGET(t, s, "/api/admin/audit?action=admin.create", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var page auditPage
	_ = json.Unmarshal([]byte(body), &page)
	for _, e := range page.Items {
		if e.Action != "admin.create" {
			t.Fatalf("filter leaked a %q entry", e.Action)
		}
	}
	if page.Total == 0 {
		t.Error("the filter matched nothing, but an admin was just created")
	}
}

// A malformed time must be refused, not ignored: silently widening the window to
// "everything" is how an operator concludes an event never happened.
func TestAuditRefusesAMalformedTimeWindow(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/admin/audit?since=yesterday", token)
	if code != 400 {
		t.Fatalf("a malformed `since` returned %d, want 400: %s", code, body)
	}
	if !strings.Contains(body, "since") {
		t.Errorf("the error should name the offending parameter: %s", body)
	}
}

func TestAuditActionsListIsServed(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := realPost(t, s, "/api/admin/admins", token, map[string]any{
		"username": "acts", "password": "hunter2hunter2", "role": "viewer",
	}); code != 201 {
		t.Fatal("setup failed")
	}
	code, body := doGET(t, s, "/api/admin/audit/actions", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	if !strings.Contains(body, "admin.create") {
		t.Errorf("the action list omits an action that was just recorded: %s", body)
	}
}

// One reseller must not learn what another tenant's admin did, and a viewer has
// no business with the trail at all.
func TestAuditIsNotReadableByResellersOrViewers(t *testing.T) {
	roles := rolesForRoute(http.MethodGet, "/api/admin/audit")
	if len(roles) == 0 {
		t.Fatal("GET /api/admin/audit resolves to no policy")
	}
	for _, bad := range []string{string(store.RoleReseller), string(store.RoleViewer)} {
		if allows(roles, bad) {
			t.Errorf("the audit trail is readable by %s (allowed=%v)", bad, roles)
		}
	}
}
