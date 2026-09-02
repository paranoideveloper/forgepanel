package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// tmplPost is the one-line request shape the rest of this file needs: a JSON
// body at an admin route, with the bearer token, returning status and body.
func tmplPost(t *testing.T, srv *Server, token, path string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal %s body: %v", path, err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

// TestCreateUserFromTemplateAppliesEveryField is the wiring test for saved
// plans. It asserts on the created USER, never on the template row, because a
// template table with its own green CRUD round-trip is exactly the shape this
// feature fails in: everything stored, nothing stamped.
//
// The prefix/suffix is the load-bearing assertion. It is the one field a caller
// cannot fake by passing values directly, so a composed username proves the
// template was READ rather than the request echoed.
func TestCreateUserFromTemplateAppliesEveryField(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)

	code, body := tmplPost(t, srv, token, "/api/admin/inbounds", map[string]any{
		"tag": "vless-main", "protocol": "vless", "port": 443, "flow": "xtls-rprx-vision",
	})
	if code != http.StatusCreated {
		t.Fatalf("create inbound: %d %s", code, body)
	}
	var in store.Inbound
	if err := json.Unmarshal(body, &in); err != nil || in.ID == 0 {
		t.Fatalf("inbound id missing: %v %s", err, body)
	}

	code, body = tmplPost(t, srv, token, "/api/admin/groups", map[string]any{
		"name": "g1", "inbound_ids": []uint{in.ID},
	})
	if code != http.StatusCreated {
		t.Fatalf("create group: %d %s", code, body)
	}
	var grp store.Group
	if err := json.Unmarshal(body, &grp); err != nil || grp.ID == 0 {
		t.Fatalf("group id missing: %v %s", err, body)
	}

	code, body = tmplPost(t, srv, token, "/api/admin/user-templates", map[string]any{
		"name": "trial-5g", "username_prefix": "tr-", "username_suffix": "-x",
		"data_limit": 5368709120, "expire_days": 30,
		"group_id": grp.ID, "inbound_ids": []uint{in.ID},
	})
	if code != http.StatusCreated {
		t.Fatalf("create user template: %d %s", code, body)
	}
	var tpl struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &tpl); err != nil || tpl.ID == 0 {
		t.Fatalf("template id missing: %v %s", err, body)
	}

	code, body = tmplPost(t, srv, token, "/api/admin/users", map[string]any{
		"username": "bob", "template_id": tpl.ID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create user from template: %d %s", code, body)
	}
	var created struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
		t.Fatalf("user id missing: %v %s", err, body)
	}

	u, err := st.UserByID(created.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if u.Username != "tr-bob-x" {
		t.Fatalf("template prefix/suffix not applied server-side: got %q, want %q", u.Username, "tr-bob-x")
	}
	if u.DataLimit != 5368709120 {
		t.Fatalf("template data limit not stamped: got %d, want 5368709120", u.DataLimit)
	}
	if u.ExpireAt == nil {
		t.Fatal("template expiry not stamped: expire_at is nil")
	} else if d := u.ExpireAt.Sub(time.Now().AddDate(0, 0, 30)); d > time.Minute || d < -time.Minute {
		t.Fatalf("template expiry off by %s from now+30d", d)
	}
	if u.GroupID != grp.ID {
		t.Fatalf("template group not stamped: got %d, want %d", u.GroupID, grp.ID)
	}

	as, err := st.UserAssignments(created.ID)
	if err != nil {
		t.Fatalf("UserAssignments: %v", err)
	}
	if !slices.Contains(as.Direct, in.ID) {
		t.Fatalf("template inbounds never reached the user_inbounds rows: direct=%v want %d",
			as.Direct, in.ID)
	}

	// The apply path, on an account that already exists: same stamp, and the
	// username is deliberately left alone (its SubToken is already distributed).
	code, body = tmplPost(t, srv, token, "/api/admin/users", map[string]any{"username": "carol"})
	if code != http.StatusCreated {
		t.Fatalf("create plain user: %d %s", code, body)
	}
	var plain struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &plain); err != nil || plain.ID == 0 {
		t.Fatalf("plain user id missing: %v %s", err, body)
	}
	code, body = tmplPost(t, srv, token,
		"/api/admin/users/"+strconv.FormatUint(uint64(plain.ID), 10)+"/apply-template",
		map[string]any{"template_id": tpl.ID})
	if code != http.StatusOK {
		t.Fatalf("apply template to existing user: %d %s", code, body)
	}
	after, err := st.UserByID(plain.ID)
	if err != nil {
		t.Fatalf("UserByID after apply: %v", err)
	}
	if after.Username != "carol" {
		t.Fatalf("apply renamed a live account: got %q, want %q", after.Username, "carol")
	}
	if after.DataLimit != 5368709120 || after.GroupID != grp.ID {
		t.Fatalf("apply did not stamp the plan: limit=%d group=%d", after.DataLimit, after.GroupID)
	}
	asAfter, err := st.UserAssignments(plain.ID)
	if err != nil {
		t.Fatalf("UserAssignments after apply: %v", err)
	}
	if !slices.Contains(asAfter.Direct, in.ID) {
		t.Fatalf("apply did not assign the template inbounds: direct=%v want %d", asAfter.Direct, in.ID)
	}
}

// TestResellerMayUseSavedPlans pins the authz rule. adminAuthzRules matches on a
// bare prefix with no segment boundary, so "/api/admin/user-templates" is NOT
// covered by the "/api/admin/users" rule and falls through to the owner-only
// catch-all — the feature would work for the owner and 403 for the one role that
// wanted saved plans, with the whole suite still green.
func TestResellerMayUseSavedPlans(t *testing.T) {
	if roles := rolesForRoute("GET", "/api/admin/user-templates"); !slices.Contains(roles, string(store.RoleReseller)) {
		t.Fatalf("a reseller cannot reach saved plans: roles=%v", roles)
	}
	// The rule must not be so short that it also swallows customer management.
	if roles := rolesForRoute("GET", "/api/admin/users"); !slices.Contains(roles, string(store.RoleReseller)) {
		t.Fatalf("the new rule re-scoped /api/admin/users: roles=%v", roles)
	}
}

// The panel sends data_limit on every create — the GB box starts at 0 and an
// emptied number input coerces to 0 — so the request body always carried a
// non-nil *int64. handleCreateUser applied the template's limit and then
// overwrote it unconditionally, which meant picking "trial-5g" in the only UI
// that exists created an UNLIMITED account, and charged the reseller's traffic
// credit nothing.
//
// The wiring test above posts {"username":..,"template_id":..} with no
// data_limit key at all — a body the browser never produces — so it passed
// against the bug.
func TestASavedPlansLimitSurvivesTheBodyTheBrowserActuallySends(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)
	const fiveGB = 5368709120

	code, body := tmplPost(t, srv, token, "/api/admin/user-templates", map[string]any{
		"name": "trial-5g", "data_limit": fiveGB,
	})
	if code != http.StatusCreated {
		t.Fatalf("create template: %d %s", code, body)
	}
	var tpl struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &tpl); err != nil || tpl.ID == 0 {
		t.Fatalf("template id missing: %v %s", err, body)
	}

	// Verbatim the shape UsersView.svelte builds with an untouched GB box:
	// data_limit present, and zero.
	code, body = tmplPost(t, srv, token, "/api/admin/users", map[string]any{
		"username": "bob", "group_id": 0, "template_id": tpl.ID,
		"data_limit": 0, "expire_days": 0,
	})
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}
	var created struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
		t.Fatalf("user id missing: %v %s", err, body)
	}
	u, err := st.UserByID(created.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if u.DataLimit != fiveGB {
		t.Fatalf("data_limit = %d, want the plan's %d — an untouched box wiped the plan",
			u.DataLimit, fiveGB)
	}
}

// The other direction, so the fix does not turn the box into decoration: a
// limit the operator actually typed still overrides the plan.
func TestATypedLimitStillOverridesTheSavedPlan(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)
	const fiveGB, tenGB = 5368709120, 10737418240

	_, body := tmplPost(t, srv, token, "/api/admin/user-templates", map[string]any{
		"name": "trial-5g-2", "data_limit": fiveGB,
	})
	var tpl struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &tpl); err != nil || tpl.ID == 0 {
		t.Fatalf("template id missing: %v %s", err, body)
	}

	_, body = tmplPost(t, srv, token, "/api/admin/users", map[string]any{
		"username": "carol", "template_id": tpl.ID, "data_limit": tenGB,
	})
	var created struct {
		ID uint `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == 0 {
		t.Fatalf("user id missing: %v %s", err, body)
	}
	u, err := st.UserByID(created.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if u.DataLimit != tenGB {
		t.Fatalf("data_limit = %d, want the typed %d", u.DataLimit, tenGB)
	}
}
