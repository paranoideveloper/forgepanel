package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/job"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// ugFixture builds a server with two inbounds, a group binding one of them, and
// a user in that group — the smallest shape that can express "direct versus
// inherited".
type ugFixture struct {
	s               *Server
	router          *gin.Engine
	user            *store.User
	group           *store.Group
	inGroup, inFree uint
	ownerTok        string
	resellerTok     string
	resellerID      uint
}

func newUGFixture(t *testing.T) *ugFixture {
	t.Helper()
	s := dbServerT(t)

	mk := func(remark string, port int) uint {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "203.0.113.5",
			Port: port, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: remark}
		in, err := s.db.CreateInbound(n)
		if err != nil {
			t.Fatal(err)
		}
		return in.ID
	}
	inGroup, inFree := mk("grouped", 443), mk("free", 8443)

	g := &store.Group{Name: "g1", InboundIDs: store.IntSlice{inGroup}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "alice", GroupID: g.ID, Status: store.StatusActive,
		SubToken: "tok-alice", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	owner := &store.Admin{Username: "owner", Role: store.RoleOwner, PasswordHash: "x"}
	if err := s.db.CreateAdmin(owner); err != nil {
		t.Fatal(err)
	}
	reseller := &store.Admin{Username: "res", Role: store.RoleReseller, PasswordHash: "x"}
	if err := s.db.CreateAdmin(reseller); err != nil {
		t.Fatal(err)
	}
	ownerTok, _, _ := s.signer.Issue(owner.ID, owner.Username, string(store.RoleOwner))
	resTok, _, _ := s.signer.Issue(reseller.ID, reseller.Username, string(store.RoleReseller))

	r := gin.New()
	api := r.Group("/api/admin", s.signer.Middleware())
	api.GET("/users", s.handleListUsers)
	api.GET("/users/:id", s.handleGetUser)
	api.PATCH("/users/:id", s.handleUpdateUser)
	api.PUT("/users/:id/inbounds", s.handleSetUserInbounds)
	api.POST("/users/:id/reset-credentials", s.handleResetUserCredentials)
	api.GET("/groups/:id", s.handleGetGroup)
	api.PATCH("/groups/:id", s.handleUpdateGroup)
	api.DELETE("/groups/:id", s.handleDeleteGroup)
	api.GET("/health/detail", s.handleHealthDetail)
	s.router = r

	return &ugFixture{s: s, router: r, user: u, group: g, inGroup: inGroup,
		inFree: inFree, ownerTok: ownerTok, resellerTok: resTok, resellerID: reseller.ID}
}

func (f *ugFixture) do(t *testing.T, method, path, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// --- §2 user editing ------------------------------------------------------

// TestUserCanBeEditedAfterCreation is the headline gap: before this there was no
// update route at all, so correcting any field meant deleting and recreating the
// user, which changes their subscription token and breaks every configured client.
func TestUserCanBeEditedAfterCreation(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"note":"vip","data_limit":1073741824,"status":"disabled"}`)
	if rec.Code != 200 {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}
	got, err := f.s.db.UserByID(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Note != "vip" || got.DataLimit != 1073741824 || got.Status != store.StatusDisabled {
		t.Fatalf("fields not applied: %+v", got)
	}
}

// TestEditingDoesNotRegenerateCredentials: an ordinary edit must never rotate
// secrets, or changing a note would silently break every client the user has.
func TestEditingDoesNotRegenerateCredentials(t *testing.T) {
	f := newUGFixture(t)
	before, _ := f.s.db.UserByID(f.user.ID)

	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"note":"changed"}`)
	if rec.Code != 200 {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}
	after, _ := f.s.db.UserByID(f.user.ID)
	if after.UUID != before.UUID || after.SubToken != before.SubToken ||
		after.Password != before.Password {
		t.Fatal("an ordinary edit rotated the user's credentials")
	}
}

// TestCredentialResetIsExplicit: rotation happens only through its own endpoint,
// and only for what was asked for.
func TestCredentialResetIsExplicit(t *testing.T) {
	f := newUGFixture(t)
	before, _ := f.s.db.UserByID(f.user.ID)

	rec := f.do(t, http.MethodPost,
		fmt.Sprintf("/api/admin/users/%d/reset-credentials", f.user.ID),
		f.ownerTok, `{"uuid":true}`)
	if rec.Code != 200 {
		t.Fatalf("reset failed: %d %s", rec.Code, rec.Body.String())
	}
	after, _ := f.s.db.UserByID(f.user.ID)
	if after.UUID == before.UUID {
		t.Fatal("uuid was not rotated when explicitly requested")
	}
	if after.SubToken != before.SubToken {
		t.Fatal("sub_token rotated although only uuid was requested")
	}
}

// TestConcurrentEditIsRejected: the second writer must not silently discard the
// first writer's change.
func TestConcurrentEditIsRejected(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodGet, fmt.Sprintf("/api/admin/users/%d", f.user.ID), f.ownerTok, "")
	var read struct {
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}

	// Someone else edits first.
	time.Sleep(1100 * time.Millisecond) // updated_at has second granularity
	if rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"note":"first writer"}`); rec.Code != 200 {
		t.Fatalf("first write failed: %d", rec.Code)
	}

	// Our stale write must be refused.
	body := fmt.Sprintf(`{"note":"second writer","updated_at":%q}`,
		read.UpdatedAt.Format(time.RFC3339))
	rec = f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, body)
	if rec.Code != 409 {
		t.Fatalf("stale write got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	got, _ := f.s.db.UserByID(f.user.ID)
	if got.Note != "first writer" {
		t.Fatalf("stale write clobbered the earlier edit: note=%q", got.Note)
	}
}

// TestUnknownFieldIsRejectedNotIgnored: silently dropping an unknown field would
// report success for an edit that did not happen.
func TestUnknownFieldIsRejectedNotIgnored(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"owner_admin_id":99,"used_traffic":0}`)
	if rec.Code != 422 {
		t.Fatalf("unknown fields got %d, want 422: %s", rec.Code, rec.Body.String())
	}
}

// TestInvalidFieldValuesReturnFieldLevelErrors.
func TestInvalidFieldValuesReturnFieldLevelErrors(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"status":"nonsense","data_limit":-1}`)
	if rec.Code != 422 {
		t.Fatalf("got %d, want 422", rec.Code)
	}
	var resp struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Fields["status"] == "" || resp.Fields["data_limit"] == "" {
		t.Fatalf("expected per-field errors, got %+v", resp.Fields)
	}
}

// --- permissions ----------------------------------------------------------

// TestResellerCannotEditForeignUser: scope is enforced server-side, and the
// response must not reveal that the user exists.
func TestResellerCannotEditForeignUser(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.resellerTok, `{"note":"mine now"}`)
	if rec.Code != 404 {
		t.Fatalf("reseller editing another tenant's user got %d, want 404", rec.Code)
	}
	got, _ := f.s.db.UserByID(f.user.ID)
	if got.Note == "mine now" {
		t.Fatal("a reseller edited a user outside their tenancy")
	}
}

// TestResellerCannotRaiseQuota: a field outside the reseller allowlist must be
// rejected outright, not quietly dropped.
func TestResellerCannotRaiseQuota(t *testing.T) {
	f := newUGFixture(t)
	own := &store.User{Username: "bob", Status: store.StatusActive,
		OwnerAdminID: f.resellerID, SubToken: "tok-bob", DataLimit: 100}
	if err := f.s.db.CreateUser(own); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", own.ID),
		f.resellerTok, `{"data_limit":999999999999}`)
	if rec.Code != 422 {
		t.Fatalf("reseller quota edit got %d, want 422: %s", rec.Code, rec.Body.String())
	}
	got, _ := f.s.db.UserByID(own.ID)
	if got.DataLimit != 100 {
		t.Fatalf("reseller raised their own user's quota to %d", got.DataLimit)
	}
}

// TestResellerCanEditAllowedFieldOnOwnUser confirms the allowlist is not a
// blanket denial.
func TestResellerCanEditAllowedFieldOnOwnUser(t *testing.T) {
	f := newUGFixture(t)
	own := &store.User{Username: "carol", Status: store.StatusActive,
		OwnerAdminID: f.resellerID, SubToken: "tok-carol"}
	if err := f.s.db.CreateUser(own); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", own.ID),
		f.resellerTok, `{"note":"ok"}`)
	if rec.Code != 200 {
		t.Fatalf("reseller editing an allowed field got %d: %s", rec.Code, rec.Body.String())
	}
}

// --- §4 inbound assignment ------------------------------------------------

// TestDirectAndInheritedAreDistinguished: the split is the whole point — an
// inherited inbound belongs to the group, a direct one to the user.
func TestDirectAndInheritedAreDistinguished(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	rec := f.do(t, http.MethodPut,
		fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID), f.ownerTok, body)
	if rec.Code != 200 {
		t.Fatalf("assign failed: %d %s", rec.Code, rec.Body.String())
	}
	a, err := f.s.db.UserAssignments(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Direct) != 1 || a.Direct[0] != f.inFree {
		t.Fatalf("direct = %v, want [%d]", a.Direct, f.inFree)
	}
	if len(a.Inherited) != 1 || a.Inherited[0] != f.inGroup {
		t.Fatalf("inherited = %v, want [%d]", a.Inherited, f.inGroup)
	}
	if len(a.Effective) != 2 {
		t.Fatalf("effective = %v, want both", a.Effective)
	}
}

// TestDuplicateAssignmentsArePrevented.
func TestDuplicateAssignmentsArePrevented(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d,%d,%d]}`, f.inFree, f.inFree, f.inFree)
	if rec := f.do(t, http.MethodPut,
		fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID), f.ownerTok, body); rec.Code != 200 {
		t.Fatalf("assign failed: %d %s", rec.Code, rec.Body.String())
	}
	a, _ := f.s.db.UserAssignments(f.user.ID)
	if len(a.Direct) != 1 {
		t.Fatalf("duplicates were stored: %v", a.Direct)
	}
}

// TestAssignmentIsRemovable.
func TestAssignmentIsRemovable(t *testing.T) {
	f := newUGFixture(t)
	path := fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID)
	f.do(t, http.MethodPut, path, f.ownerTok, fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree))
	if rec := f.do(t, http.MethodPut, path, f.ownerTok, `{"inbound_ids":[]}`); rec.Code != 200 {
		t.Fatalf("clearing assignments failed: %d", rec.Code)
	}
	a, _ := f.s.db.UserAssignments(f.user.ID)
	if len(a.Direct) != 0 {
		t.Fatalf("direct assignments survived removal: %v", a.Direct)
	}
	if len(a.Inherited) != 1 {
		t.Fatal("clearing direct assignments must not touch inherited ones")
	}
}

// TestNonexistentInboundIsRejected: the payload is validated against reality,
// not against whatever the UI rendered.
func TestNonexistentInboundIsRejected(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, `{"inbound_ids":[99999]}`)
	if rec.Code == 200 {
		t.Fatal("an assignment to a nonexistent inbound was accepted")
	}
}

// TestSubscriptionReflectsEffectiveAssignments: the whole feature is pointless
// if the subscription does not follow.
func TestSubscriptionReflectsEffectiveAssignments(t *testing.T) {
	f := newUGFixture(t)
	nodes := f.s.subscriptionNodes(f.user.SubToken, "example.com")
	if len(nodes) != 1 {
		t.Fatalf("baseline: want 1 inherited node, got %d", len(nodes))
	}
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, body)

	nodes = f.s.subscriptionNodes(f.user.SubToken, "example.com")
	if len(nodes) != 2 {
		t.Fatalf("subscription did not pick up the direct assignment: %d nodes", len(nodes))
	}
}

// TestUserWithNoGroupKeepsDirectAssignments: "no group" is a valid persistent
// state, and it must not wipe out access assigned to the user directly.
func TestUserWithNoGroupKeepsDirectAssignments(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, body)

	if rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", f.user.ID),
		f.ownerTok, `{"group_id":0}`); rec.Code != 200 {
		t.Fatalf("removing the group failed: %d %s", rec.Code, rec.Body.String())
	}
	a, _ := f.s.db.UserAssignments(f.user.ID)
	if len(a.Inherited) != 0 {
		t.Fatalf("inherited survived group removal: %v", a.Inherited)
	}
	if len(a.Direct) != 1 {
		t.Fatalf("direct assignments were lost with the group: %v", a.Direct)
	}
	if nodes := f.s.subscriptionNodes(f.user.SubToken, "example.com"); len(nodes) != 1 {
		t.Fatalf("group-less user's subscription has %d nodes, want 1", len(nodes))
	}
}

// TestEngineSpecIncludesDirectAssignments: an inbound a user can see in their
// subscription but cannot authenticate on is worse than not offering it.
func TestEngineSpecIncludesDirectAssignments(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, body)

	specs := f.s.enabledInboundSpecs()
	found := false
	for _, sp := range specs {
		if sp.Node.Remark != "free" {
			continue
		}
		// The inbound now always carries its own credential too; assert the
		// directly-assigned USER is present among the clients.
		for _, cl := range sp.Clients {
			if cl.Email == job.UserEmail(f.user.ID) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the directly-assigned inbound was served without the user as a client")
	}
}

// TestOverQuotaUserExcludedFromEngine is the enforcement half of quota: the
// scheduler flipping a user to StatusLimited is worthless if the engine still
// materializes their credential — they would keep transferring until some later
// reload. A limited, disabled or expired user must be absent from the built
// specs so the core refuses their traffic on the very next reload.
func TestOverQuotaUserExcludedFromEngine(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, body)

	present := func() bool {
		for _, sp := range f.s.enabledInboundSpecs() {
			for _, cl := range sp.Clients {
				if cl.Email == job.UserEmail(f.user.ID) {
					return true
				}
			}
		}
		return false
	}

	// Active: the credential is materialized (control).
	if !present() {
		t.Fatal("an active assigned user should be a client on the inbound")
	}

	// Each non-serving status must remove the credential entirely.
	for _, st := range []store.UserStatus{store.StatusLimited, store.StatusDisabled, store.StatusExpired} {
		u, err := f.s.db.UserByID(f.user.ID)
		if err != nil {
			t.Fatal(err)
		}
		u.Status = st
		if err := f.s.db.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		if present() {
			t.Fatalf("a %s user is still materialized into the engine config — the core would keep serving their traffic", st)
		}
	}

	// Restoring to active brings the credential back, so a top-up/renewal works.
	u, _ := f.s.db.UserByID(f.user.ID)
	u.Status = store.StatusActive
	_ = f.s.db.SaveUser(u)
	if !present() {
		t.Fatal("reactivating the user did not restore their engine credential")
	}
}

// --- §5/§6 group editing --------------------------------------------------

func TestGroupCanBeEditedAfterCreation(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"name":"renamed","description":"d","inbound_ids":[%d,%d]}`,
		f.inGroup, f.inFree)
	if rec := f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/groups/%d", f.group.ID),
		f.ownerTok, body); rec.Code != 200 {
		t.Fatalf("group update failed: %d %s", rec.Code, rec.Body.String())
	}
	g, _ := f.s.db.GroupByID(f.group.ID)
	if g.Name != "renamed" || g.Description != "d" || len(g.InboundIDs) != 2 {
		t.Fatalf("group not updated: %+v", g)
	}
}

// TestGroupChangePropagatesToMembers.
func TestGroupChangePropagatesToMembers(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d,%d]}`, f.inGroup, f.inFree)
	f.do(t, http.MethodPatch, fmt.Sprintf("/api/admin/groups/%d", f.group.ID), f.ownerTok, body)

	a, _ := f.s.db.UserAssignments(f.user.ID)
	if len(a.Inherited) != 2 {
		t.Fatalf("member did not inherit the new inbound: %v", a.Inherited)
	}
}

// TestGroupShowsMemberCount so the UI can warn before a wide-reaching edit.
func TestGroupShowsMemberCount(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodGet, fmt.Sprintf("/api/admin/groups/%d", f.group.ID), f.ownerTok, "")
	var resp struct {
		Members int64 `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Members != 1 {
		t.Fatalf("members = %d, want 1", resp.Members)
	}
}

// TestDeletingGroupWithMembersIsRefusedByDefault: deleting a container must
// never silently delete its contents.
func TestDeletingGroupWithMembersIsRefusedByDefault(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodDelete, fmt.Sprintf("/api/admin/groups/%d", f.group.ID),
		f.ownerTok, "")
	if rec.Code != 409 {
		t.Fatalf("deleting a populated group got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if _, err := f.s.db.UserByID(f.user.ID); err != nil {
		t.Fatal("the member was deleted along with the group")
	}
}

// TestDeletingGroupNeverDeletesUsers, whichever disposition is chosen.
func TestDeletingGroupNeverDeletesUsers(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodDelete,
		fmt.Sprintf("/api/admin/groups/%d?remove_members_from_group=true", f.group.ID),
		f.ownerTok, "")
	if rec.Code != 200 {
		t.Fatalf("explicit delete got %d: %s", rec.Code, rec.Body.String())
	}
	u, err := f.s.db.UserByID(f.user.ID)
	if err != nil {
		t.Fatal("member deleted with the group")
	}
	if u.GroupID != 0 {
		t.Fatalf("member still points at the deleted group: %d", u.GroupID)
	}
}

// TestDeletingGroupCanReassignMembers.
func TestDeletingGroupCanReassignMembers(t *testing.T) {
	f := newUGFixture(t)
	other := &store.Group{Name: "g2"}
	if err := f.s.db.CreateGroup(other); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, http.MethodDelete,
		fmt.Sprintf("/api/admin/groups/%d?reassign_to=%d", f.group.ID, other.ID),
		f.ownerTok, "")
	if rec.Code != 200 {
		t.Fatalf("reassigning delete got %d: %s", rec.Code, rec.Body.String())
	}
	u, _ := f.s.db.UserByID(f.user.ID)
	if u.GroupID != other.ID {
		t.Fatalf("member was not reassigned: group %d", u.GroupID)
	}
}

// --- §3 no silent group assignment ----------------------------------------

// TestDefaultGroupIsAtMostOne keeps the "default" flag coherent.
func TestDefaultGroupIsAtMostOne(t *testing.T) {
	f := newUGFixture(t)
	g2 := &store.Group{Name: "g2"}
	if err := f.s.db.CreateGroup(g2); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.SetDefaultGroup(f.group.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.db.SetDefaultGroup(g2.ID); err != nil {
		t.Fatal(err)
	}
	groups, _ := f.s.db.ListGroups()
	n := 0
	for _, g := range groups {
		if g.IsDefault {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d groups marked default, want exactly 1", n)
	}
	if d := f.s.db.DefaultGroup(); d == nil || d.ID != g2.ID {
		t.Fatalf("DefaultGroup returned %+v, want g2", d)
	}
}

// TestUserCreationDoesNotInventAGroup: creating a user without naming a group
// must leave them with none, not silently manufacture or attach one.
func TestUserCreationDoesNotInventAGroup(t *testing.T) {
	f := newUGFixture(t)
	before, _ := f.s.db.ListGroups()

	u := &store.User{Username: "nogroup", Status: store.StatusActive, SubToken: "tok-ng"}
	if err := f.s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	got, _ := f.s.db.UserByID(u.ID)
	if got.GroupID != 0 {
		t.Fatalf("a group was assigned without being asked for: %d", got.GroupID)
	}
	after, _ := f.s.db.ListGroups()
	if len(after) != len(before) {
		t.Fatalf("a group was created as a side effect: %d -> %d", len(before), len(after))
	}
}

// --- §1 status indicator --------------------------------------------------

// TestHealthDetailExplainsEverySubsystem: the old indicator was a bare coloured
// dot. Every state must now carry text an operator can act on.
func TestHealthDetailExplainsEverySubsystem(t *testing.T) {
	f := newUGFixture(t)
	rec := f.do(t, http.MethodGet, "/api/admin/health/detail", f.ownerTok, "")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var rep HealthReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Label == "" || rep.Summary == "" {
		t.Fatal("overall health has no human-readable text")
	}
	want := map[string]bool{"api": true, "database": true, "engine": true,
		"nodes": true, "certificates": true, "forgedns": true}
	for _, sub := range rep.Subsystems {
		delete(want, sub.Key)
		if sub.Label == "" {
			t.Errorf("%s: no label", sub.Key)
		}
		if sub.Summary == "" {
			t.Errorf("%s: no summary — colour would be the only signal", sub.Key)
		}
		if sub.State == "" {
			t.Errorf("%s: no state", sub.Key)
		}
	}
	if len(want) > 0 {
		t.Fatalf("subsystems missing from the report: %v", want)
	}
}

// TestMissingEngineIsNotAFault: light-server mode is a supported deployment, so
// it must not light up red.
func TestMissingEngineIsNotAFault(t *testing.T) {
	f := newUGFixture(t) // dbServerT leaves engine nil
	rep := f.s.healthReport()
	for _, sub := range rep.Subsystems {
		if sub.Key != "engine" {
			continue
		}
		if sub.State == HealthCritical || sub.State == HealthWarning {
			t.Fatalf("light-server mode reported as %s: %s", sub.State, sub.Summary)
		}
		if sub.State != HealthNotConfigured {
			t.Fatalf("engine state = %s, want not_configured", sub.State)
		}
		return
	}
	t.Fatal("no engine subsystem in the report")
}

// TestUnknownStateIsNotReportedAsCritical guards the "no red for unknown" rule.
func TestUnknownStateIsNotReportedAsCritical(t *testing.T) {
	f := newUGFixture(t)
	rep := f.s.healthReport()
	if rep.State == HealthCritical {
		t.Fatalf("a freshly configured panel reports critical: %s", rep.Summary)
	}
}

var _ = auth.ClaimsFrom

// TestUserListExposesLastSeen: the online indicator reads last_seen_at off the
// user list, so the field must survive the API's JSON serialization (present as
// a key, and carrying the stamped time once the poll cycle has seen the user).
func TestUserListExposesLastSeen(t *testing.T) {
	f := newUGFixture(t)

	// Before any traffic: the key is present and null.
	rec := f.do(t, http.MethodGet, "/api/admin/users", f.ownerTok, "")
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "\"last_seen_at\"") {
		t.Fatalf("user list is missing the last_seen_at field: %s", rec.Body)
	}

	// Stamp it as the poll cycle would, then confirm it round-trips.
	u, _ := f.s.db.UserByID(f.user.ID)
	now := time.Now().UTC().Truncate(time.Second)
	u.LastSeenAt = &now
	if err := f.s.db.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	rec = f.do(t, http.MethodGet, "/api/admin/users", f.ownerTok, "")
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) == 0 || list[0]["last_seen_at"] == nil {
		t.Fatalf("last_seen_at did not round-trip through the API: %s", rec.Body)
	}
}

// TestIPHeldUserExcludedFromEngine is the enforcement half of the concurrent-
// address limit. store.User.IPLimit was stored and editable from the day it was
// added and NOTHING read it: an operator could cap an account at two devices,
// the panel would accept the number, and the account stayed unlimited. Holding a
// user in the database is worthless if their credential is still materialized —
// the core would keep serving them regardless.
func TestIPHeldUserExcludedFromEngine(t *testing.T) {
	f := newUGFixture(t)
	body := fmt.Sprintf(`{"inbound_ids":[%d]}`, f.inFree)
	f.do(t, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", f.user.ID),
		f.ownerTok, body)

	present := func() bool {
		for _, sp := range f.s.enabledInboundSpecs() {
			for _, cl := range sp.Clients {
				if cl.Email == job.UserEmail(f.user.ID) {
					return true
				}
			}
		}
		return false
	}
	if !present() {
		t.Fatal("setup: an active assigned user should be a client on the inbound")
	}

	until := time.Now().Add(5 * time.Minute)
	if err := f.s.db.UpdateUserFields(f.user.ID, map[string]any{"ip_limited_until": until}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if present() {
		t.Fatal("a user held for exceeding their address limit is still materialized into the engine config; the limit does nothing")
	}

	// The hold is transient and self-clearing: a PAST timestamp must serve
	// again, or a user would stay locked out until something else noticed.
	past := time.Now().Add(-time.Minute)
	if err := f.s.db.UpdateUserFields(f.user.ID, map[string]any{"ip_limited_until": past}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !present() {
		t.Fatal("an expired hold still excludes the user; the cooldown would never end")
	}

	// The user's real Status must be untouched throughout. Folding the hold into
	// Status would overwrite why the account is in whatever state it is in, and
	// leave it wrong once the cooldown lifted.
	got, err := f.s.db.UserByID(f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusActive {
		t.Errorf("status = %q, want active — an IP hold must not overwrite the account's real state", got.Status)
	}
}
