package api

// Tests for admin-API authorization.
//
// The point of these tests is not to prove the policy table is *nice* — it is
// to make an unguarded admin route impossible to ship. TestAuthzEveryAdminRoute
// HasAPolicy walks the real router, so adding a route without classifying it
// fails the build rather than quietly exposing owner powers to a viewer.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/gin-gonic/gin"
)

// adminRoutes returns every registered /api/admin route from a fully wired
// router, so the tests below assert against reality rather than a hand-kept list.
func adminRoutes(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := dbServerT(t)
	s.routes()
	var out []gin.RouteInfo
	for _, r := range s.router.Routes() {
		if strings.HasPrefix(r.Path, "/api/admin") {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatal("no /api/admin routes registered — the harness is wrong, not the policy")
	}
	return out
}

func allows(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// Every admin route must resolve to an explicit, non-empty role set. A route
// that resolves to nothing is denied at runtime, which is safe, but it is also
// a sign someone added an endpoint without deciding who may call it.
func TestAuthzEveryAdminRouteHasAPolicy(t *testing.T) {
	for _, r := range adminRoutes(t) {
		roles := rolesForRoute(r.Method, r.Path)
		if len(roles) == 0 {
			t.Errorf("%s %s has NO authorisation policy (would be denied)", r.Method, r.Path)
		}
	}
}

// A viewer is read-only. No viewer token may reach a mutating verb anywhere in
// the admin API, with the single deliberate exception of self-service routes
// (your own password, your own 2FA) — denying those would be its own problem.
func TestAuthzViewerCannotMutate(t *testing.T) {
	selfService := []string{"/api/admin/2fa", "/api/admin/change-password"}
	for _, r := range adminRoutes(t) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		isSelf := false
		for _, p := range selfService {
			if strings.HasPrefix(r.Path, p) {
				isSelf = true
			}
		}
		if isSelf {
			continue
		}
		if allows(rolesForRoute(r.Method, r.Path), string(store.RoleViewer)) {
			t.Errorf("viewer may mutate %s %s — viewer must be read-only", r.Method, r.Path)
		}
	}
}

// A reseller manages customers, not infrastructure. They must never be able to
// reconfigure the serving plane, the panel itself, or the edge.
func TestAuthzResellerCannotTouchInfrastructure(t *testing.T) {
	infra := []string{
		"/api/admin/inbounds", "/api/admin/engines", "/api/admin/nodes",
		"/api/admin/domains", "/api/admin/forgedns", "/api/admin/dns",
		"/api/admin/edge", "/api/admin/panel-address", "/api/admin/certs",
		"/api/admin/settings", "/api/admin/wizard", "/api/admin/deploy",
	}
	for _, r := range adminRoutes(t) {
		hit := false
		for _, p := range infra {
			if strings.HasPrefix(r.Path, p) {
				hit = true
			}
		}
		// Listing inventory read-only is fine (a reseller must see which
		// inbounds exist to assign them); mutating it is not.
		if !hit || r.Method == http.MethodGet || r.Method == http.MethodHead {
			continue
		}
		if allows(rolesForRoute(r.Method, r.Path), string(store.RoleReseller)) {
			t.Errorf("reseller may mutate infrastructure %s %s", r.Method, r.Path)
		}
	}
}

// Endpoints that hand back key material, tokens or ready-to-use client bundles
// must be owner/admin only. A "read-only" role that can read private keys is
// not read-only.
func TestAuthzSensitiveReadsAreRestricted(t *testing.T) {
	sensitive := []struct{ method, path string }{
		{http.MethodGet, "/api/admin/inbounds/:id/config"},
		{http.MethodGet, "/api/admin/engines/config"},
		{http.MethodGet, "/api/admin/forgedns/zones/:id/bundle"},
		{http.MethodGet, "/api/admin/forgedns/zones/:id/client"},
		{http.MethodGet, "/api/admin/forgedns/zones/:id/config"},
		{http.MethodGet, "/api/admin/edge/feed-token"},
		{http.MethodGet, "/api/admin/dns/credentials"},
		{http.MethodGet, "/api/admin/openapi.json"},
	}
	for _, s := range sensitive {
		roles := rolesForRoute(s.method, s.path)
		if len(roles) == 0 {
			t.Errorf("%s %s resolves to no policy", s.method, s.path)
			continue
		}
		for _, bad := range []string{string(store.RoleViewer), string(store.RoleReseller)} {
			if allows(roles, bad) {
				t.Errorf("%s %s exposes credentials to %s (allowed=%v)", s.method, s.path, bad, roles)
			}
		}
	}
}

// Panel-level reconfiguration is owner-only: an admin who manages proxy users
// should not be able to move the panel's address or import its certificate.
func TestAuthzPanelConfigIsOwnerOnly(t *testing.T) {
	// /api/admin/update stages a panel BINARY: it is the most privileged thing
	// the panel can be told to fetch, and the catch-all at the bottom of the
	// table would silently hand it to a plain admin.
	for _, p := range []string{"/api/admin/panel-address", "/api/admin/certs", "/api/admin/settings/subscription", "/api/admin/update"} {
		roles := rolesForRoute(http.MethodPost, p)
		if len(roles) != 1 || roles[0] != string(store.RoleOwner) {
			t.Errorf("POST %s should be owner-only, got %v", p, roles)
		}
	}
}

// End-to-end through the real middleware chain: a real JWT per role driven at a
// real route, asserting the HTTP outcome rather than just the policy lookup.
func TestAuthzMiddlewareEnforcesOverHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := dbServerT(t)

	r := gin.New()
	grp := r.Group("/api/admin", s.signer.Middleware(), s.authz())
	grp.POST("/inbounds", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	grp.GET("/overview", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	grp.GET("/me", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	token := func(role string) string {
		access, _, err := s.signer.Issue(1, "u", role)
		if err != nil {
			t.Fatalf("issue token for %s: %v", role, err)
		}
		return access
	}
	call := func(method, path, role string) int {
		req := httptest.NewRequest(method, path, nil)
		if role != "" {
			req.Header.Set("Authorization", "Bearer "+token(role))
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// No token at all is still 401 — authorisation did not replace authentication.
	if got := call(http.MethodGet, "/api/admin/overview", ""); got != http.StatusUnauthorized {
		t.Errorf("anonymous overview = %d, want 401", got)
	}
	// The regression this whole file exists for: a viewer creating an inbound.
	if got := call(http.MethodPost, "/api/admin/inbounds", string(store.RoleViewer)); got != http.StatusForbidden {
		t.Errorf("viewer POST /inbounds = %d, want 403", got)
	}
	if got := call(http.MethodPost, "/api/admin/inbounds", string(store.RoleReseller)); got != http.StatusForbidden {
		t.Errorf("reseller POST /inbounds = %d, want 403", got)
	}
	if got := call(http.MethodPost, "/api/admin/inbounds", string(store.RoleAdmin)); got != http.StatusOK {
		t.Errorf("admin POST /inbounds = %d, want 200", got)
	}
	if got := call(http.MethodPost, "/api/admin/inbounds", string(store.RoleOwner)); got != http.StatusOK {
		t.Errorf("owner POST /inbounds = %d, want 200", got)
	}
	// Read paths a viewer legitimately needs must keep working — over-tightening
	// would break the dashboard and get the guard reverted.
	if got := call(http.MethodGet, "/api/admin/overview", string(store.RoleViewer)); got != http.StatusOK {
		t.Errorf("viewer GET /overview = %d, want 200", got)
	}
	if got := call(http.MethodGet, "/api/admin/me", string(store.RoleViewer)); got != http.StatusOK {
		t.Errorf("viewer GET /me = %d, want 200", got)
	}
	// An unrecognised role is denied rather than defaulted to something useful.
	if got := call(http.MethodGet, "/api/admin/overview", "wizard"); got != http.StatusForbidden {
		t.Errorf("unknown role GET /overview = %d, want 403", got)
	}
}

// Admin provisioning is owner-only. A reseller that can mint another reseller,
// or raise its own quota, is a privilege escalation that looks identical to
// legitimate use in the audit log — and every one of these routes creates,
// re-roles, disables or deletes an account.
func TestAuthzAdminProvisioningIsOwnerOnly(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		roles := rolesForRoute(m, "/api/admin/admins")
		if len(roles) != 1 || roles[0] != string(store.RoleOwner) {
			t.Errorf("%s /api/admin/admins allows %v, want owner only", m, roles)
		}
	}
	for _, m := range []string{http.MethodPatch, http.MethodDelete} {
		roles := rolesForRoute(m, "/api/admin/admins/:id")
		if len(roles) != 1 || roles[0] != string(store.RoleOwner) {
			t.Errorf("%s /api/admin/admins/:id allows %v, want owner only", m, roles)
		}
	}
}
