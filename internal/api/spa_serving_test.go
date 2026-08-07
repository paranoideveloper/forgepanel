package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSPAAssetsAreServed is the regression for the dead-UI bug: the panel served
// admin.html but every /_app/*.js and *.css it referenced returned 404, so the
// SvelteKit app could never boot. Client-side routes must fall back to the SPA
// entry, and an /api miss must stay a JSON 404 rather than leaking the SPA HTML.
func TestSPAAssetsAreServed(t *testing.T) {
	s := dbServerT(t)
	entry := s.assetOr("web/admin.html", "<!doctype html><html><body>spa</body></html>")
	s.router.NoRoute(s.serveSPA(entry))

	get := func(p string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/api/definitely-missing"); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("/api miss should be JSON 404, got %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("/users"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "html") {
		t.Fatalf("client route should serve the SPA entry HTML, got %d", rec.Code)
	}
}
