package api

import (
	"io/fs"
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
	entry := s.assetOr("web/index.html", "<!doctype html><html><body>spa</body></html>")
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

// TestSPAAssetsServedUnderSecretPathPrefix is the regression for the blank-panel
// bug: served at /panel/<secret> (no trailing slash), SvelteKit's relative
// "./_app/…" assets resolve to /panel/<secret>/_app/…. Before the fix serveSPA
// only matched the bare /_app/… path, so the prefixed request fell through to the
// SPA shell — the browser then rejected the "script" (text/html) and rendered
// nothing. Assets must be served by their _app/… suffix regardless of prefix.
func TestSPAAssetsServedUnderSecretPathPrefix(t *testing.T) {
	s := dbServerT(t)
	entry := s.assetOr("web/index.html", "<!doctype html><html><body>spa</body></html>")
	s.router.NoRoute(s.serveSPA(entry))

	// Find a real hashed JS asset in the embedded bundle.
	sub, _ := fs.Sub(webFS, "web")
	var asset string
	fs.WalkDir(sub, "_app", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".js") && asset == "" {
			asset = p
		}
		return nil
	})
	if asset == "" {
		t.Skip("no embedded _app JS asset in this build")
	}

	get := func(p string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)
		return rec
	}
	for _, prefix := range []string{"", "/panel/deadbeef", "/panel/deadbeef/subroute"} {
		rec := get(prefix + "/" + asset)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s/%s: want 200, got %d", prefix, asset, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Fatalf("%s/%s: want a javascript content-type, got %q (asset served as the SPA shell → blank panel)", prefix, asset, ct)
		}
		if strings.Contains(rec.Body.String(), "<html") {
			t.Fatalf("%s/%s: asset came back as HTML, not the script", prefix, asset)
		}
	}
}
