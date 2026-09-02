package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTheSecretPathActuallyHidesThePanel.
//
// SECURITY.md's claim for the randomized admin path is specific: it "removes
// the panel from the results of untargeted scanners probing /admin, /panel and
// /xui". That was not delivered. NoRoute handed the SPA shell to every unmatched
// path, so /admin, /panel and /panel/<wrong> all answered with the panel —
// observed on a live public install, where /panel/deadbeef1234 returned bytes
// identical to the real /panel/6ba89fe94246/.
func TestTheSecretPathActuallyHidesThePanel(t *testing.T) {
	const secret = "/panel/6ba89fe94246"
	s := dbServerT(t)
	entry := s.assetOr("web/index.html", "<!doctype html><html><body>spa</body></html>")
	s.router.NoRoute(s.serveSPA(entry, secret))

	code := func(p string) int {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec.Code
	}

	// What an untargeted scanner probes.
	for _, p := range []string{"/admin", "/panel", "/xui", "/panel/deadbeef1234", "/wp-login.php"} {
		if got := code(p); got == http.StatusOK {
			t.Errorf("%s returned 200 — the panel is still in the scanner's results", p)
		}
	}

	// The operator's own path, and client-side routes under it, must work.
	if got := code(secret + "/"); got != http.StatusOK {
		t.Errorf("the real admin path returned %d; the panel would be unreachable", got)
	}
	if got := code(secret + "/users"); got != http.StatusOK {
		t.Errorf("a client-side route under the secret path returned %d", got)
	}
	// An /api miss stays a JSON 404 rather than leaking the shell.
	if got := code("/api/nope"); got != http.StatusNotFound {
		t.Errorf("/api miss returned %d", got)
	}
}

// TestWithNoSecretPathEveryRouteStillGetsTheShell: an operator who has not set
// a secret path must not be locked out, so the guard only applies when there is
// something to hide behind.
func TestWithNoSecretPathEveryRouteStillGetsTheShell(t *testing.T) {
	s := dbServerT(t)
	entry := s.assetOr("web/index.html", "<!doctype html><html><body>spa</body></html>")
	s.router.NoRoute(s.serveSPA(entry, ""))

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("with no secret path configured, /anything returned %d, want the shell", rec.Code)
	}
}
