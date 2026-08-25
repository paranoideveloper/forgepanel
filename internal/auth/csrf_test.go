package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The token used to be accepted from a "token" COOKIE as well as the
// Authorization header. Nothing in the panel ever set that cookie — the frontend
// uses localStorage and a header — so the branch was dead for the shipped UI and
// live for anyone who set it themselves.
//
// That was the entire CSRF surface. A browser attaches cookies to cross-site
// requests automatically, so any page on the internet could have made a
// state-changing request to the panel and had the browser authenticate it. An
// Authorization header cannot be set cross-site, so the header path is immune by
// construction.

func protectedRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s := NewSigner([]byte("test-secret"))
	tok, _, err := s.Issue(1, "owner", "owner")
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/protected", s.Middleware(), func(c *gin.Context) { c.String(200, "ok") })
	return r, tok
}

func TestATokenCookieIsNotAccepted(t *testing.T) {
	r, tok := protectedRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tok})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// A VALID token in a cookie must still be refused. The token being genuine is
	// exactly the CSRF scenario: the victim is signed in, and the browser sends
	// their credential on a request the attacker's page made.
	if w.Code != 401 {
		t.Fatalf("a request authenticated only by a cookie returned %d, want 401 — "+
			"cookie auth is a CSRF surface because browsers send it cross-site", w.Code)
	}
}

func TestTheAuthorizationHeaderStillWorks(t *testing.T) {
	r, tok := protectedRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("the header path returned %d, want 200 — removing the cookie fallback "+
			"must not break the way the panel actually authenticates", w.Code)
	}
}

func TestAHeaderBeatsAStaleCookie(t *testing.T) {
	r, tok := protectedRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "token", Value: "garbage"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// A cookie left over from anything must not be able to override or poison a
	// legitimate header.
	if w.Code != 200 {
		t.Fatalf("a stray cookie broke header authentication: %d", w.Code)
	}
}
