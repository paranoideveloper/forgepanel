package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

func subGetAccept(t *testing.T, s *Server, path, ua, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func TestBrowserGetsSubscriptionLandingPage(t *testing.T) {
	s, tok := subServer(t)
	rec := subGetAccept(t, s, "/sub/"+tok, chromeUA, "text/html,application/xhtml+xml")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("browser did not get HTML: Content-Type=%q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"ForgePanel", "Import", "Copy link", "clash://install-config", "sing-box://import-remote-profile", "/sub/" + tok + "/clash"} {
		if !strings.Contains(body, want) {
			t.Fatalf("landing page missing %q", want)
		}
	}
}

func TestProxyClientDoesNotGetLandingPage(t *testing.T) {
	s, tok := subServer(t)
	// A sing-box client (even with an Accept) must get its JSON config, never HTML.
	rec := subGetAccept(t, s, "/sub/"+tok, "sing-box/1.13.15", "text/html")
	if strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal("a sing-box client wrongly got the HTML landing page")
	}
	// A bare curl (no text/html Accept) gets the base64 sub, not HTML.
	rec2 := subGetAccept(t, s, "/sub/"+tok, chromeUA, "*/*")
	if strings.Contains(rec2.Header().Get("Content-Type"), "text/html") {
		t.Fatal("a non-html Accept wrongly got the HTML landing page")
	}
}

func TestRawQueryOptsOutOfLandingPage(t *testing.T) {
	s, tok := subServer(t)
	rec := subGetAccept(t, s, "/sub/"+tok+"?raw=1", chromeUA, "text/html")
	if strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal("?raw=1 should bypass the landing page")
	}
}

func TestParseUserinfoAndHumanBytes(t *testing.T) {
	used, total, expire := parseUserinfo("upload=0; download=1048576; total=2097152; expire=1000")
	if used != 1048576 || total != 2097152 || expire != 1000 {
		t.Fatalf("parseUserinfo wrong: %d %d %d", used, total, expire)
	}
	if humanBytes(1048576) != "1.0 MB" {
		t.Fatalf("humanBytes wrong: %q", humanBytes(1048576))
	}
}
