package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewPKCE(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7636 requires a verifier of at least 43 characters.
	if len(p.Verifier) < 43 {
		t.Fatalf("verifier is %d characters, below the 43 minimum", len(p.Verifier))
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); p.Challenge != want {
		t.Fatalf("challenge is not S256 over the verifier")
	}
	if p.State == "" {
		t.Fatal("no state was generated; the callback could not be bound to this attempt")
	}
	other, _ := NewPKCE()
	if other.Verifier == p.Verifier || other.State == p.State {
		t.Fatal("two attempts produced identical material")
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	o := &OAuth{}
	p := &PKCE{Verifier: "v", Challenge: "c", State: "s"}
	raw := o.BuildAuthorizeURL(p, "http://localhost:1234/oauth/callback")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != OAuthAuthorizeURL {
		t.Errorf("authorize endpoint = %q", raw)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": OAuthClientID, "state": "s",
		"code_challenge": "c", "code_challenge_method": "S256",
		"redirect_uri": "http://localhost:1234/oauth/callback",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	scopes := strings.Fields(q.Get("scope"))
	needed := map[string]bool{"workers_scripts:write": false, "workers_kv:write": false, "offline_access": false}
	for _, s := range scopes {
		if _, ok := needed[s]; ok {
			needed[s] = true
		}
	}
	for s, seen := range needed {
		if !seen {
			t.Errorf("scope %q is missing; deploy would fail at the first upload", s)
		}
	}
}

// oauthServer replays Cloudflare's token endpoint, verifying PKCE properly.
func oauthServer(t *testing.T, verifierWant *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		if form.Get("grant_type") == "refresh_token" {
			if form.Get("refresh_token") != "refresh-1" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"unknown refresh token"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at-2","refresh_token":"refresh-2","expires_in":3600,"token_type":"bearer"}`))
			return
		}
		if verifierWant != nil && form.Get("code_verifier") != *verifierWant {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code_verifier mismatch"}`))
			return
		}
		if form.Get("code") != "the-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad code"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1","refresh_token":"refresh-1","expires_in":3600,"token_type":"bearer"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOAuth_FullFlow(t *testing.T) {
	srv := oauthServer(t, nil)
	var out bytes.Buffer
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 10 * time.Second}
	// The browser is replaced by a direct GET at the callback listener.
	o.OpenBrowser = func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		q := u.Query()
		cb, _ := url.Parse(q.Get("redirect_uri"))
		go func() {
			resp, err := http.Get(cb.String() + "?state=" + url.QueryEscape(q.Get("state")) + "&code=the-code")
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	ts, err := o.Authorize(context.Background())
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if ts.AccessToken != "at-1" || ts.RefreshToken != "refresh-1" {
		t.Fatalf("token set = %+v", ts)
	}
	if ts.ExpiresAt == "" {
		t.Error("expires_at must be computed on receipt")
	}
	// The URL is always printed: headless boxes and Termux have no browser.
	if !strings.Contains(out.String(), "Open this URL") {
		t.Errorf("the authorisation URL was not printed: %q", out.String())
	}
}

func TestOAuth_RejectsMismatchedState(t *testing.T) {
	srv := oauthServer(t, nil)
	var out bytes.Buffer
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 5 * time.Second}
	o.OpenBrowser = func(raw string) error {
		u, _ := url.Parse(raw)
		cb, _ := url.Parse(u.Query().Get("redirect_uri"))
		go func() {
			// A callback from some other flow, carrying a code that is not ours.
			resp, err := http.Get(cb.String() + "?state=someone-elses-state&code=stolen-code")
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	_, err := o.Authorize(context.Background())
	if err == nil {
		t.Fatal("a mismatched state must abort before the code is used")
	}
	e, ok := AsError(err)
	if !ok || e.Kind != KindAuth || !strings.Contains(e.Message, "state") {
		t.Fatalf("want a state-mismatch auth error, got %v", err)
	}
}

func TestOAuth_CallbackErrorAndMissingCode(t *testing.T) {
	cases := []struct {
		name  string
		query func(state string) string
		want  string
	}{
		{"provider error", func(s string) string {
			return "?state=" + url.QueryEscape(s) + "&error=access_denied&error_description=user+said+no"
		}, "access_denied"},
		{"no code", func(s string) string { return "?state=" + url.QueryEscape(s) }, "no authorisation code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := oauthServer(t, nil)
			var out bytes.Buffer
			o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 5 * time.Second}
			o.OpenBrowser = func(raw string) error {
				u, _ := url.Parse(raw)
				cb, _ := url.Parse(u.Query().Get("redirect_uri"))
				state := u.Query().Get("state")
				go func() {
					resp, err := http.Get(cb.String() + tc.query(state))
					if err == nil {
						resp.Body.Close()
					}
				}()
				return nil
			}
			_, err := o.Authorize(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestOAuth_VerifierIsSentAndChecked(t *testing.T) {
	var captured string
	srv := oauthServer(t, &captured)
	p, _ := NewPKCE()
	captured = p.Verifier
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client()}
	ts, err := o.Exchange(context.Background(), "the-code", p.Verifier, "http://localhost/cb")
	if err != nil {
		t.Fatalf("Exchange with the right verifier: %v", err)
	}
	if ts.AccessToken != "at-1" {
		t.Fatalf("token = %+v", ts)
	}
	if _, err := o.Exchange(context.Background(), "the-code", "a-different-verifier", "http://localhost/cb"); err == nil {
		t.Fatal("the token endpoint must reject a verifier that does not match the challenge")
	}
}

func TestOAuth_Refresh(t *testing.T) {
	srv := oauthServer(t, nil)
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client()}
	ts, err := o.Refresh(context.Background(), "refresh-1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if ts.AccessToken != "at-2" || ts.RefreshToken != "refresh-2" {
		t.Fatalf("refreshed set = %+v", ts)
	}
	if _, err := o.Refresh(context.Background(), "stale"); err == nil {
		t.Fatal("a stale refresh token must be rejected")
	} else if e, _ := AsError(err); e == nil || e.Kind != KindAuth {
		t.Fatalf("want an auth failure, got %v", err)
	}
}

func TestOAuth_TokenEndpointReturnsNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
	}))
	defer srv.Close()
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client()}
	if _, err := o.Exchange(context.Background(), "c", "v", "http://localhost/cb"); err == nil {
		t.Fatal("an empty access token must not be accepted as success")
	}
}

func TestOAuth_TimesOutWithoutACallback(t *testing.T) {
	srv := oauthServer(t, nil)
	var out bytes.Buffer
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 60 * time.Millisecond,
		OpenBrowser: func(string) error { return nil }}
	_, err := o.Authorize(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no OAuth callback arrived") {
		t.Fatalf("want a timeout, got %v", err)
	}
}

func TestOAuth_BrowserFailureIsNotFatal(t *testing.T) {
	srv := oauthServer(t, nil)
	var out bytes.Buffer
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 60 * time.Millisecond,
		OpenBrowser: func(string) error { return errUpload("no browser here") }}
	_, _ = o.Authorize(context.Background())
	if !strings.Contains(out.String(), "open the URL above by hand") {
		t.Fatalf("a headless box must be told to open the URL itself: %q", out.String())
	}
}

func TestTokenStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "edge-token.json")

	if _, err := LoadToken(path); !IsNotFound(err) {
		t.Fatalf("a missing token file means 'not authorised yet', got %v", err)
	}

	ts := &TokenSet{AccessToken: "at", RefreshToken: "rt", AccountID: "acct-1",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := SaveToken(path, ts); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A refresh token is a live Cloudflare credential; it must not be readable
	// by anyone else on the box.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file mode is %o, want 0600", perm)
	}
	back, err := LoadToken(path)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if back.AccessToken != "at" || back.RefreshToken != "rt" || back.AccountID != "acct-1" {
		t.Fatalf("round trip = %+v", back)
	}

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(path); err == nil {
		t.Fatal("a corrupt token file must be reported, not silently ignored")
	}
}

func TestTokenSet_Expired(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		ts   *TokenSet
		want bool
	}{
		{"nil", nil, false},
		{"no expiry", &TokenSet{}, false},
		{"unparseable", &TokenSet{ExpiresAt: "soon"}, false},
		{"future", &TokenSet{ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}, false},
		{"past", &TokenSet{ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}, true},
		{"inside the slack window", &TokenSet{ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339)}, true},
	}
	for _, tc := range cases {
		if got := tc.ts.Expired(now); got != tc.want {
			t.Errorf("%s: Expired = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestTokenPath(t *testing.T) {
	p := TokenPath()
	if !strings.HasSuffix(p, filepath.Join("forgepanel", "edge-token.json")) {
		t.Fatalf("TokenPath = %q", p)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("TokenPath must be absolute, got %q", p)
	}
}

func TestOAuthDefaults(t *testing.T) {
	o := &OAuth{}
	if o.clientID() != OAuthClientID || o.authorizeURL() != OAuthAuthorizeURL || o.tokenURL() != OAuthTokenURL {
		t.Error("the zero OAuth must fall back to Cloudflare's real endpoints")
	}
	if len(o.scopes()) != len(OAuthScopes) || o.httpClient() == nil || o.out() == nil {
		t.Error("zero-value defaults are incomplete")
	}
	custom := &OAuth{ClientID: "c", Scopes: []string{"a"}}
	if custom.clientID() != "c" || len(custom.scopes()) != 1 {
		t.Error("explicit values must win over the defaults")
	}
}

func TestOpenBrowser_MissingOpenerIsAnError(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no xdg-open/open/rundll32 anywhere
	if err := OpenBrowser("https://example.invalid"); err == nil {
		t.Fatal("with no opener installed this must report a failure, so the caller prints the URL instead")
	}
}

func TestOAuth_ExchangeUnreachableEndpoint(t *testing.T) {
	o := &OAuth{TokenURL: "http://127.0.0.1:1/token", HTTP: &http.Client{Timeout: time.Second}}
	_, err := o.Exchange(context.Background(), "c", "v", "http://localhost/cb")
	if e, ok := AsError(err); !ok || e.Kind != KindNetwork {
		t.Fatalf("want a network error, got %v", err)
	}
}

func TestOAuth_ExchangeUndecodableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>proxy</html>"))
	}))
	defer srv.Close()
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client()}
	if _, err := o.Exchange(context.Background(), "c", "v", "http://localhost/cb"); err == nil {
		t.Fatal("a non-JSON token response must not be read as success")
	}
}

func TestOAuth_CancelledContext(t *testing.T) {
	srv := oauthServer(t, nil)
	c, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	o := &OAuth{TokenURL: srv.URL, HTTP: srv.Client(), Out: &out, Timeout: 10 * time.Second,
		OpenBrowser: func(string) error { cancel(); return nil }}
	if _, err := o.Authorize(c); err == nil {
		t.Fatal("a cancelled context must abort the wait")
	}
}

// TestTokenSet_JSONShape guards the on-disk format so an upgrade does not
// silently orphan an operator's stored authorisation.
func TestTokenSet_JSONShape(t *testing.T) {
	raw, err := json.Marshal(&TokenSet{AccessToken: "a", RefreshToken: "r", AccountID: "acct"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"access_token"`, `"refresh_token"`, `"account_id"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("stored token is missing %s: %s", key, raw)
		}
	}
}
