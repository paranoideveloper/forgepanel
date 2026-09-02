package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Cloudflare's OAuth + PKCE flow, the default credential path for
// `forgectl edge` (FORGECTL_EDGE_SPEC.md, credential policy). No long-lived
// secret is written into the Worker: the token is issued to the operator's own
// machine and stays there.

const (
	// OAuthClientID is Wrangler's public OAuth client. It is public by design —
	// PKCE is what binds the authorisation to this process, not a client secret.
	OAuthClientID = "54d11594-84e4-41aa-b438-e81b8fa78ee7"
	// OAuthAuthorizeURL is Cloudflare's authorisation endpoint.
	OAuthAuthorizeURL = "https://dash.cloudflare.com/oauth2/auth"
	// OAuthTokenURL is Cloudflare's token endpoint.
	OAuthTokenURL = "https://dash.cloudflare.com/oauth2/token"
)

// OAuthScopes are exactly the permissions `forgectl edge` uses. offline_access
// is what makes a refresh token available, so a later `edge update` does not
// need another browser round trip.
var OAuthScopes = []string{
	"account:read", "user:read", "workers:write", "workers_kv:write",
	"workers_scripts:write", "d1:write", "pages:write", "pages:read",
	"zone:read", "offline_access",
}

// OAuth drives the PKCE flow. Every field has a working default, and the URL
// and HTTP client are injectable so the flow can be exercised end to end
// against an httptest server.
type OAuth struct {
	ClientID     string
	AuthorizeURL string
	TokenURL     string
	Scopes       []string
	HTTP         *http.Client
	// Out receives the "open this URL" line. Always printed: headless boxes and
	// Termux have no browser to launch.
	Out io.Writer
	// OpenBrowser launches the operator's browser. Nil uses the platform opener;
	// tests replace it to drive the callback themselves.
	OpenBrowser func(url string) error
	// Timeout bounds how long the callback listener waits. Zero means 5 minutes.
	Timeout time.Duration
}

func (o *OAuth) clientID() string {
	if o.ClientID != "" {
		return o.ClientID
	}
	return OAuthClientID
}

func (o *OAuth) authorizeURL() string {
	if o.AuthorizeURL != "" {
		return o.AuthorizeURL
	}
	return OAuthAuthorizeURL
}

func (o *OAuth) tokenURL() string {
	if o.TokenURL != "" {
		return o.TokenURL
	}
	return OAuthTokenURL
}

func (o *OAuth) scopes() []string {
	if len(o.Scopes) > 0 {
		return o.Scopes
	}
	return OAuthScopes
}

func (o *OAuth) httpClient() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return netegress.Client(30 * time.Second)
}

func (o *OAuth) out() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stdout
}

// PKCE is one authorisation attempt's proof material.
type PKCE struct {
	Verifier  string
	Challenge string
	State     string
}

// NewPKCE mints a verifier (33 random bytes → 44 base64url chars, over the
// 43-char minimum), its S256 challenge, and an unguessable state.
func NewPKCE() (*PKCE, error) {
	verifier, err := randomB64(33)
	if err != nil {
		return nil, err
	}
	state, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return &PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		State:     state,
	}, nil
}

func randomB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", &Error{Op: "oauth", Kind: KindServer,
			Message: "no entropy available: " + err.Error(), Cause: err}
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// TokenSet is the result of an authorisation.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	// ExpiresAt is computed on receipt so a stored token can be judged stale
	// without re-deriving it from a request time nobody recorded.
	ExpiresAt string `json:"expires_at,omitempty"`
	// AccountID is filled in by the caller once resolved.
	AccountID string `json:"account_id,omitempty"`
}

// Expired reports whether the access token is past its life (with a minute of
// slack). A token set with no expiry is treated as live.
func (t *TokenSet) Expired(now time.Time) bool {
	if t == nil || t.ExpiresAt == "" {
		return false
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Add(time.Minute).After(exp)
}

// BuildAuthorizeURL assembles the authorisation URL for this attempt.
func (o *OAuth) BuildAuthorizeURL(p *PKCE, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.clientID())
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(o.scopes(), " "))
	q.Set("state", p.State)
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", "S256")
	return o.authorizeURL() + "?" + q.Encode()
}

// Authorize runs the whole flow: bind an ephemeral loopback listener, print
// (and try to open) the authorisation URL, wait for the callback, verify the
// state, and exchange the code.
func (o *OAuth) Authorize(ctx context.Context) (*TokenSet, error) {
	p, err := NewPKCE()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, &Error{Op: "oauth", Kind: KindNetwork,
			Message:     "could not bind a loopback listener for the OAuth callback: " + err.Error(),
			Remediation: "this flow needs to listen on 127.0.0.1; on a locked-down host use --api-token instead.",
			Cause:       err}
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://localhost:%d/oauth/callback", ln.Addr().(*net.TCPAddr).Port)
	authURL := o.BuildAuthorizeURL(p, redirect)

	fmt.Fprintf(o.out(), "Open this URL to authorise ForgePanel with Cloudflare:\n\n  %s\n\n", authURL)
	open := o.OpenBrowser
	if open == nil {
		open = OpenBrowser
	}
	if err := open(authURL); err != nil {
		fmt.Fprintf(o.out(), "(could not launch a browser automatically: %v — open the URL above by hand)\n", err)
	}

	code, err := o.waitForCode(ctx, ln, p.State)
	if err != nil {
		return nil, err
	}
	return o.Exchange(ctx, code, p.Verifier, redirect)
}

// waitForCode serves the single callback request.
func (o *OAuth) waitForCode(ctx context.Context, ln net.Listener, state string) (string, error) {
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// The state is checked BEFORE the code is read: a mismatch means this
		// callback belongs to some other flow, and its code is not ours to use.
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch — this callback did not come from the authorisation this process started", http.StatusBadRequest)
			done <- result{err: &Error{Op: "oauth-callback", Kind: KindAuth,
				Message:     "the OAuth callback carried a state that does not match this attempt",
				Remediation: "start the flow again and complete it in the browser window it opens; do not reuse an old authorisation link."}}
			return
		}
		if e := q.Get("error"); e != "" {
			desc := q.Get("error_description")
			http.Error(w, "authorisation failed: "+e, http.StatusBadRequest)
			done <- result{err: &Error{Op: "oauth-callback", Kind: KindAuth,
				Message: strings.TrimSpace(e + " " + desc)}}
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code in the callback", http.StatusBadRequest)
			done <- result{err: &Error{Op: "oauth-callback", Kind: KindAuth,
				Message: "the OAuth callback carried no authorisation code"}}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, callbackPage)
		done <- result{code: code}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	select {
	case r := <-done:
		return r.code, r.err
	case <-time.After(timeout):
		return "", &Error{Op: "oauth-callback", Kind: KindAuth,
			Message:     fmt.Sprintf("no OAuth callback arrived within %s", timeout),
			Remediation: "complete the authorisation in the browser, or use --api-token on a machine without one."}
	case <-ctx.Done():
		return "", &Error{Op: "oauth-callback", Kind: KindAuth, Message: ctx.Err().Error(), Cause: ctx.Err()}
	}
}

const callbackPage = `<!doctype html><meta charset="utf-8"><title>ForgePanel</title>
<body style="background:#0b0f17;color:#e5e7eb;font-family:system-ui;padding:3rem">
<h1>Authorised</h1><p>You can close this tab and return to the terminal.</p></body>`

// Exchange swaps an authorisation code for a token set.
func (o *OAuth) Exchange(ctx context.Context, code, verifier, redirectURI string) (*TokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", o.clientID())
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return o.postToken(ctx, form, "oauth-exchange")
}

// Refresh renews an access token from a stored refresh token.
func (o *OAuth) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", o.clientID())
	return o.postToken(ctx, form, "oauth-refresh")
}

func (o *OAuth) postToken(ctx context.Context, form url.Values, op string) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &Error{Op: op, Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, &Error{Op: op, Kind: KindNetwork,
			Message: "could not reach the Cloudflare token endpoint: " + err.Error(), Cause: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Error + " " + e.Description)
		if msg == "" {
			msg = truncate(string(raw), 200)
		}
		return nil, &Error{Op: op, Kind: KindAuth, Status: resp.StatusCode, Message: msg,
			Remediation: "the authorisation was rejected. Re-run the command to start a fresh flow; if it keeps failing, use --api-token."}
	}
	var ts TokenSet
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, decodeError(op, err)
	}
	if ts.AccessToken == "" {
		return nil, &Error{Op: op, Kind: KindAuth,
			Message: "the token endpoint returned no access token"}
	}
	if ts.ExpiresIn > 0 {
		ts.ExpiresAt = time.Now().Add(time.Duration(ts.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	return &ts, nil
}

// --- token storage ----------------------------------------------------------

// TokenPath is where a refresh token is kept.
//
// There is no OS keyring integration here, and pretending otherwise would be
// worse than saying so: the file is written at 0600 under the operator's config
// directory, and `forgectl edge` prints that path when it stores one.
func TokenPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "forgepanel", "edge-token.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "forgepanel", "edge-token.json")
}

// SaveToken writes a token set at 0600, creating the directory if needed.
func SaveToken(path string, ts *TokenSet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &Error{Op: "save-token", Kind: KindServer, Message: err.Error(), Cause: err}
	}
	raw, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return &Error{Op: "save-token", Kind: KindServer, Message: err.Error(), Cause: err}
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		return &Error{Op: "save-token", Kind: KindServer, Message: err.Error(), Cause: err}
	}
	return nil
}

// LoadToken reads a stored token set. A missing file is a KindNotFound error,
// which callers treat as "not authorised yet".
func LoadToken(path string) (*TokenSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &Error{Op: "load-token", Kind: KindNotFound,
				Message:     "no stored Cloudflare authorisation at " + path,
				Remediation: "run `forgectl edge deploy` to authorise, or pass --api-token."}
		}
		return nil, &Error{Op: "load-token", Kind: KindServer, Message: err.Error(), Cause: err}
	}
	var ts TokenSet
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, &Error{Op: "load-token", Kind: KindValidation,
			Message:     "the stored authorisation at " + path + " is not valid JSON",
			Remediation: "delete the file and re-run `forgectl edge deploy`.", Cause: err}
	}
	return &ts, nil
}

// OpenBrowser launches the platform's URL opener. A failure is never fatal —
// the URL is always printed first.
func OpenBrowser(target string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	path, err := exec.LookPath(cmd)
	if err != nil {
		return fmt.Errorf("%s is not installed", cmd)
	}
	return exec.Command(path, append(args, target)...).Start()
}
