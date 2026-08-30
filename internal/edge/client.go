// Package edge is the ForgeEdge control plane on the Go side (§6): the
// Cloudflare Workers API calls that deploy, update and delete an edge, and the
// small client that talks to a deployed Worker's own API.
//
// It is a hand-rolled REST client for the same reason internal/dns is one — no
// vendor SDK, and every failure carries a remediation an operator can act on
// rather than Cloudflare's generic "Unauthorized to access requested resource".
//
// The canonical feed itself lives in internal/api (it is built from the panel
// DB); this package only moves it and manages the Worker that receives it.
package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"net/url"
	"strings"
	"time"
)

// APIBase is the production Cloudflare API root. Tests point a client at an
// httptest server by setting Client.BaseURL.
const APIBase = "https://api.cloudflare.com/client/v4"

// Token scopes, spelled as Cloudflare's token editor labels them, so a
// remediation message names the checkbox the operator has to tick.
const (
	ScopeWorkersScripts = "Account → Workers Scripts → Edit"
	ScopeWorkersKV      = "Account → Workers KV Storage → Edit"
	ScopeAccountRead    = "Account → Account Settings → Read"
	ScopeZoneRead       = "Zone → Zone → Read"
	ScopeDNSEdit        = "Zone → DNS → Edit"
	ScopePages          = "Account → Cloudflare Pages → Edit"
)

// Kind classifies a failure so callers can map it to an HTTP status or a CLI
// exit code without string matching.
type Kind string

const (
	KindAuth       Kind = "auth"
	KindPermission Kind = "permission"
	KindNotFound   Kind = "not_found"
	KindConflict   Kind = "conflict"
	KindValidation Kind = "validation"
	KindRateLimit  Kind = "rate_limit"
	KindNetwork    Kind = "network"
	KindServer     Kind = "server"
	// KindNoCredentials is the honest answer when an operation needs Cloudflare
	// and nothing has been authorised. It is never dressed up as success.
	KindNoCredentials Kind = "no_credentials"
)

// Error is a typed Cloudflare/edge failure.
type Error struct {
	Op           string `json:"op"`
	Kind         Kind   `json:"kind"`
	Status       int    `json:"status,omitempty"`
	Code         int    `json:"code,omitempty"`
	Message      string `json:"error"`
	Remediation  string `json:"remediation,omitempty"`
	MissingScope string `json:"missing_scope,omitempty"`
	Cause        error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Message
	}
	return e.Op + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Cause }

// AsError extracts a *Error from an error chain.
func AsError(err error) (*Error, bool) {
	for err != nil {
		if e, ok := err.(*Error); ok {
			return e, true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return nil, false
		}
		err = u.Unwrap()
	}
	return nil, false
}

// IsNotFound reports whether err is a "no such Worker/namespace/zone".
func IsNotFound(err error) bool {
	e, ok := AsError(err)
	return ok && e.Kind == KindNotFound
}

// IsConflict reports whether err is "that name is already taken".
func IsConflict(err error) bool {
	e, ok := AsError(err)
	return ok && e.Kind == KindConflict
}

// ErrNoCredentials is the sentinel returned by panel handlers when a live
// Cloudflare call is required and nothing has been authorised. It carries the
// exact next step instead of pretending the operation succeeded.
func ErrNoCredentials(op string) *Error {
	return &Error{Op: op, Kind: KindNoCredentials,
		Message: "no Cloudflare credential is available to this panel",
		Remediation: "run `forgectl edge deploy` from a machine with a browser (OAuth + PKCE, nothing is stored), " +
			"or pass an API token minted at https://dash.cloudflare.com/profile/api-tokens with Workers Scripts:Edit and Workers KV Storage:Edit."}
}

// Client is the Cloudflare API client.
type Client struct {
	Token     string
	AccountID string
	BaseURL   string
	HTTP      *http.Client
	// MaxRetries bounds retries on 429/5xx. Zero means 2.
	MaxRetries int
	// Sleep is the backoff hook; tests replace it to avoid real waiting.
	Sleep func(time.Duration)
}

// NewClient builds a client with the production API root.
func NewClient(token, accountID string) *Client {
	return &Client{Token: token, AccountID: accountID, BaseURL: APIBase}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return netegress.Client(60 * time.Second)
}

func (c *Client) base() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return APIBase
}

func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

// envelope is Cloudflare's uniform response wrapper.
type envelope struct {
	Success  bool            `json:"success"`
	Errors   []apiMessage    `json:"errors"`
	Messages []apiMessage    `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// do performs one JSON API call.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, op, scope string) (*envelope, error) {
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, &Error{Op: op, Kind: KindValidation,
				Message: "could not encode the request body: " + err.Error(), Cause: err}
		}
		raw = b
	}
	return c.send(ctx, method, path, query, func() (io.Reader, string) {
		if raw == nil {
			return nil, ""
		}
		return bytes.NewReader(raw), "application/json"
	}, op, scope)
}

// send is the retrying transport shared by JSON and multipart calls. bodyFn is
// called once per attempt so a retry gets a fresh reader.
func (c *Client) send(ctx context.Context, method, path string, query url.Values,
	bodyFn func() (io.Reader, string), op, scope string,
) (*envelope, error) {
	endpoint := c.base() + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	retries := c.MaxRetries
	if retries == 0 {
		retries = 2
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			c.sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		reader, contentType := bodyFn()
		req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, &Error{Op: op, Kind: KindValidation,
				Message: "could not build the request: " + err.Error(), Cause: err}
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			lastErr = &Error{Op: op, Kind: KindNetwork,
				Message:     fmt.Sprintf("could not reach %s: %v", endpoint, err),
				Remediation: "check outbound HTTPS from this host and DNS resolution for api.cloudflare.com",
				Cause:       err}
			continue
		}
		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = &Error{Op: op, Kind: KindNetwork, Status: resp.StatusCode,
				Message: "could not read the response body: " + readErr.Error(), Cause: readErr}
			continue
		}

		var env envelope
		decodeErr := json.Unmarshal(payload, &env)

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = apiError(op, scope, resp.StatusCode, env, payload)
			if attempt < retries {
				continue
			}
			return nil, lastErr
		}
		if decodeErr != nil {
			return nil, &Error{Op: op, Kind: KindServer, Status: resp.StatusCode,
				Message:     "unexpected non-JSON response: " + truncate(string(payload), 300),
				Remediation: "this usually means a proxy intercepted the call; verify api.cloudflare.com is reachable directly",
				Cause:       decodeErr}
		}
		if resp.StatusCode >= 400 || !env.Success {
			return nil, apiError(op, scope, resp.StatusCode, env, payload)
		}
		return &env, nil
	}
	return nil, lastErr
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// apiError maps a Cloudflare failure onto a typed error.
func apiError(op, scope string, status int, env envelope, raw []byte) *Error {
	e := &Error{Op: op, Status: status}
	if len(env.Errors) > 0 {
		e.Code = env.Errors[0].Code
		msgs := make([]string, 0, len(env.Errors))
		for _, m := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%s (code %d)", m.Message, m.Code))
		}
		e.Message = strings.Join(msgs, "; ")
	} else {
		e.Message = truncate(string(raw), 300)
	}
	lower := strings.ToLower(e.Message)

	switch {
	case status == http.StatusTooManyRequests:
		e.Kind = KindRateLimit
		e.Remediation = "Cloudflare rate-limited the token (1200 requests per five minutes). Wait a minute and retry."
		return e
	case status >= 500:
		e.Kind = KindServer
		e.Remediation = "Cloudflare returned a server error. Retry shortly; check https://www.cloudflarestatus.com if it persists."
		return e
	case status == http.StatusUnauthorized, e.Code == 10000, e.Code == 9106, e.Code == 6003,
		strings.Contains(lower, "invalid api token"), strings.Contains(lower, "authentication error"):
		e.Kind = KindAuth
		e.Remediation = "the credential was rejected. Re-run `forgectl edge deploy` to reauthorise, or mint a fresh token at https://dash.cloudflare.com/profile/api-tokens."
		return e
	case status == http.StatusForbidden, e.Code == 9109,
		strings.Contains(lower, "unauthorized to access"), strings.Contains(lower, "insufficient permission"):
		e.Kind = KindPermission
		e.MissingScope = scope
		e.Remediation = scopeRemediation(scope)
		return e
	case status == http.StatusNotFound, e.Code == 7003, e.Code == 10007, e.Code == 1003,
		strings.Contains(lower, "could not route"), strings.Contains(lower, "not found"),
		strings.Contains(lower, "workers.api.error.script_not_found"):
		e.Kind = KindNotFound
		e.Remediation = "no object with that name exists under this account. Check the name with `forgectl edge status --all`."
		return e
	case status == http.StatusConflict, strings.Contains(lower, "already exists"):
		e.Kind = KindConflict
		e.Remediation = "an object with that name already exists. Choose another --name, or pass --force to overwrite deliberately."
		return e
	case status == http.StatusBadRequest:
		e.Kind = KindValidation
		e.Remediation = "Cloudflare rejected the request contents; re-run with --json to capture the full error."
		return e
	}
	e.Kind = KindServer
	e.Remediation = "unexpected Cloudflare response; re-run with --json to capture the full error for a bug report."
	return e
}

func scopeRemediation(scope string) string {
	if scope == "" {
		scope = ScopeAccountRead
	}
	return "open https://dash.cloudflare.com/profile/api-tokens → edit the token → Permissions → add \"" + scope +
		"\" → Account Resources must include this account. Save, then re-run."
}

// TokenURL returns a pre-filled Cloudflare token-creation URL with exactly the
// permissions `forgectl edge` needs, so nobody has to click through the
// permission matrix by hand (FORGECTL_EDGE_SPEC.md, credential policy).
func TokenURL() string {
	keys := []string{
		"com.cloudflare.edge.worker.write",
		"com.cloudflare.edge.storage.kv.write",
		"com.cloudflare.api.account.pages.write",
		"com.cloudflare.api.account.zone.dns.write",
		"com.cloudflare.api.account.read",
		"com.cloudflare.api.user.read",
	}
	q := url.Values{}
	q.Set("permissionGroupKeys", "["+strings.Join(quoteAll(keys), ",")+"]")
	q.Set("accountId", "*")
	q.Set("zoneId", "all")
	q.Set("name", "ForgePanel-Edge")
	return "https://dash.cloudflare.com/profile/api-tokens?" + q.Encode()
}

func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, `"`+s+`"`)
	}
	return out
}
