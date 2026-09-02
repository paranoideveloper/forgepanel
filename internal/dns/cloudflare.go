package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CloudflareAPIBase is the production API root. Tests point a client at an
// httptest server by setting Client.BaseURL.
const CloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// Cloudflare token scopes, spelled exactly as Cloudflare's token editor labels
// them. These strings go straight into operator-facing remediation text, so the
// operator can find the checkbox without translating our vocabulary into theirs.
const (
	ScopeZoneRead     = "Zone → Zone → Read"
	ScopeDNSRead      = "Zone → DNS → Read"
	ScopeDNSEdit      = "Zone → DNS → Edit"
	ScopeSettingsEdit = "Zone → Zone Settings → Edit"
	ScopeSettingsRead = "Zone → Zone Settings → Read"
	ScopeSSLEdit      = "Zone → SSL and Certificates → Edit"
)

// Cloudflare is a hand-rolled REST client for api.cloudflare.com/client/v4.
// It exists rather than a vendor SDK so the panel adds no dependency and so
// every permission failure can be turned into an exact "add this scope" message
// instead of the API's generic "Unauthorized to access requested resource".
type Cloudflare struct {
	Token     string
	AccountID string
	BaseURL   string
	HTTP      *http.Client
	// Now is injectable for deterministic retry/backoff in tests.
	Now func() time.Time
	// MaxRetries bounds retries on 429/5xx. Zero means 2.
	MaxRetries int
	// Sleep is the backoff hook; tests replace it to avoid real waiting.
	Sleep func(time.Duration)
}

// NewCloudflare builds a Cloudflare provider from credentials. It requires
// "api_token"; "account_id" is optional and switches token verification to the
// account-scoped endpoint.
func NewCloudflare(creds Credentials) (Provider, error) {
	if err := creds.Require("cloudflare", "api_token"); err != nil {
		return nil, err
	}
	c := &Cloudflare{
		Token:     creds.Get("api_token"),
		AccountID: creds.Get("account_id"),
		BaseURL:   creds.Get("base_url"),
	}
	if c.BaseURL == "" {
		c.BaseURL = CloudflareAPIBase
	}
	return c, nil
}

// Name implements Provider.
func (c *Cloudflare) Name() string { return "cloudflare" }

func (c *Cloudflare) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return netegress.Client(30 * time.Second)
}

func (c *Cloudflare) base() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return CloudflareAPIBase
}

func (c *Cloudflare) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

// cfEnvelope is Cloudflare's uniform response wrapper.
type cfEnvelope struct {
	Success  bool            `json:"success"`
	Errors   []cfMessage     `json:"errors"`
	Messages []cfMessage     `json:"messages"`
	Result   json.RawMessage `json:"result"`
	Info     *cfResultInfo   `json:"result_info,omitempty"`
}

type cfMessage struct {
	Code             int    `json:"code"`
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url,omitempty"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// do performs one API call, unwraps the envelope and converts any failure into
// a typed *Error carrying the missing scope for the operation.
func (c *Cloudflare) do(ctx context.Context, method, path string, query url.Values, body any, op string, scope string) (*cfEnvelope, error) {
	endpoint := c.base() + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindValidation,
				Message: "could not encode the request body: " + err.Error(), Cause: err}
		}
		reader = bytes.NewReader(raw)
	}

	retries := c.MaxRetries
	if retries == 0 {
		retries = 2
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			c.sleep(time.Duration(attempt) * 500 * time.Millisecond)
			if reader != nil {
				raw, _ := json.Marshal(body)
				reader = bytes.NewReader(raw)
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindValidation,
				Message: "could not build the request: " + err.Error(), Cause: err}
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient().Do(req)
		if err != nil {
			lastErr = &Error{Provider: "cloudflare", Op: op, Kind: KindNetwork,
				Message:     fmt.Sprintf("could not reach %s: %v", endpoint, err),
				Remediation: "check outbound HTTPS from this host, DNS resolution for api.cloudflare.com, and any proxy or firewall in the path",
				Cause:       err}
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = &Error{Provider: "cloudflare", Op: op, Kind: KindNetwork, Status: resp.StatusCode,
				Message: "could not read the response body: " + readErr.Error(), Cause: readErr}
			continue
		}

		var env cfEnvelope
		// A 5xx from the edge is sometimes HTML, so a decode failure is only
		// meaningful when the status said success.
		decodeErr := json.Unmarshal(raw, &env)

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = c.apiError(op, scope, resp.StatusCode, env, raw)
			if attempt < retries {
				continue
			}
			return nil, lastErr
		}
		if decodeErr != nil {
			return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindServer, Status: resp.StatusCode,
				Message:     fmt.Sprintf("unexpected non-JSON response: %s", truncate(string(raw), 300)),
				Remediation: "this usually means a proxy intercepted the call; verify api.cloudflare.com is reachable directly",
				Cause:       decodeErr}
		}
		if resp.StatusCode >= 400 || !env.Success {
			return nil, c.apiError(op, scope, resp.StatusCode, env, raw)
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

// apiError maps a Cloudflare failure onto a typed error. The scope argument is
// the permission the operation needs; when the failure looks like an
// authorization problem we name it explicitly.
func (c *Cloudflare) apiError(op, scope string, status int, env cfEnvelope, raw []byte) *Error {
	e := &Error{Provider: "cloudflare", Op: op, Status: status}
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

	switch {
	case status == http.StatusTooManyRequests:
		e.Kind = KindRateLimit
		e.Remediation = "Cloudflare rate-limited the API token (1200 requests per five minutes per user). Wait a minute and retry; reduce --bulk-count or --scan-concurrency if this repeats."
		return e
	case status >= 500:
		e.Kind = KindServer
		e.Remediation = "Cloudflare returned a server error. Retry shortly; check https://www.cloudflarestatus.com if it persists."
		return e
	}

	// Cloudflare's authentication/authorization codes.
	switch e.Code {
	case 6003, 9106, 9109, 10000:
		// 6003 invalid request headers, 9106 missing auth, 9109 unauthorized to
		// access the resource, 10000 authentication error.
	}
	lower := strings.ToLower(e.Message)
	switch {
	case status == http.StatusUnauthorized, e.Code == 10000, e.Code == 9106, e.Code == 6003,
		strings.Contains(lower, "invalid api token"), strings.Contains(lower, "authentication error"):
		e.Kind = KindAuth
		e.Remediation = "the API token was rejected. Create a fresh token at https://dash.cloudflare.com/profile/api-tokens, confirm it is not expired or IP-restricted, and paste it without surrounding whitespace."
		return e
	case status == http.StatusForbidden, e.Code == 9109,
		strings.Contains(lower, "unauthorized to access"), strings.Contains(lower, "insufficient permission"),
		strings.Contains(lower, "access denied"):
		e.Kind = KindPermission
		e.MissingScope = scope
		e.Remediation = cfScopeRemediation(scope)
		return e
	case status == http.StatusNotFound, e.Code == 7003, e.Code == 7000, e.Code == 1003,
		strings.Contains(lower, "could not route"), strings.Contains(lower, "not found"):
		e.Kind = KindNotFound
		e.Remediation = "the zone or record id does not exist under this token. Re-list zones (`forgectl provision --list-zones`) and confirm the token's Zone Resources include this zone."
		return e
	case e.Code == 81053, e.Code == 81057, e.Code == 81058, status == http.StatusConflict,
		strings.Contains(lower, "already exists"):
		e.Kind = KindConflict
		e.Remediation = "a record with that name and type already exists. The wizard upserts by default; if you meant to replace it, delete the existing record or re-run without --no-overwrite."
		return e
	case status == http.StatusBadRequest, e.Code == 1004, e.Code == 9207:
		e.Kind = KindValidation
		e.Remediation = "Cloudflare rejected the record contents. Check the record type matches the value (A needs IPv4, AAAA needs IPv6, CNAME needs a hostname) and that the name is inside the zone."
		return e
	}
	e.Kind = KindServer
	e.Remediation = "unexpected Cloudflare response; re-run with --json to capture the full error for a bug report."
	return e
}

// cfScopeRemediation turns a scope label into step-by-step instructions.
func cfScopeRemediation(scope string) string {
	if scope == "" {
		scope = ScopeZoneRead
	}
	base := "open https://dash.cloudflare.com/profile/api-tokens → edit the token → Permissions → add \"" + scope +
		"\" → and under Zone Resources include this zone (or \"All zones from an account\"). Save, then re-run."
	switch scope {
	case ScopeSSLEdit:
		return base + " Setting the SSL mode to Full (strict) needs BOTH \"" + ScopeSettingsEdit + "\" and \"" + ScopeSSLEdit + "\"; add whichever is missing."
	case ScopeDNSEdit:
		return base + " \"" + ScopeDNSEdit + "\" implies read, so you do not need \"" + ScopeDNSRead + "\" separately."
	case ScopeZoneRead:
		return base + " Without \"" + ScopeZoneRead + "\" the token cannot even enumerate zones, so nothing else will work."
	}
	return base
}

// VerifyCredentials proves the token works and — critically — that it holds the
// scopes the panel actually needs. It checks the account-scoped verify endpoint
// when an account id is configured and the user-scoped one otherwise, then
// probes zone enumeration so a token that verifies but cannot list zones is
// caught here rather than three steps later.
func (c *Cloudflare) VerifyCredentials(ctx context.Context) (*Identity, error) {
	path := "/user/tokens/verify"
	op := "verify-user-token"
	if c.AccountID != "" {
		path = "/accounts/" + url.PathEscape(c.AccountID) + "/tokens/verify"
		op = "verify-account-token"
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, op, ScopeZoneRead)
	if err != nil {
		if c.AccountID != "" && IsNotFound(err) {
			// A wrong account id produces "could not route"; say so plainly
			// instead of leaving the operator to guess.
			if e, ok := AsError(err); ok {
				e.Remediation = fmt.Sprintf("account id %q was not found for this token. Copy the Account ID from the right-hand sidebar of any zone's Overview page, or omit --cf-account to verify the token against the user endpoint.", c.AccountID)
			}
		}
		return nil, err
	}
	var res struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		ExpiresOn string `json:"expires_on"`
		NotBefore string `json:"not_before"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindServer,
			Message: "could not decode the token verification result: " + err.Error(), Cause: err}
	}
	if !strings.EqualFold(res.Status, "active") {
		return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindAuth,
			Message:     fmt.Sprintf("token status is %q, not active", res.Status),
			Remediation: "the token is disabled or expired. Roll it at https://dash.cloudflare.com/profile/api-tokens and update the stored credential."}
	}
	ident := &Identity{
		Provider:  "cloudflare",
		TokenID:   res.ID,
		AccountID: c.AccountID,
		Status:    res.Status,
		ExpiresOn: res.ExpiresOn,
	}

	// Verification says the token is live; it says nothing about scopes. Probe
	// zone enumeration so an under-scoped token fails here with a precise
	// message instead of mid-provision.
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	ident.Scopes = append(ident.Scopes, ScopeZoneRead)
	ident.Detail = fmt.Sprintf("token is active and can see %d zone(s)", len(zones))
	return ident, nil
}

// cfZone is the wire shape of a zone.
type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Paused      bool     `json:"paused"`
	Type        string   `json:"type"`
	NameServers []string `json:"name_servers"`
	Account     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}

func (z cfZone) toZone() Zone {
	return Zone{
		ID: z.ID, Name: NormalizeDomain(z.Name), Status: z.Status,
		Provider: "cloudflare", NameServers: z.NameServers, Paused: z.Paused,
	}
}

// ListZones enumerates every zone visible to the token, following pagination.
func (c *Cloudflare) ListZones(ctx context.Context) ([]Zone, error) {
	return c.listZones(ctx, "")
}

func (c *Cloudflare) listZones(ctx context.Context, name string) ([]Zone, error) {
	var out []Zone
	for page := 1; page <= 100; page++ {
		q := url.Values{}
		q.Set("per_page", "50")
		q.Set("page", strconv.Itoa(page))
		if name != "" {
			q.Set("name", name)
		}
		if c.AccountID != "" {
			q.Set("account.id", c.AccountID)
		}
		env, err := c.do(ctx, http.MethodGet, "/zones", q, nil, "list-zones", ScopeZoneRead)
		if err != nil {
			return nil, err
		}
		var zs []cfZone
		if err := json.Unmarshal(env.Result, &zs); err != nil {
			return nil, &Error{Provider: "cloudflare", Op: "list-zones", Kind: KindServer,
				Message: "could not decode the zone list: " + err.Error(), Cause: err}
		}
		for _, z := range zs {
			out = append(out, z.toZone())
		}
		if env.Info == nil || env.Info.TotalPages <= page || len(zs) == 0 {
			break
		}
	}
	return out, nil
}

// FindZone returns the zone with exactly this name.
func (c *Cloudflare) FindZone(ctx context.Context, name string) (*Zone, error) {
	want := NormalizeDomain(name)
	zones, err := c.listZones(ctx, want)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		if z.Name == want {
			found := z
			return &found, nil
		}
	}
	return nil, &Error{Provider: "cloudflare", Op: "find-zone", Kind: KindNotFound,
		Message: fmt.Sprintf("no Cloudflare zone named %q is visible to this token", want),
		Remediation: "add the domain as a zone at https://dash.cloudflare.com (Add a Site), or widen the token's Zone Resources to include it. " +
			"If the domain is a subdomain, the panel needs the zone of its parent — provisioning node.example.com works through the example.com zone."}
}
