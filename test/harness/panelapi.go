//go:build harness

// panelapi.go is a thin client for the ForgePanel REST API. The harness drives
// the panel exactly the way an operator's browser does — first-run setup, login,
// create inbound, create user, assign, fetch subscription — so that what it
// proves is the shipped product surface and not an internal Go function.
package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Panel is an authenticated session against one panel instance.
type Panel struct {
	BaseURL string // e.g. http://panel:2053
	HTTP    *http.Client
	token   string
	// Credentials are retained so an expired access token can be renewed
	// mid-run. auth.AccessTTL is 15 minutes and a full matrix run takes longer
	// than that; without renewal every case past the fifteen-minute mark fails
	// with HTTP 401 and the matrix reports a panel defect that is really a
	// defect in the harness.
	user, pass string
}

// NewPanel returns a session with sane timeouts. Login must be called before
// any /api/admin route.
func NewPanel(baseURL string) *Panel {
	return &Panel{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Host returns the host[:port] part of the base URL. The panel substitutes this
// into exported links, so the harness records it to explain the address a
// client config ends up dialling.
func (p *Panel) Host() string {
	u, err := url.Parse(p.BaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// APIError carries a non-2xx response so callers can assert on the status.
type APIError struct {
	Status int
	Method string
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, strings.TrimSpace(e.Body))
}

func (p *Panel) do(method, path string, in, out any) error {
	err := p.doOnce(method, path, in, out)
	// A 401 on an authenticated route means the 15-minute access token aged out
	// during the run. Sign in again and retry once; a second 401 is a real
	// authentication failure and is returned as such.
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized && p.user != "" {
		if lerr := p.Login(p.user, p.pass); lerr != nil {
			return fmt.Errorf("%w (renewing the session also failed: %v)", err, lerr)
		}
		return p.doOnce(method, path, in, out)
	}
	return err
}

func (p *Panel) doOnce(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, p.BaseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w (body=%.400s)", method, path, err, raw)
		}
	}
	return nil
}

// WaitHealthy blocks until /healthz answers or the budget expires.
func (p *Panel) WaitHealthy(budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		var v map[string]any
		if err := p.do(http.MethodGet, "/healthz", nil, &v); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("panel never became healthy within %s: %v", budget, last)
}

// Version returns /api/version verbatim, recorded in the results file so a
// matrix can be tied to the exact build that produced it.
func (p *Panel) Version() (map[string]any, error) {
	var v map[string]any
	err := p.do(http.MethodGet, "/api/version", nil, &v)
	return v, err
}

// SetupRequired reports whether first-run administrator setup is pending.
func (p *Panel) SetupRequired() (bool, error) {
	var v struct {
		SetupRequired bool `json:"setup_required"`
	}
	err := p.do(http.MethodGet, "/api/setup/status", nil, &v)
	return v.SetupRequired, err
}

// SetupInit creates the first owner account with the one-time setup token.
func (p *Panel) SetupInit(token, user, pass string) error {
	return p.do(http.MethodPost, "/api/setup/init", map[string]any{
		"token": token, "username": user, "password": pass, "password_confirm": pass,
	}, nil)
}

// Login exchanges credentials for an access token and stores it on the session.
func (p *Panel) Login(user, pass string) error {
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err := p.doOnce(http.MethodPost, "/api/login", map[string]any{
		"username": user, "password": pass,
	}, &v); err != nil {
		return err
	}
	if v.AccessToken == "" {
		return fmt.Errorf("login returned no access token")
	}
	p.token = v.AccessToken
	p.user, p.pass = user, pass
	return nil
}

// Inbound is the create response for an inbound.
type Inbound struct {
	ID       uint   `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// CreateInbound posts a canonical node. node is the model.Node JSON shape, so
// the harness exercises the same payload the Config Studio sends.
func (p *Panel) CreateInbound(node map[string]any) (*Inbound, error) {
	var in Inbound
	if err := p.do(http.MethodPost, "/api/admin/inbounds", node, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

// DeleteInbound removes an inbound (and triggers an engine reload).
func (p *Panel) DeleteInbound(id uint) error {
	return p.do(http.MethodDelete, fmt.Sprintf("/api/admin/inbounds/%d", id), nil, nil)
}

// InboundRow is one row of the admin inbound list, including the canonical node
// with its server-side credentials. The harness reads these back so a failing
// case can say whether the subscription handed the client the same secret the
// server is actually serving.
type InboundRow struct {
	ID       uint           `json:"id"`
	Remark   string         `json:"remark"`
	Protocol string         `json:"protocol"`
	Port     int            `json:"port"`
	Enabled  bool           `json:"enabled"`
	Node     map[string]any `json:"node"`
}

// ListInbounds returns every configured inbound.
func (p *Panel) ListInbounds() ([]InboundRow, error) {
	var v []InboundRow
	err := p.do(http.MethodGet, "/api/admin/inbounds", nil, &v)
	return v, err
}

// UpdateInbound replaces an inbound's canonical node.
func (p *Panel) UpdateInbound(id uint, node map[string]any) error {
	return p.do(http.MethodPut, fmt.Sprintf("/api/admin/inbounds/%d", id), node, nil)
}

// InboundNode returns the stored canonical node for one inbound.
func (p *Panel) InboundNode(id uint) (map[string]any, error) {
	rows, err := p.ListInbounds()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r.Node, nil
		}
	}
	return nil, fmt.Errorf("inbound %d not found", id)
}

// User is the create response for a proxy account.
type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	SubToken string `json:"sub_token"`
	SubURL   string `json:"sub_url"`
	UUID     string `json:"uuid"`
}

// CreateUser creates an account with no group; access is granted per-inbound by
// SetUserInbounds so each case is isolated to exactly one tunnel.
func (p *Panel) CreateUser(username string) (*User, error) {
	var u User
	if err := p.do(http.MethodPost, "/api/admin/users", map[string]any{
		"username": username,
	}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// DeleteUser removes an account.
func (p *Panel) DeleteUser(id uint) error {
	return p.do(http.MethodDelete, fmt.Sprintf("/api/admin/users/%d", id), nil, nil)
}

// SetUserInbounds replaces a user's direct inbound assignments.
func (p *Panel) SetUserInbounds(userID uint, inboundIDs []uint) error {
	return p.do(http.MethodPut, fmt.Sprintf("/api/admin/users/%d/inbounds", userID),
		map[string]any{"inbound_ids": inboundIDs}, nil)
}

// UserRecord mirrors the fields of store.User the harness asserts on.
type UserRecord struct {
	ID             uint       `json:"id"`
	Username       string     `json:"username"`
	Status         string     `json:"status"`
	UUID           string     `json:"uuid"`
	SubToken       string     `json:"sub_token"`
	DataLimit      int64      `json:"data_limit"`
	UsedTraffic    int64      `json:"used_traffic"`
	ExpireAt       *time.Time `json:"expire_at"`
	FirstConnectAt *time.Time `json:"first_connect_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// GetUser reads one account back with its effective assignments.
func (p *Panel) GetUser(id uint) (*UserRecord, error) {
	var v struct {
		User UserRecord `json:"user"`
	}
	if err := p.do(http.MethodGet, fmt.Sprintf("/api/admin/users/%d", id), nil, &v); err != nil {
		return nil, err
	}
	return &v.User, nil
}

// PatchUser applies a partial user update (status, data_limit, expire_at…).
func (p *Panel) PatchUser(id uint, fields map[string]any) error {
	return p.do(http.MethodPatch, fmt.Sprintf("/api/admin/users/%d", id), fields, nil)
}

// EngineStatus is one supervised core's reported state.
type EngineStatus struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Err     string `json:"error"`
	Restart int    `json:"restarts"`
}

// Engines returns the supervised cores' live status.
func (p *Panel) Engines() ([]EngineStatus, error) {
	var v []EngineStatus
	err := p.do(http.MethodGet, "/api/admin/engines", nil, &v)
	return v, err
}

// EngineConfig is the last generated bundle, including inbounds the engine
// layer refused. Skipped is the panel's own admission that a configuration it
// accepted at the API cannot actually be served.
type EngineConfig struct {
	Xray            string `json:"xray"`
	Singbox         string `json:"singbox"`
	XrayInbounds    int    `json:"xray_inbounds"`
	SingboxInbounds int    `json:"singbox_inbounds"`
	Skipped         []struct {
		Remark string `json:"remark"`
		Reason string `json:"reason"`
	} `json:"skipped"`
}

// EngineConfigDump returns the generated engine configs.
func (p *Panel) EngineConfigDump() (*EngineConfig, error) {
	var v EngineConfig
	err := p.do(http.MethodGet, "/api/admin/engines/config", nil, &v)
	return &v, err
}

// Subscription fetches /sub/<token>/<format> and returns the raw body plus the
// response headers, which carry the quota/expiry the client displays.
func (p *Panel) Subscription(token, format, userAgent string) ([]byte, http.Header, error) {
	path := "/sub/" + token
	if format != "" {
		path += "/" + format
	}
	req, err := http.NewRequest(http.MethodGet, p.BaseURL+path, nil)
	if err != nil {
		return nil, nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return raw, resp.Header, &APIError{Status: resp.StatusCode, Method: "GET", Path: path, Body: string(raw)}
	}
	return raw, resp.Header, nil
}
