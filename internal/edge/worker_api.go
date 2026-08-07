package edge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// This file talks to a DEPLOYED ForgeEdge Worker rather than to the Cloudflare
// API: pushing the canonical feed, reading the Worker's own status, and
// rotating its secure path. See deploy/cloudflare/forgeedge/src/panel/handler.ts
// for the other end of each of these.

// UpdateRepo is the GitHub repository the update check reads releases from. It
// matches the Worker's own `updateRepo` default.
const UpdateRepo = "forgepanel/forgepanel"

// SecurePathAlphabet is the Worker's alphabet for a minted secure path: a-z
// without `l` and `o`, digits 2-9. Generating a path with the same alphabet is
// what lets `forgectl edge deploy` pass SECURE_PATH in at deploy time and know
// it up front, instead of scraping a log line for it.
const SecurePathAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// SecurePathLength is the default length the Worker mints.
const SecurePathLength = 24

// GenerateSecurePath returns a fresh secure path.
func GenerateSecurePath(n int) (string, error) {
	if n <= 0 {
		n = SecurePathLength
	}
	max := big.NewInt(int64(len(SecurePathAlphabet)))
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", &Error{Op: "generate-secure-path", Kind: KindServer,
				Message: "no entropy available: " + err.Error(), Cause: err}
		}
		b.WriteByte(SecurePathAlphabet[idx.Int64()])
	}
	return b.String(), nil
}

// RandomName returns a default Worker name, forgeedge-<6 hex>.
func RandomName() (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", &Error{Op: "generate-name", Kind: KindServer,
			Message: "no entropy available: " + err.Error(), Cause: err}
	}
	return fmt.Sprintf("forgeedge-%x", buf), nil
}

// WorkerClient talks to one deployed Worker.
type WorkerClient struct {
	Origin     string
	SecurePath string
	HTTP       *http.Client
	// Session is the cookie value obtained from Login; set by Login.
	Session string
}

// NewWorkerClient builds a client for <origin>/<securePath>/….
func NewWorkerClient(origin, securePath string) *WorkerClient {
	return &WorkerClient{
		Origin:     strings.TrimSuffix(strings.TrimSpace(origin), "/"),
		SecurePath: strings.Trim(strings.TrimSpace(securePath), "/"),
	}
}

func (w *WorkerClient) httpClient() *http.Client {
	if w.HTTP != nil {
		return w.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// URL builds an absolute URL under the Worker's secure path.
func (w *WorkerClient) URL(parts ...string) string {
	segs := append([]string{w.Origin, w.SecurePath}, parts...)
	return strings.Join(segs, "/")
}

// workerEnvelope is the Worker's uniform ApiEnvelope (src/common/http.ts).
type workerEnvelope struct {
	Success bool            `json:"success"`
	Status  int             `json:"status"`
	Message *string         `json:"message"`
	Body    json.RawMessage `json:"body"`
}

func (w *WorkerClient) call(ctx context.Context, method, url string, body any, op string) (*workerEnvelope, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, &Error{Op: op, Kind: KindValidation, Message: err.Error(), Cause: err}
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, &Error{Op: op, Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if w.Session != "" {
		req.Header.Set("Cookie", w.Session)
	}
	resp, err := w.httpClient().Do(req)
	if err != nil {
		return nil, &Error{Op: op, Kind: KindNetwork,
			Message:     fmt.Sprintf("could not reach %s: %v", url, err),
			Remediation: "confirm the Worker is deployed and the origin/secure path are right (`forgectl edge status`).",
			Cause:       err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	// Keep the session cookie a login handed back.
	if sc := resp.Header.Get("Set-Cookie"); sc != "" {
		if name, _, ok := strings.Cut(sc, ";"); ok || name != "" {
			w.Session = name
		}
	}
	var env workerEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &Error{Op: op, Kind: KindServer, Status: resp.StatusCode,
			Message: "the edge did not return JSON: " + truncate(string(raw), 200),
			Remediation: "that path is served by the decoy handler unless the secure path is exactly right — " +
				"check it against the Worker's panel URL.", Cause: err}
	}
	if !env.Success {
		msg := ""
		if env.Message != nil {
			msg = *env.Message
		}
		return &env, workerError(op, resp.StatusCode, msg)
	}
	return &env, nil
}

func workerError(op string, status int, msg string) *Error {
	e := &Error{Op: op, Status: status, Message: msg}
	if e.Message == "" {
		e.Message = fmt.Sprintf("the edge returned %d", status)
	}
	switch status {
	case http.StatusUnauthorized:
		e.Kind = KindAuth
		e.Remediation = "the edge rejected the credential. For /feed that is the push token (read it from the Worker's panel → status); " +
			"for the panel API it is the admin password."
	case http.StatusNotFound:
		e.Kind = KindNotFound
	case http.StatusBadRequest:
		e.Kind = KindValidation
	default:
		e.Kind = KindServer
	}
	return e
}

// Login opens an admin session against the Worker's panel API. The panel needs
// this to proxy /api/status, which is session-authenticated: the secure path
// gets you to the door, the password opens it.
func (w *WorkerClient) Login(ctx context.Context, password string) error {
	_, err := w.call(ctx, http.MethodPost, w.URL("api", "login"), map[string]string{"password": password}, "edge-login")
	return err
}

// WorkerStatus mirrors the Worker's `GET /<path>/api/status` body.
type WorkerStatus struct {
	Version              string `json:"version"`
	Host                 string `json:"host"`
	Panel                string `json:"panel"`
	DoHEndpoint          string `json:"dohEndpoint"`
	SubscriptionTemplate string `json:"subscriptionTemplate"`
	FeedPushEndpoint     string `json:"feedPushEndpoint"`
	FeedPushToken        string `json:"feedPushToken"`
	SecurePathRotatedAt  string `json:"securePathRotatedAt"`
	BackendMode          string `json:"backendMode"`
	Users                int    `json:"users"`
	FeedGeneratedAt      string `json:"feedGeneratedAt"`
	CleanIPs             struct {
		Count     int    `json:"count"`
		UpdatedAt string `json:"updatedAt"`
	} `json:"cleanIPs"`
	Deployment json.RawMessage `json:"deployment"`
}

// Status reads the Worker's own view of itself. password may be empty, in which
// case an unauthenticated attempt is made and a 401 is reported honestly rather
// than swallowed.
func (w *WorkerClient) Status(ctx context.Context, password string) (*WorkerStatus, error) {
	if password != "" {
		if err := w.Login(ctx, password); err != nil {
			return nil, err
		}
	}
	env, err := w.call(ctx, http.MethodGet, w.URL("api", "status"), nil, "edge-status")
	if err != nil {
		return nil, err
	}
	var st WorkerStatus
	if err := json.Unmarshal(env.Body, &st); err != nil {
		return nil, decodeError("edge-status", err)
	}
	return &st, nil
}

// RotatePath rotates the Worker's secure path. Every previous URL — panel, API
// and every subscription — stops working immediately.
func (w *WorkerClient) RotatePath(ctx context.Context, password string) (string, error) {
	if password != "" {
		if err := w.Login(ctx, password); err != nil {
			return "", err
		}
	}
	env, err := w.call(ctx, http.MethodPost, w.URL("api", "rotate-path"), map[string]any{}, "edge-rotate-path")
	if err != nil {
		return "", err
	}
	var res struct {
		SecurePath string `json:"securePath"`
	}
	if err := json.Unmarshal(env.Body, &res); err != nil {
		return "", decodeError("edge-rotate-path", err)
	}
	return res.SecurePath, nil
}

// PushResult is what the edge reports back after accepting a feed.
type PushResult struct {
	Users       int      `json:"users"`
	SharedNodes int      `json:"sharedNodes"`
	Warnings    []string `json:"warnings"`
}

// PushFeed POSTs a canonical feed document to <origin>/<path>/feed with the
// push token.
//
// Warnings are returned, never swallowed: a non-empty list means the edge
// dropped users or nodes it could not parse, and those subscribers are getting a
// short list without knowing it.
func PushFeed(ctx context.Context, client *http.Client, feedURL, token string, doc any) (*PushResult, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, &Error{Op: "edge-push", Kind: KindValidation,
			Message: "could not encode the feed: " + err.Error(), Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, feedURL, bytes.NewReader(raw))
	if err != nil {
		return nil, &Error{Op: "edge-push", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &Error{Op: "edge-push", Kind: KindNetwork,
			Message:     fmt.Sprintf("could not reach %s: %v", feedURL, err),
			Remediation: "confirm the Worker is deployed and the origin/secure path are right (`forgectl edge status`).",
			Cause:       err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env workerEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &Error{Op: "edge-push", Kind: KindServer, Status: resp.StatusCode,
			Message:     "the edge did not return JSON: " + truncate(string(body), 200),
			Remediation: "an unrecognised path is served by the decoy handler; check the secure path.", Cause: err}
	}
	if !env.Success {
		msg := ""
		if env.Message != nil {
			msg = *env.Message
		}
		return nil, workerError("edge-push", resp.StatusCode, msg)
	}
	var res PushResult
	if len(env.Body) > 0 {
		_ = json.Unmarshal(env.Body, &res)
	}
	return &res, nil
}

// --- update check -----------------------------------------------------------

// UpdateInfo mirrors the Worker's own update-check shape.
type UpdateInfo struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url,omitempty"`
	CheckedAt       string `json:"checked_at"`
}

// GitHubAPIBase is overridable so the update check can be tested without the
// network.
var GitHubAPIBase = "https://api.github.com"

// CheckForUpdate reports whether a newer ForgeEdge release exists. It is
// strictly read-only: ForgeEdge never fetches and self-executes remote code, so
// this only tells the operator that a release exists and where to read it.
func CheckForUpdate(ctx context.Context, client *http.Client, repo, current string) (*UpdateInfo, error) {
	if repo == "" {
		repo = UpdateRepo
	}
	info := &UpdateInfo{Current: current, Latest: current, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	url := strings.TrimSuffix(GitHubAPIBase, "/") + "/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &Error{Op: "update-check", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	req.Header.Set("User-Agent", "ForgePanel")
	req.Header.Set("Accept", "application/vnd.github+json")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &Error{Op: "update-check", Kind: KindNetwork,
			Message:     "could not reach the GitHub releases API: " + err.Error(),
			Remediation: "this host may have no outbound HTTPS; the edge keeps running either way, the check is advisory.",
			Cause:       err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Op: "update-check", Kind: KindServer, Status: resp.StatusCode,
			Message: "the GitHub releases API returned " + truncate(string(raw), 200)}
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(raw, &rel); err != nil {
		return nil, decodeError("update-check", err)
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	if latest != "" {
		info.Latest = latest
		info.UpdateAvailable = latest != current
	}
	info.ReleaseURL = rel.HTMLURL
	return info, nil
}
