// Package cfedge deploys and manages the ForgeEdge Cloudflare Worker (the
// VLESS-over-WebSocket edge proxy + free-config generator, see worker.js) from
// ForgePanel itself. This is the differentiator over BPB/Nova: the operator
// never touches wrangler — they paste a Cloudflare API token and the panel
// ships the Worker for them and hands back the panel/subscription URL.
package cfedge

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// WorkerJS is the single-file ForgeEdge Worker, embedded so the panel can deploy
// it with no external assets.
//
//go:embed worker.js
var WorkerJS string

const (
	apiBase       = "https://api.cloudflare.com/client/v4"
	compatDate    = "2024-09-23"
	mainModule    = "worker.js"
	defaultScript = "forgeedge"
)

// Credentials authenticate to the Cloudflare API. Prefer APIToken (scoped to
// "Workers Scripts: Edit"); the global key + email path is accepted for parity
// with the Cloudflare CLI, but a scoped token is safer.
type Credentials struct {
	AccountID string
	APIToken  string
	Email     string
	GlobalKey string
}

func (c Credentials) valid() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return fmt.Errorf("cfedge: account id required")
	}
	if c.APIToken == "" && (c.Email == "" || c.GlobalKey == "") {
		return fmt.Errorf("cfedge: an API token (or email + global key) is required")
	}
	return nil
}

// Options control a single ForgeEdge deployment. All but UUID are optional.
type Options struct {
	ScriptName  string // worker script name; defaults to "forgeedge"
	UUID        string // VLESS id clients authenticate with
	ProxyIP     string // fallback relay host[:port] for Cloudflare-hosted dests
	SubPath     string // secret panel path prefix; defaults to the UUID
	DNSResolver string // DoH resolver for UDP/DNS; defaults to 1.1.1.1
}

func (o Options) script() string {
	if s := strings.TrimSpace(o.ScriptName); s != "" {
		return s
	}
	return defaultScript
}

// Client talks to the Cloudflare Workers API for one account.
type Client struct {
	creds Credentials
	http  *http.Client
}

// New returns a client. The HTTP timeout is generous because a script upload can
// take a couple of seconds on a cold path.
func New(c Credentials) *Client {
	return &Client{creds: c, http: &http.Client{Timeout: 45 * time.Second}}
}

func (c *Client) auth(req *http.Request) {
	if c.creds.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.creds.APIToken)
		return
	}
	req.Header.Set("X-Auth-Email", c.creds.Email)
	req.Header.Set("X-Auth-Key", c.creds.GlobalKey)
}

type apiResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(req *http.Request, out any) error {
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var r apiResp
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("cloudflare: unreadable response (HTTP %d): %.200s", resp.StatusCode, body)
	}
	if !r.Success {
		if len(r.Errors) > 0 {
			return fmt.Errorf("cloudflare: %s (code %d)", r.Errors[0].Message, r.Errors[0].Code)
		}
		return fmt.Errorf("cloudflare: request failed (HTTP %d)", resp.StatusCode)
	}
	if out != nil && len(r.Result) > 0 {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// Verify confirms the credentials work and the account is reachable, so the UI
// can validate a pasted token before attempting a deploy.
func (c *Client) Verify(ctx context.Context) error {
	if err := c.creds.valid(); err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/accounts/"+c.creds.AccountID, nil)
	return c.do(req, nil)
}

// Subdomain returns the account's *.workers.dev subdomain (the hostname stem for
// every Worker on the account).
func (c *Client) Subdomain(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/accounts/"+c.creds.AccountID+"/workers/subdomain", nil)
	var out struct {
		Subdomain string `json:"subdomain"`
	}
	if err := c.do(req, &out); err != nil {
		return "", err
	}
	return out.Subdomain, nil
}

// Deploy uploads the ForgeEdge worker with the given settings and enables its
// workers.dev route. It returns the public panel URL (host + secret path).
func (c *Client) Deploy(ctx context.Context, o Options) (string, error) {
	if err := c.creds.valid(); err != nil {
		return "", err
	}
	name := o.script()

	bindings := []map[string]any{}
	for k, v := range map[string]string{"UUID": o.UUID, "PROXYIP": o.ProxyIP, "SUBPATH": o.SubPath, "DNS_RESOLVER": o.DNSResolver} {
		if strings.TrimSpace(v) != "" {
			bindings = append(bindings, map[string]any{"type": "plain_text", "name": k, "text": v})
		}
	}
	meta, _ := json.Marshal(map[string]any{
		"main_module":         mainModule,
		"compatibility_date":  compatDate,
		"compatibility_flags": []string{"nodejs_compat"},
		"bindings":            bindings,
	})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mp, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="metadata"`},
		"Content-Type":        {"application/json"},
	})
	if err != nil {
		return "", err
	}
	mp.Write(meta)
	fw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {fmt.Sprintf(`form-data; name=%q; filename=%q`, mainModule, mainModule)},
		"Content-Type":        {"application/javascript+module"},
	})
	if err != nil {
		return "", err
	}
	io.WriteString(fw, WorkerJS)
	mw.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, apiBase+"/accounts/"+c.creds.AccountID+"/workers/scripts/"+name, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := c.do(req, nil); err != nil {
		return "", fmt.Errorf("upload worker: %w", err)
	}

	sreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/accounts/"+c.creds.AccountID+"/workers/scripts/"+name+"/subdomain", strings.NewReader(`{"enabled":true}`))
	sreq.Header.Set("Content-Type", "application/json")
	if err := c.do(sreq, nil); err != nil {
		return "", fmt.Errorf("enable workers.dev route: %w", err)
	}

	sub, err := c.Subdomain(ctx)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://%s.%s.workers.dev", name, sub)
	switch {
	case strings.TrimSpace(o.SubPath) != "":
		url += "/" + strings.TrimSpace(o.SubPath)
	case strings.TrimSpace(o.UUID) != "":
		url += "/" + strings.TrimSpace(o.UUID)
	}
	return url, nil
}

// Delete removes a deployed ForgeEdge worker script.
func (c *Client) Delete(ctx context.Context, scriptName string) error {
	if err := c.creds.valid(); err != nil {
		return err
	}
	name := strings.TrimSpace(scriptName)
	if name == "" {
		name = defaultScript
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, apiBase+"/accounts/"+c.creds.AccountID+"/workers/scripts/"+name, nil)
	return c.do(req, nil)
}
