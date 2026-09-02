package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// Account is a Cloudflare account visible to the credential.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListAccounts enumerates the accounts the credential can see. `forgectl edge`
// prompts when there is more than one rather than picking silently.
func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	env, err := c.do(ctx, http.MethodGet, "/accounts", nil, nil, "list-accounts", ScopeAccountRead)
	if err != nil {
		return nil, err
	}
	var out []Account
	if err := json.Unmarshal(env.Result, &out); err != nil {
		return nil, decodeError("list-accounts", err)
	}
	return out, nil
}

func decodeError(op string, err error) *Error {
	return &Error{Op: op, Kind: KindServer,
		Message: "could not decode the Cloudflare response: " + err.Error(), Cause: err}
}

// requireAccount fails early with an actionable message rather than building a
// URL with an empty path segment that Cloudflare answers with "could not route".
func (c *Client) requireAccount(op string) error {
	if strings.TrimSpace(c.AccountID) == "" {
		return &Error{Op: op, Kind: KindValidation,
			Message:     "no Cloudflare account id was supplied",
			Remediation: "pass --account, or let `forgectl edge deploy` resolve it with GET /accounts (it prompts when the credential spans several)."}
	}
	return nil
}

func (c *Client) acctPath(parts ...string) string {
	segs := make([]string, 0, len(parts)+2)
	segs = append(segs, "accounts", url.PathEscape(c.AccountID))
	for _, p := range parts {
		segs = append(segs, url.PathEscape(p))
	}
	return "/" + strings.Join(segs, "/")
}

// --- Workers scripts -------------------------------------------------------

// ScriptInfo is the subset of a Worker's metadata the CLI reports.
type ScriptInfo struct {
	ID         string `json:"id"`
	CreatedOn  string `json:"created_on"`
	ModifiedOn string `json:"modified_on"`
	Etag       string `json:"etag"`
}

// GetScript reads a Worker's metadata. A KindNotFound error means "free to
// deploy under this name"; anything else is a real failure.
func (c *Client) GetScript(ctx context.Context, name string) (*ScriptInfo, error) {
	if err := c.requireAccount("get-script"); err != nil {
		return nil, err
	}
	env, err := c.do(ctx, http.MethodGet, c.acctPath("workers", "scripts", name), nil, nil,
		"get-script", ScopeWorkersScripts)
	if err != nil {
		return nil, err
	}
	var info ScriptInfo
	// A script GET can return the script body rather than JSON metadata on some
	// account types; an undecodable result still proves existence.
	if err := json.Unmarshal(env.Result, &info); err != nil {
		return &ScriptInfo{ID: name}, nil
	}
	if info.ID == "" {
		info.ID = name
	}
	return &info, nil
}

// ScriptExists reports whether a Worker with this name is already deployed.
func (c *Client) ScriptExists(ctx context.Context, name string) (bool, error) {
	_, err := c.GetScript(ctx, name)
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// Binding is one entry in the uploaded metadata's bindings array.
type Binding struct {
	Type string `json:"type"`
	Name string `json:"name"`
	// NamespaceID is set for kv_namespace bindings.
	NamespaceID string `json:"namespace_id,omitempty"`
	// ID is set for d1 bindings.
	ID string `json:"id,omitempty"`
	// Text is set for plain_text and secret_text bindings (this is how
	// SECURE_PATH is passed).
	Text string `json:"text,omitempty"`
}

// KVBinding builds the KV namespace binding the Worker reads as `env.KV`.
func KVBinding(namespaceID string) Binding {
	return Binding{Type: "kv_namespace", Name: "KV", NamespaceID: namespaceID}
}

// D1Binding builds the optional D1 binding.
func D1Binding(databaseID string) Binding {
	return Binding{Type: "d1", Name: "DB", ID: databaseID}
}

// PlainTextBinding builds a plain-text var binding.
func PlainTextBinding(name, text string) Binding {
	return Binding{Type: "plain_text", Name: name, Text: text}
}

// SecretTextBinding builds a secret_text binding: the same shape on the wire as
// plain_text, but Cloudflare redacts the value from the dashboard and from the
// API afterwards. It exists for CF_API_TOKEN, the one binding whose value is a
// credential rather than a setting.
func SecretTextBinding(name, text string) Binding {
	return Binding{Type: "secret_text", Name: name, Text: text}
}

// UploadSpec is one script upload.
type UploadSpec struct {
	Name              string
	Script            []byte
	Bindings          []Binding
	CompatibilityDate string
	// CompatibilityFlags defaults to ["nodejs_compat"], which the Worker needs.
	CompatibilityFlags []string
}

// uploadMetadata is the multipart `metadata` part.
type uploadMetadata struct {
	MainModule         string    `json:"main_module"`
	CompatibilityDate  string    `json:"compatibility_date"`
	CompatibilityFlags []string  `json:"compatibility_flags"`
	KeepBindings       []string  `json:"keep_bindings"`
	Bindings           []Binding `json:"bindings,omitempty"`
}

// KeepBindings is sent on EVERY upload, deploy and update alike. Without it a
// re-upload detaches the KV namespace, and every subscriber's config disappears
// on the Worker's next request (FORGECTL_EDGE_SPEC.md step 6).
var KeepBindings = []string{"kv_namespace", "d1"}

// UploadScript PUTs a Worker script as multipart/form-data.
func (c *Client) UploadScript(ctx context.Context, spec UploadSpec) error {
	if err := c.requireAccount("upload-script"); err != nil {
		return err
	}
	if len(spec.Script) == 0 {
		return &Error{Op: "upload-script", Kind: KindValidation,
			Message:     "the Worker bundle is empty",
			Remediation: "build it first: cd deploy/cloudflare/forgeedge && bun run build, or pass --bundle <path> to a released worker.js"}
	}
	meta := uploadMetadata{
		MainModule:         "worker.js",
		CompatibilityDate:  spec.CompatibilityDate,
		CompatibilityFlags: spec.CompatibilityFlags,
		KeepBindings:       KeepBindings,
		Bindings:           spec.Bindings,
	}
	if meta.CompatibilityDate == "" {
		meta.CompatibilityDate = time.Now().UTC().Format("2006-01-02")
	}
	if len(meta.CompatibilityFlags) == 0 {
		meta.CompatibilityFlags = []string{"nodejs_compat"}
	}
	body, contentType, err := buildUpload(meta, spec.Script)
	if err != nil {
		return err
	}
	_, err = c.send(ctx, http.MethodPut, c.acctPath("workers", "scripts", spec.Name), nil,
		func() (io.Reader, string) { return bytes.NewReader(body), contentType },
		"upload-script", ScopeWorkersScripts)
	return err
}

// buildUpload assembles the multipart body. The script part must carry
// Content-Type application/javascript+module or the upload is rejected as a
// service-worker-format script.
func buildUpload(meta uploadMetadata, script []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	metaHeader := textproto.MIMEHeader{}
	metaHeader.Set("Content-Disposition", `form-data; name="metadata"`)
	metaHeader.Set("Content-Type", "application/json")
	part, err := w.CreatePart(metaHeader)
	if err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	if _, err := part.Write(raw); err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}

	scriptHeader := textproto.MIMEHeader{}
	scriptHeader.Set("Content-Disposition", `form-data; name="worker.js"; filename="worker.js"`)
	scriptHeader.Set("Content-Type", "application/javascript+module")
	sp, err := w.CreatePart(scriptHeader)
	if err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	if _, err := sp.Write(script); err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	if err := w.Close(); err != nil {
		return nil, "", &Error{Op: "upload-script", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// --- cron triggers ----------------------------------------------------------

// DefaultCrons is the schedule the Worker's scheduled() handler runs on: the
// clean-IP refresh, the external-subscription merge, the feed pull and the
// update check (deploy/cloudflare/forgeedge/src/worker.ts). It mirrors the
// "triggers" block in wrangler.jsonc.
//
// That wrangler block was the ONLY place the cron was ever declared, and the
// panel never runs wrangler — it PUTs the prebuilt bundle at the API directly.
// So every Worker the panel deployed had a scheduled() handler that nothing
// ever invoked: clean IPs went stale, external subs were never merged, and the
// update check never ran, all silently.
var DefaultCrons = []string{"17 */6 * * *"}

// PutSchedules registers the Worker's cron triggers, replacing whatever it had.
//
// Registered with its own call rather than a "triggers" field in the upload
// metadata: the multipart metadata form of triggers is undocumented and has
// been dropped by the API without an error, which would leave exactly the
// silent no-op this exists to fix. PUT .../schedules answers with the schedule
// list it stored, so a failure is a failure.
func (c *Client) PutSchedules(ctx context.Context, name string, crons []string) error {
	if err := c.requireAccount("put-schedules"); err != nil {
		return err
	}
	// The API takes a bare array of {cron} objects; an empty array clears the
	// triggers, which is a legitimate thing to ask for.
	body := make([]map[string]string, 0, len(crons))
	for _, cron := range crons {
		cron = strings.TrimSpace(cron)
		if cron == "" {
			continue
		}
		body = append(body, map[string]string{"cron": cron})
	}
	_, err := c.do(ctx, http.MethodPut, c.acctPath("workers", "scripts", name, "schedules"), nil, body,
		"put-schedules", ScopeWorkersScripts)
	return err
}

// Schedules lists the cron triggers currently registered for a Worker.
func (c *Client) Schedules(ctx context.Context, name string) ([]string, error) {
	if err := c.requireAccount("list-schedules"); err != nil {
		return nil, err
	}
	env, err := c.do(ctx, http.MethodGet, c.acctPath("workers", "scripts", name, "schedules"), nil, nil,
		"list-schedules", ScopeWorkersScripts)
	if err != nil {
		return nil, err
	}
	// The result is {"schedules":[{"cron":"..."}]} on a GET, even though the PUT
	// takes the bare array.
	var res struct {
		Schedules []struct {
			Cron string `json:"cron"`
		} `json:"schedules"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, decodeError("list-schedules", err)
	}
	out := make([]string, 0, len(res.Schedules))
	for _, s := range res.Schedules {
		out = append(out, s.Cron)
	}
	return out, nil
}

// DeleteScript removes a Worker. Every subscription URL it served dies with it.
func (c *Client) DeleteScript(ctx context.Context, name string) error {
	if err := c.requireAccount("delete-script"); err != nil {
		return err
	}
	q := url.Values{"force": {"true"}}
	_, err := c.do(ctx, http.MethodDelete, c.acctPath("workers", "scripts", name), q, nil,
		"delete-script", ScopeWorkersScripts)
	return err
}

// --- workers.dev subdomain --------------------------------------------------

// EnableSubdomain publishes the Worker on <name>.<account subdomain>.workers.dev.
func (c *Client) EnableSubdomain(ctx context.Context, name string) error {
	if err := c.requireAccount("enable-subdomain"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodPost, c.acctPath("workers", "scripts", name, "subdomain"), nil,
		map[string]any{"enabled": true}, "enable-subdomain", ScopeWorkersScripts)
	return err
}

// AccountSubdomain returns the account's workers.dev subdomain (the "acme" in
// forgeedge-a1b2c3.acme.workers.dev), or "" when the account has never set one.
func (c *Client) AccountSubdomain(ctx context.Context) (string, error) {
	if err := c.requireAccount("get-subdomain"); err != nil {
		return "", err
	}
	env, err := c.do(ctx, http.MethodGet, c.acctPath("workers", "subdomain"), nil, nil,
		"get-subdomain", ScopeWorkersScripts)
	if err != nil {
		if IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	var res struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return "", decodeError("get-subdomain", err)
	}
	return res.Subdomain, nil
}

// SetAccountSubdomain claims a workers.dev subdomain for an account that has
// none yet.
func (c *Client) SetAccountSubdomain(ctx context.Context, sub string) error {
	if err := c.requireAccount("set-subdomain"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodPut, c.acctPath("workers", "subdomain"), nil,
		map[string]any{"subdomain": sub}, "set-subdomain", ScopeWorkersScripts)
	return err
}

// WorkerOrigin is the https origin of a Worker on workers.dev.
func WorkerOrigin(name, subdomain string) string {
	return fmt.Sprintf("https://%s.%s.workers.dev", name, subdomain)
}

// --- custom domains ---------------------------------------------------------

// AttachDomain binds a custom hostname to the Worker. The zone must already be
// in this account.
func (c *Client) AttachDomain(ctx context.Context, name, hostname, zoneID string) error {
	if err := c.requireAccount("attach-domain"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodPut, c.acctPath("workers", "domains"), nil, map[string]any{
		"hostname": hostname, "service": name, "environment": "production", "zone_id": zoneID,
	}, "attach-domain", ScopeZoneRead)
	return err
}

// WorkerDomains lists the custom hostnames bound to a Worker.
func (c *Client) WorkerDomains(ctx context.Context, name string) ([]string, error) {
	if err := c.requireAccount("list-domains"); err != nil {
		return nil, err
	}
	q := url.Values{"service": {name}}
	env, err := c.do(ctx, http.MethodGet, c.acctPath("workers", "domains"), q, nil,
		"list-domains", ScopeZoneRead)
	if err != nil {
		return nil, err
	}
	var res []struct {
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(env.Result, &res); err != nil {
		return nil, decodeError("list-domains", err)
	}
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.Hostname)
	}
	return out, nil
}

// FindZone resolves a hostname to the zone that contains it, walking up the
// labels so node.example.com is provisioned through the example.com zone.
func (c *Client) FindZone(ctx context.Context, hostname string) (id, name string, err error) {
	env, err := c.do(ctx, http.MethodGet, "/zones", nil, nil, "list-zones", ScopeZoneRead)
	if err != nil {
		return "", "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", "", decodeError("list-zones", err)
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	best := ""
	for _, z := range zones {
		zn := strings.ToLower(z.Name)
		if host == zn || strings.HasSuffix(host, "."+zn) {
			if len(zn) > len(best) {
				best, id, name = zn, z.ID, z.Name
			}
		}
	}
	if id == "" {
		return "", "", &Error{Op: "find-zone", Kind: KindNotFound,
			Message:     fmt.Sprintf("no zone in this account contains %q", hostname),
			Remediation: "add the domain at https://dash.cloudflare.com (Add a Site), or widen the credential's Zone Resources to include it."}
	}
	return id, name, nil
}

// --- KV ---------------------------------------------------------------------

// KVNamespace is a Workers KV namespace.
type KVNamespace struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// KVTitle is the namespace title convention: one namespace per Worker, derived
// from its name, so `forgectl edge delete` can find it without another column
// in the panel DB.
func KVTitle(name string) string { return name + "-forgeedge" }

// CreateKVNamespace creates the Worker's KV namespace.
func (c *Client) CreateKVNamespace(ctx context.Context, title string) (*KVNamespace, error) {
	if err := c.requireAccount("create-kv"); err != nil {
		return nil, err
	}
	env, err := c.do(ctx, http.MethodPost, c.acctPath("storage", "kv", "namespaces"), nil,
		map[string]any{"title": title}, "create-kv", ScopeWorkersKV)
	if err != nil {
		return nil, err
	}
	var ns KVNamespace
	if err := json.Unmarshal(env.Result, &ns); err != nil {
		return nil, decodeError("create-kv", err)
	}
	return &ns, nil
}

// FindKVNamespace looks a namespace up by title, which is how an update or a
// delete rediscovers the namespace created at deploy time.
func (c *Client) FindKVNamespace(ctx context.Context, title string) (*KVNamespace, error) {
	if err := c.requireAccount("list-kv"); err != nil {
		return nil, err
	}
	q := url.Values{"per_page": {"100"}}
	env, err := c.do(ctx, http.MethodGet, c.acctPath("storage", "kv", "namespaces"), q, nil,
		"list-kv", ScopeWorkersKV)
	if err != nil {
		return nil, err
	}
	var all []KVNamespace
	if err := json.Unmarshal(env.Result, &all); err != nil {
		return nil, decodeError("list-kv", err)
	}
	for _, ns := range all {
		if ns.Title == title {
			found := ns
			return &found, nil
		}
	}
	return nil, &Error{Op: "list-kv", Kind: KindNotFound,
		Message:     fmt.Sprintf("no KV namespace titled %q", title),
		Remediation: "it may have been renamed or deleted in the dashboard; re-run deploy to create a fresh one."}
}

// DeleteKVNamespace destroys a namespace and everything in it: config, users,
// the secure path.
func (c *Client) DeleteKVNamespace(ctx context.Context, id string) error {
	if err := c.requireAccount("delete-kv"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodDelete, c.acctPath("storage", "kv", "namespaces", id), nil, nil,
		"delete-kv", ScopeWorkersKV)
	return err
}

// --- D1 ---------------------------------------------------------------------

// D1Database is a D1 database.
type D1Database struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// CreateD1 creates the optional D1 database.
func (c *Client) CreateD1(ctx context.Context, name string) (*D1Database, error) {
	if err := c.requireAccount("create-d1"); err != nil {
		return nil, err
	}
	env, err := c.do(ctx, http.MethodPost, c.acctPath("d1", "database"), nil,
		map[string]any{"name": name}, "create-d1", ScopeWorkersKV)
	if err != nil {
		return nil, err
	}
	var db D1Database
	if err := json.Unmarshal(env.Result, &db); err != nil {
		return nil, decodeError("create-d1", err)
	}
	return &db, nil
}

// DeleteD1 destroys a D1 database.
func (c *Client) DeleteD1(ctx context.Context, id string) error {
	if err := c.requireAccount("delete-d1"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodDelete, c.acctPath("d1", "database", id), nil, nil,
		"delete-d1", ScopeWorkersKV)
	return err
}

// --- Pages ------------------------------------------------------------------

// DeletePagesProject removes a Pages project.
func (c *Client) DeletePagesProject(ctx context.Context, name string) error {
	if err := c.requireAccount("delete-pages"); err != nil {
		return err
	}
	_, err := c.do(ctx, http.MethodDelete, c.acctPath("pages", "projects", name), nil, nil,
		"delete-pages", ScopePages)
	return err
}
