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

// ArvanAPIBase is the ArvanCloud CDN API root. Arvan matters for the Iranian
// market specifically: it is reachable from inside Iran when Cloudflare's
// dashboard and API are not, so it is the fallback that keeps provisioning
// possible from a domestic vantage point.
const ArvanAPIBase = "https://napi.arvancloud.ir/cdn/4.0"

// Arvan is the ArvanCloud DNS provider. Arvan addresses zones by domain name
// rather than an opaque id, and stores record values as a typed object rather
// than a string, so the conversion in and out of the neutral Record shape is
// where most of this file lives.
type Arvan struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// NewArvan builds an ArvanCloud provider. It requires "api_key" — the value
// from the ArvanCloud machine-user API keys page. The "Apikey " prefix is added
// if the operator pasted the bare key.
func NewArvan(creds Credentials) (Provider, error) {
	if err := creds.Require("arvancloud", "api_key"); err != nil {
		return nil, err
	}
	a := &Arvan{APIKey: creds.Get("api_key"), BaseURL: creds.Get("base_url")}
	if a.BaseURL == "" {
		a.BaseURL = ArvanAPIBase
	}
	return a, nil
}

// Name implements Provider.
func (a *Arvan) Name() string { return "arvancloud" }

func (a *Arvan) httpClient() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return netegress.Client(30 * time.Second)
}

func (a *Arvan) base() string {
	if strings.TrimSpace(a.BaseURL) != "" {
		return strings.TrimSuffix(a.BaseURL, "/")
	}
	return ArvanAPIBase
}

// authHeader returns the Authorization value. Arvan's own docs show
// "Apikey <key>"; operators habitually paste it either way.
func (a *Arvan) authHeader() string {
	key := strings.TrimSpace(a.APIKey)
	if strings.HasPrefix(strings.ToLower(key), "apikey ") {
		return "Apikey " + strings.TrimSpace(key[len("apikey "):])
	}
	return "Apikey " + key
}

// arvanEnvelope is Arvan's response wrapper: data plus a human message, and an
// errors map on validation failures.
type arvanEnvelope struct {
	Data    json.RawMessage            `json:"data"`
	Message string                     `json:"message"`
	Errors  map[string]json.RawMessage `json:"errors"`
	Meta    *struct {
		Total       int `json:"total"`
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
		PerPage     int `json:"per_page"`
	} `json:"meta"`
}

func (a *Arvan) do(ctx context.Context, method, path string, query url.Values, body any, op string) (*arvanEnvelope, error) {
	endpoint := a.base() + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindValidation,
				Message: "could not encode the request body: " + err.Error(), Cause: err}
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindValidation,
			Message: "could not build the request: " + err.Error(), Cause: err}
	}
	req.Header.Set("Authorization", a.authHeader())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient().Do(req)
	if err != nil {
		return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindNetwork,
			Message:     fmt.Sprintf("could not reach %s: %v", endpoint, err),
			Remediation: "check outbound HTTPS to napi.arvancloud.ir; from outside Iran this host is occasionally geo-filtered, in which case run the wizard from a domestic vantage point",
			Cause:       err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindNetwork, Status: resp.StatusCode,
			Message: "could not read the response body: " + err.Error(), Cause: err}
	}
	var env arvanEnvelope
	decodeErr := json.Unmarshal(raw, &env)
	if resp.StatusCode >= 400 {
		return nil, a.apiError(op, resp.StatusCode, env, raw)
	}
	if decodeErr != nil {
		return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindServer, Status: resp.StatusCode,
			Message: fmt.Sprintf("unexpected non-JSON response: %s", truncate(string(raw), 300)), Cause: decodeErr}
	}
	return &env, nil
}

func (a *Arvan) apiError(op string, status int, env arvanEnvelope, raw []byte) *Error {
	e := &Error{Provider: "arvancloud", Op: op, Status: status, Message: strings.TrimSpace(env.Message)}
	if e.Message == "" {
		e.Message = truncate(string(raw), 300)
	}
	if len(env.Errors) > 0 {
		parts := make([]string, 0, len(env.Errors))
		for field, detail := range env.Errors {
			parts = append(parts, fmt.Sprintf("%s: %s", field, strings.Trim(string(detail), `"`)))
		}
		e.Message = e.Message + " — " + strings.Join(parts, "; ")
	}
	switch status {
	case http.StatusUnauthorized:
		e.Kind = KindAuth
		e.Remediation = "the ArvanCloud API key was rejected. Generate a machine-user key under Profile → API keys and paste it as api_key; the panel adds the \"Apikey \" prefix itself."
	case http.StatusForbidden:
		e.Kind = KindPermission
		e.MissingScope = "CDN → DNS records (read & write)"
		e.Remediation = "the key exists but is not allowed on this domain. In ArvanCloud, grant the machine user access to the domain and the CDN/DNS product, then re-run."
	case http.StatusNotFound:
		e.Kind = KindNotFound
		e.Remediation = "the domain or record does not exist under this key. Add the domain in the ArvanCloud CDN panel first."
	case http.StatusUnprocessableEntity, http.StatusBadRequest:
		e.Kind = KindValidation
		e.Remediation = "ArvanCloud rejected the record contents. Check the value matches the type (a → IPv4, aaaa → IPv6, cname → hostname) and that the sub-name is relative to the zone."
	case http.StatusConflict:
		e.Kind = KindConflict
		e.Remediation = "a record with that name and type already exists; the wizard upserts, so re-run without --no-overwrite."
	case http.StatusTooManyRequests:
		e.Kind = KindRateLimit
		e.Remediation = "ArvanCloud throttled the API key. Wait a minute and retry with a lower --bulk-count."
	default:
		if status >= 500 {
			e.Kind = KindServer
			e.Remediation = "ArvanCloud returned a server error; retry shortly."
		} else {
			e.Kind = KindServer
		}
	}
	return e
}

type arvanDomain struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
	CurrentNS   []string `json:"current_ns"`
}

func (d arvanDomain) toZone() Zone {
	ns := d.NameServers
	if len(ns) == 0 {
		ns = d.CurrentNS
	}
	return Zone{
		// Arvan's record endpoints are keyed by domain name, so the name is the
		// working handle; the opaque id is kept for display only.
		ID: d.Name, Name: NormalizeDomain(d.Name), Status: d.Status,
		Provider: "arvancloud", NameServers: ns,
	}
}

// VerifyCredentials proves the key works by listing domains, which is the same
// permission every later call needs.
func (a *Arvan) VerifyCredentials(ctx context.Context) (*Identity, error) {
	zones, err := a.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider: "arvancloud", Status: "active",
		Scopes: []string{"CDN → DNS records"},
		Detail: fmt.Sprintf("API key is valid and can see %d domain(s)", len(zones)),
	}, nil
}

// ListZones enumerates the domains on the account, following pagination.
func (a *Arvan) ListZones(ctx context.Context) ([]Zone, error) {
	var out []Zone
	for page := 1; page <= 100; page++ {
		q := url.Values{}
		q.Set("per_page", "50")
		q.Set("page", strconv.Itoa(page))
		env, err := a.do(ctx, http.MethodGet, "/domains", q, nil, "list-zones")
		if err != nil {
			return nil, err
		}
		var domains []arvanDomain
		if err := json.Unmarshal(env.Data, &domains); err != nil {
			return nil, &Error{Provider: "arvancloud", Op: "list-zones", Kind: KindServer,
				Message: "could not decode the domain list: " + err.Error(), Cause: err}
		}
		for _, d := range domains {
			out = append(out, d.toZone())
		}
		if env.Meta == nil || env.Meta.LastPage <= page || len(domains) == 0 {
			break
		}
	}
	return out, nil
}

// FindZone returns the domain with exactly this name.
func (a *Arvan) FindZone(ctx context.Context, name string) (*Zone, error) {
	want := NormalizeDomain(name)
	env, err := a.do(ctx, http.MethodGet, "/domains", url.Values{"search": {want}, "per_page": {"50"}}, nil, "find-zone")
	if err != nil && !IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		var domains []arvanDomain
		if jsonErr := json.Unmarshal(env.Data, &domains); jsonErr == nil {
			for _, d := range domains {
				if NormalizeDomain(d.Name) == want {
					z := d.toZone()
					return &z, nil
				}
			}
		}
	}
	return nil, &Error{Provider: "arvancloud", Op: "find-zone", Kind: KindNotFound,
		Message:     fmt.Sprintf("no ArvanCloud domain named %q is visible to this key", want),
		Remediation: "add the domain in the ArvanCloud CDN panel and point the registrar at Arvan's nameservers, then re-run. For a subdomain, the panel needs the parent domain's zone."}
}
