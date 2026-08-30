package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"strconv"
	"strings"
	"time"
)

// DesecAPIBase is the deSEC API root. deSEC is the free, DNSSEC-signed,
// no-CDN option: it has no proxy layer at all, which makes it the right
// provider for REALITY and direct-TLS inbounds where an orange cloud would
// break the handshake anyway.
const DesecAPIBase = "https://desec.io/api/v1"

// Desec is the deSEC DNS provider. deSEC models DNS as RRsets — one object per
// (subname, type) holding every value — rather than one object per value, so a
// "record id" here is the synthetic "subname/type" key its REST paths use.
type Desec struct {
	Token   string
	BaseURL string
	HTTP    *http.Client
	// Sleep is the backoff hook, replaced in tests. deSEC throttles hard and
	// answers 429 with Retry-After, which this client honours.
	Sleep func(time.Duration)
	// MaxRetries bounds 429 retries. Zero means 2.
	MaxRetries int
}

// NewDesec builds a deSEC provider. It requires "token" — the value from
// https://desec.io/tokens.
func NewDesec(creds Credentials) (Provider, error) {
	if err := creds.Require("desec", "token"); err != nil {
		return nil, err
	}
	d := &Desec{Token: creds.Get("token"), BaseURL: creds.Get("base_url")}
	if d.BaseURL == "" {
		d.BaseURL = DesecAPIBase
	}
	return d, nil
}

// Name implements Provider.
func (d *Desec) Name() string { return "desec" }

func (d *Desec) httpClient() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return netegress.Client(30 * time.Second)
}

func (d *Desec) base() string {
	if strings.TrimSpace(d.BaseURL) != "" {
		return strings.TrimSuffix(d.BaseURL, "/")
	}
	return DesecAPIBase
}

func (d *Desec) sleep(dur time.Duration) {
	if d.Sleep != nil {
		d.Sleep(dur)
		return
	}
	time.Sleep(dur)
}

// do performs a request. deSEC returns bare JSON (no envelope) and uses HTTP
// status for everything, including a 429 with Retry-After that this honours
// rather than surfacing as an opaque failure.
func (d *Desec) do(ctx context.Context, method, path string, body any, op string) (int, []byte, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, nil, &Error{Provider: "desec", Op: op, Kind: KindValidation,
				Message: "could not encode the request body: " + err.Error(), Cause: err}
		}
	}
	retries := d.MaxRetries
	if retries == 0 {
		retries = 2
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, d.base()+path, reader)
		if err != nil {
			return 0, nil, &Error{Provider: "desec", Op: op, Kind: KindValidation,
				Message: "could not build the request: " + err.Error(), Cause: err}
		}
		req.Header.Set("Authorization", "Token "+d.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := d.httpClient().Do(req)
		if err != nil {
			return 0, nil, &Error{Provider: "desec", Op: op, Kind: KindNetwork,
				Message:     fmt.Sprintf("could not reach %s: %v", d.base()+path, err),
				Remediation: "check outbound HTTPS to desec.io and that DNS resolution works on this host",
				Cause:       err}
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()
		if readErr != nil {
			return resp.StatusCode, nil, &Error{Provider: "desec", Op: op, Kind: KindNetwork, Status: resp.StatusCode,
				Message: "could not read the response body: " + readErr.Error(), Cause: readErr}
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < retries {
			wait := 2 * time.Second
			if secs, convErr := strconv.Atoi(strings.TrimSpace(retryAfter)); convErr == nil && secs > 0 && secs <= 60 {
				wait = time.Duration(secs) * time.Second
			}
			lastErr = d.apiError(op, resp.StatusCode, raw, retryAfter)
			d.sleep(wait)
			continue
		}
		if resp.StatusCode >= 400 {
			return resp.StatusCode, raw, d.apiError(op, resp.StatusCode, raw, retryAfter)
		}
		return resp.StatusCode, raw, nil
	}
	return 0, nil, lastErr
}

func (d *Desec) apiError(op string, status int, raw []byte, retryAfter string) *Error {
	e := &Error{Provider: "desec", Op: op, Status: status, Message: truncate(string(raw), 400)}
	// deSEC reports either {"detail": "..."} or a per-field map.
	var detail struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &detail); err == nil && strings.TrimSpace(detail.Detail) != "" {
		e.Message = detail.Detail
	}
	switch status {
	case http.StatusUnauthorized:
		e.Kind = KindAuth
		e.Remediation = "the deSEC token was rejected. Create one at https://desec.io/tokens and paste the token value (not the token id) as `token`."
	case http.StatusForbidden:
		e.Kind = KindPermission
		e.MissingScope = "token with domain write access (perm_manage_tokens off, no restricted subnets blocking this host)"
		e.Remediation = "the token exists but cannot write here. At https://desec.io/tokens check the token is not restricted to other subnets and that its scope covers this domain, then re-run."
	case http.StatusNotFound:
		e.Kind = KindNotFound
		e.Remediation = "the domain or RRset does not exist. Register the domain at https://desec.io/domains first; for a subdomain the panel writes into the parent domain."
	case http.StatusBadRequest:
		e.Kind = KindValidation
		e.Remediation = "deSEC rejected the RRset. TXT values must be quoted, targets must be fully qualified with a trailing dot, and the TTL cannot be below the domain's minimum_ttl (3600 on free accounts)."
	case http.StatusConflict:
		e.Kind = KindConflict
		e.Remediation = "an RRset with that subname and type already exists; the wizard upserts, so re-run without --no-overwrite."
	case http.StatusTooManyRequests:
		e.Kind = KindRateLimit
		e.Remediation = "deSEC throttled the token" + retryAfterHint(retryAfter) + ". deSEC allows a few writes per second per account; lower --bulk-count and retry."
	default:
		e.Kind = KindServer
		if status >= 500 {
			e.Remediation = "deSEC returned a server error; retry shortly."
		}
	}
	return e
}

func retryAfterHint(retryAfter string) string {
	if strings.TrimSpace(retryAfter) == "" {
		return ""
	}
	return " (Retry-After: " + strings.TrimSpace(retryAfter) + "s)"
}

type desecDomain struct {
	Name       string   `json:"name"`
	MinimumTTL int      `json:"minimum_ttl"`
	Published  string   `json:"published"`
	Touched    string   `json:"touched"`
	Keys       []any    `json:"keys"`
	Zonefile   string   `json:"zonefile,omitempty"`
	NameServer []string `json:"-"`
}

func (dd desecDomain) toZone() Zone {
	return Zone{
		ID: NormalizeDomain(dd.Name), Name: NormalizeDomain(dd.Name),
		// deSEC only lists domains it is authoritative for, so a listed domain
		// is by definition active.
		Status: "active", Provider: "desec", MinimumTTL: dd.MinimumTTL,
		// deSEC's nameservers are fixed and account-independent.
		NameServers: []string{"ns1.desec.io", "ns2.desec.org"},
	}
}

// VerifyCredentials proves the token works by listing domains.
func (d *Desec) VerifyCredentials(ctx context.Context) (*Identity, error) {
	zones, err := d.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider: "desec", Status: "active",
		Scopes: []string{"domain read+write"},
		Detail: fmt.Sprintf("token is valid and can see %d domain(s)", len(zones)),
	}, nil
}

// ListZones enumerates the account's domains.
func (d *Desec) ListZones(ctx context.Context) ([]Zone, error) {
	_, raw, err := d.do(ctx, http.MethodGet, "/domains/", nil, "list-zones")
	if err != nil {
		return nil, err
	}
	var domains []desecDomain
	if err := json.Unmarshal(raw, &domains); err != nil {
		return nil, &Error{Provider: "desec", Op: "list-zones", Kind: KindServer,
			Message: "could not decode the domain list: " + err.Error(), Cause: err}
	}
	out := make([]Zone, 0, len(domains))
	for _, dd := range domains {
		out = append(out, dd.toZone())
	}
	return out, nil
}

// FindZone fetches a single domain by name.
func (d *Desec) FindZone(ctx context.Context, name string) (*Zone, error) {
	want := NormalizeDomain(name)
	_, raw, err := d.do(ctx, http.MethodGet, "/domains/"+want+"/", nil, "find-zone")
	if err != nil {
		if IsNotFound(err) {
			return nil, &Error{Provider: "desec", Op: "find-zone", Kind: KindNotFound,
				Message:     fmt.Sprintf("no deSEC domain named %q is visible to this token", want),
				Remediation: "register the domain at https://desec.io/domains and delegate it to ns1.desec.io / ns2.desec.org, then re-run. For a subdomain the panel needs the parent domain."}
		}
		return nil, err
	}
	var dd desecDomain
	if err := json.Unmarshal(raw, &dd); err != nil {
		return nil, &Error{Provider: "desec", Op: "find-zone", Kind: KindServer,
			Message: "could not decode the domain: " + err.Error(), Cause: err}
	}
	z := dd.toZone()
	return &z, nil
}
