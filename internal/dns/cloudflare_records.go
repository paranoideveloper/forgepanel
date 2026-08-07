package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// cfRecord is the wire shape of a DNS record.
type cfRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Proxied  *bool  `json:"proxied,omitempty"`
	Priority *int   `json:"priority,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Data     *struct {
		Priority *int   `json:"priority,omitempty"`
		Weight   *int   `json:"weight,omitempty"`
		Port     *int   `json:"port,omitempty"`
		Target   string `json:"target,omitempty"`
	} `json:"data,omitempty"`
	Proxiable bool `json:"proxiable,omitempty"`
}

func (r cfRecord) toRecord() Record {
	out := Record{
		ID: r.ID, Type: RecordType(strings.ToUpper(r.Type)), Name: NormalizeDomain(r.Name),
		Content: r.Content, TTL: r.TTL, Comment: r.Comment,
	}
	if r.Proxied != nil {
		out.Proxied = *r.Proxied
	}
	if r.Priority != nil {
		out.Priority = *r.Priority
	}
	if r.Data != nil && out.Type == TypeSRV {
		srv := &SRVData{Target: NormalizeDomain(r.Data.Target)}
		if r.Data.Priority != nil {
			srv.Priority = *r.Data.Priority
		}
		if r.Data.Weight != nil {
			srv.Weight = *r.Data.Weight
		}
		if r.Data.Port != nil {
			srv.Port = *r.Data.Port
		}
		out.SRV = srv
	}
	return out
}

// toCF converts a neutral record into Cloudflare's request body. Only A, AAAA
// and CNAME are proxiable; sending proxied=true on anything else is a 400, so
// the flag is dropped rather than passed through.
func toCF(rec Record) map[string]any {
	body := map[string]any{
		"type":    string(rec.Type),
		"name":    rec.Name,
		"ttl":     rec.TTL,
		"comment": rec.Comment,
	}
	if rec.TTL == 0 {
		body["ttl"] = DefaultTTL
	}
	if rec.Comment == "" {
		delete(body, "comment")
	}
	switch rec.Type {
	case TypeA, TypeAAAA, TypeCNAME:
		body["content"] = rec.Content
		body["proxied"] = rec.Proxied
		// A proxied record is always served on Cloudflare's own TTL; sending a
		// custom one is rejected, so hand back "automatic".
		if rec.Proxied {
			body["ttl"] = 1
		}
	case TypeSRV:
		if rec.SRV != nil {
			body["data"] = map[string]any{
				"priority": rec.SRV.Priority,
				"weight":   rec.SRV.Weight,
				"port":     rec.SRV.Port,
				"target":   rec.SRV.Target,
			}
		}
	case TypeMX:
		body["content"] = rec.Content
		body["priority"] = rec.Priority
	default:
		body["content"] = rec.Content
	}
	return body
}

// ListRecords lists a zone's records, following pagination.
func (c *Cloudflare) ListRecords(ctx context.Context, zoneRef string, filter RecordFilter) ([]Record, error) {
	if strings.TrimSpace(zoneRef) == "" {
		return nil, &Error{Provider: "cloudflare", Op: "list-records", Kind: KindValidation,
			Message: "zone id is empty", Remediation: "resolve the zone first (ResolveZone / --domain)"}
	}
	var out []Record
	for page := 1; page <= 100; page++ {
		q := url.Values{}
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		if filter.Type != "" {
			q.Set("type", string(filter.Type))
		}
		if filter.Name != "" {
			q.Set("name", NormalizeDomain(filter.Name))
		}
		env, err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneRef)+"/dns_records", q, nil, "list-records", ScopeDNSRead)
		if err != nil {
			return nil, err
		}
		var recs []cfRecord
		if err := json.Unmarshal(env.Result, &recs); err != nil {
			return nil, &Error{Provider: "cloudflare", Op: "list-records", Kind: KindServer,
				Message: "could not decode the record list: " + err.Error(), Cause: err}
		}
		for _, r := range recs {
			rec := r.toRecord()
			// Always re-apply the filter locally: the API's name filter has
			// changed semantics between versions, and a silently ignored
			// filter would make EnsureRecord update the wrong record.
			if filter.matches(rec) {
				out = append(out, rec)
			}
		}
		if env.Info == nil || env.Info.TotalPages <= page || len(recs) == 0 {
			break
		}
	}
	return out, nil
}

// CreateRecord creates a record.
func (c *Cloudflare) CreateRecord(ctx context.Context, zoneRef string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	rec.Name = NormalizeDomain(rec.Name)
	env, err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneRef)+"/dns_records", nil, toCF(rec), "create-record", ScopeDNSEdit)
	if err != nil {
		return nil, err
	}
	return decodeCFRecord(env, "create-record")
}

// UpdateRecord replaces a record wholesale (PUT, matching Cloudflare's
// overwrite semantics).
func (c *Cloudflare) UpdateRecord(ctx context.Context, zoneRef, id string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, &Error{Provider: "cloudflare", Op: "update-record", Kind: KindValidation,
			Message: "record id is empty", Remediation: "list the record first to obtain its id"}
	}
	rec.Name = NormalizeDomain(rec.Name)
	path := "/zones/" + url.PathEscape(zoneRef) + "/dns_records/" + url.PathEscape(id)
	env, err := c.do(ctx, http.MethodPut, path, nil, toCF(rec), "update-record", ScopeDNSEdit)
	if err != nil {
		return nil, err
	}
	return decodeCFRecord(env, "update-record")
}

// DeleteRecord removes a record.
func (c *Cloudflare) DeleteRecord(ctx context.Context, zoneRef, id string) error {
	if strings.TrimSpace(id) == "" {
		return &Error{Provider: "cloudflare", Op: "delete-record", Kind: KindValidation,
			Message: "record id is empty", Remediation: "list the record first to obtain its id"}
	}
	path := "/zones/" + url.PathEscape(zoneRef) + "/dns_records/" + url.PathEscape(id)
	_, err := c.do(ctx, http.MethodDelete, path, nil, nil, "delete-record", ScopeDNSEdit)
	return err
}

// SetProxied toggles the orange cloud without otherwise touching the record.
// It reads the record first so the PUT does not blank the content.
func (c *Cloudflare) SetProxied(ctx context.Context, zoneRef, recordID string, on bool) (*Record, error) {
	path := "/zones/" + url.PathEscape(zoneRef) + "/dns_records/" + url.PathEscape(recordID)
	env, err := c.do(ctx, http.MethodGet, path, nil, nil, "get-record", ScopeDNSRead)
	if err != nil {
		return nil, err
	}
	current, err := decodeCFRecord(env, "get-record")
	if err != nil {
		return nil, err
	}
	switch current.Type {
	case TypeA, TypeAAAA, TypeCNAME:
	default:
		return nil, &Error{Provider: "cloudflare", Op: "set-proxied", Kind: KindUnsupported,
			Message:     fmt.Sprintf("%s records cannot be proxied", current.Type),
			Remediation: "only A, AAAA and CNAME records carry the orange cloud; point the client at a proxiable record instead"}
	}
	current.Proxied = on
	body := toCF(*current)
	env, err = c.do(ctx, http.MethodPut, path, nil, body, "set-proxied", ScopeDNSEdit)
	if err != nil {
		return nil, err
	}
	return decodeCFRecord(env, "set-proxied")
}

func decodeCFRecord(env *cfEnvelope, op string) (*Record, error) {
	var r cfRecord
	if err := json.Unmarshal(env.Result, &r); err != nil {
		return nil, &Error{Provider: "cloudflare", Op: op, Kind: KindServer,
			Message: "could not decode the record: " + err.Error(), Cause: err}
	}
	out := r.toRecord()
	return &out, nil
}

// cfSettings maps our neutral setting names onto Cloudflare setting ids and the
// scope each one needs. The SSL setting is the one that needs the extra
// certificates scope, which is the single most common provisioning failure.
type cfSetting struct {
	id    string
	value string
	scope string
}

func (c *Cloudflare) settingPlan(s ZoneSettings) []cfSetting {
	var plan []cfSetting
	if s.SSL != nil {
		plan = append(plan, cfSetting{id: "ssl", value: string(*s.SSL), scope: ScopeSSLEdit})
	}
	if s.AlwaysUseHTTPS != nil {
		plan = append(plan, cfSetting{id: "always_use_https", value: onOff(*s.AlwaysUseHTTPS), scope: ScopeSettingsEdit})
	}
	if s.MinTLSVersion != nil {
		plan = append(plan, cfSetting{id: "min_tls_version", value: *s.MinTLSVersion, scope: ScopeSettingsEdit})
	}
	if s.TLS13 != nil {
		plan = append(plan, cfSetting{id: "tls_1_3", value: onOff(*s.TLS13), scope: ScopeSettingsEdit})
	}
	if s.GRPC != nil {
		plan = append(plan, cfSetting{id: "grpc", value: onOff(*s.GRPC), scope: ScopeSettingsEdit})
	}
	if s.WebSockets != nil {
		plan = append(plan, cfSetting{id: "websockets", value: onOff(*s.WebSockets), scope: ScopeSettingsEdit})
	}
	return plan
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// GetZoneSettings reads back the settings the wizard manages.
func (c *Cloudflare) GetZoneSettings(ctx context.Context, zoneRef string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range []string{"ssl", "always_use_https", "min_tls_version", "tls_1_3", "grpc", "websockets"} {
		path := "/zones/" + url.PathEscape(zoneRef) + "/settings/" + id
		env, err := c.do(ctx, http.MethodGet, path, nil, nil, "get-zone-setting", ScopeSettingsRead)
		if err != nil {
			if IsNotFound(err) {
				// Not every setting exists on every plan; a missing one is not
				// a failure of the read as a whole.
				continue
			}
			return nil, err
		}
		var res struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(env.Result, &res); err != nil {
			continue
		}
		out[id] = strings.Trim(string(res.Value), `"`)
	}
	return out, nil
}

// ApplyZoneSettings pushes each requested setting and reports per-setting
// outcomes. One rejected setting does not abort the rest: an operator on a Free
// plan should still get the settings their plan allows, with an exact reason
// for the ones it does not.
func (c *Cloudflare) ApplyZoneSettings(ctx context.Context, zoneRef string, s ZoneSettings) ([]SettingResult, error) {
	plan := c.settingPlan(s)
	if len(plan) == 0 {
		return nil, nil
	}
	results := make([]SettingResult, 0, len(plan))
	var permErr error
	for _, item := range plan {
		path := "/zones/" + url.PathEscape(zoneRef) + "/settings/" + item.id
		_, err := c.do(ctx, http.MethodPatch, path, nil, map[string]any{"value": item.value}, "set-zone-setting:"+item.id, item.scope)
		res := SettingResult{Setting: item.id, Value: item.value, Applied: err == nil}
		if err != nil {
			res.Error = err.Error()
			if e, ok := AsError(err); ok {
				res.Error = e.Message
				res.Remediation = e.Remediation
				if e.Kind == KindPermission && permErr == nil {
					permErr = err
				}
				if e.Kind == KindNotFound || e.Kind == KindValidation {
					res.Remediation = fmt.Sprintf("the %q setting is not available on this zone's plan; the inbound still works, but %s",
						item.id, cfSettingConsequence(item.id))
				}
			}
		}
		results = append(results, res)
	}
	// A permission failure is worth surfacing as an error too — it is the one
	// class the operator must act on before the zone is usable.
	return results, permErr
}

func cfSettingConsequence(id string) string {
	switch id {
	case "grpc":
		return "a gRPC inbound behind the orange cloud will not carry traffic — use ws or xhttp transport instead, or turn the proxy off for that record"
	case "websockets":
		return "a ws/httpupgrade inbound behind the orange cloud will not upgrade — turn the proxy off for that record"
	case "min_tls_version":
		return "the edge keeps its default TLS floor of 1.0, which is weaker than the panel would set"
	case "tls_1_3":
		return "the edge negotiates TLS 1.2 with clients, which is still functional"
	case "always_use_https":
		return "plain-HTTP requests are not redirected, which only matters for the panel's web UI"
	case "ssl":
		return "the origin-pull mode stays as configured; verify it is Full or Full (strict), never Flexible, or TLS inbounds break"
	}
	return "verify the setting by hand in the Cloudflare dashboard"
}

// Compile-time proof that the Cloudflare client satisfies every interface it
// claims, including both optional capability interfaces.
var (
	_ Provider               = (*Cloudflare)(nil)
	_ ProxyController        = (*Cloudflare)(nil)
	_ ZoneSettingsController = (*Cloudflare)(nil)
)
