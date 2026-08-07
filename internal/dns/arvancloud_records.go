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

// arvanRecord is the wire shape. Value is polymorphic by type: a list of
// {ip} objects for a/aaaa, a single {host} for cname/ns, {text} for txt.
type arvanRecord struct {
	ID          string          `json:"id,omitempty"`
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Value       json.RawMessage `json:"value"`
	TTL         int             `json:"ttl,omitempty"`
	Cloud       bool            `json:"cloud"`
	IsProtected bool            `json:"is_protected,omitempty"`
}

// toRecord converts an Arvan record into the neutral shape. zone is needed
// because Arvan stores the sub-name only.
func (r arvanRecord) toRecord(zone string) Record {
	rtype := RecordType(strings.ToUpper(r.Type))
	name := NormalizeDomain(r.Name)
	switch name {
	case "", "@":
		name = NormalizeDomain(zone)
	default:
		if !strings.HasSuffix(name, "."+NormalizeDomain(zone)) && name != NormalizeDomain(zone) {
			name = name + "." + NormalizeDomain(zone)
		}
	}
	out := Record{ID: r.ID, Type: rtype, Name: name, TTL: r.TTL, Proxied: r.Cloud}

	switch rtype {
	case TypeA, TypeAAAA:
		var ips []struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(r.Value, &ips); err == nil && len(ips) > 0 {
			out.Content = ips[0].IP
		}
	case TypeCNAME, TypeNS, TypeMX:
		var host struct {
			Host     string `json:"host"`
			Priority *int   `json:"priority"`
		}
		if err := json.Unmarshal(r.Value, &host); err == nil {
			out.Content = NormalizeDomain(host.Host)
			if host.Priority != nil {
				out.Priority = *host.Priority
			}
		}
	case TypeTXT:
		var txt struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(r.Value, &txt); err == nil {
			out.Content = txt.Text
		}
	case TypeSRV:
		var srv struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Priority int    `json:"priority"`
			Weight   int    `json:"weight"`
		}
		if err := json.Unmarshal(r.Value, &srv); err == nil {
			out.SRV = &SRVData{Priority: srv.Priority, Weight: srv.Weight, Port: srv.Port, Target: NormalizeDomain(srv.Host)}
		}
	}
	return out
}

// toArvan builds the request body for a record. Arvan wants the sub-name
// relative to the zone, with "@" for the apex.
func toArvan(rec Record, zone string) (map[string]any, error) {
	sub := Subname(rec.Name, zone)
	if sub == "" {
		sub = "@"
	}
	ttl := rec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	body := map[string]any{
		"type": strings.ToLower(string(rec.Type)),
		"name": sub,
		"ttl":  ttl,
	}
	switch rec.Type {
	case TypeA, TypeAAAA:
		body["value"] = []map[string]string{{"ip": strings.TrimSpace(rec.Content)}}
		body["cloud"] = rec.Proxied
	case TypeCNAME:
		body["value"] = map[string]string{"host": NormalizeDomain(rec.Content)}
		body["cloud"] = rec.Proxied
	case TypeNS:
		body["value"] = map[string]string{"host": NormalizeDomain(rec.Content)}
	case TypeTXT:
		body["value"] = map[string]string{"text": rec.Content}
	case TypeMX:
		body["value"] = map[string]any{"host": NormalizeDomain(rec.Content), "priority": rec.Priority}
	case TypeSRV:
		if rec.SRV == nil {
			return nil, &Error{Provider: "arvancloud", Op: "encode-record", Kind: KindValidation,
				Message: "SRV record is missing its data", Remediation: "populate priority, weight, port and target"}
		}
		body["value"] = map[string]any{
			"host": rec.SRV.Target, "port": rec.SRV.Port,
			"priority": rec.SRV.Priority, "weight": rec.SRV.Weight,
		}
	default:
		return nil, &Error{Provider: "arvancloud", Op: "encode-record", Kind: KindUnsupported,
			Message:     fmt.Sprintf("ArvanCloud DNS does not expose %s records through this API", rec.Type),
			Remediation: "create the record by hand in the ArvanCloud panel, or use a provider that supports it"}
	}
	return body, nil
}

// ListRecords lists a zone's records. zoneRef is the domain name.
func (a *Arvan) ListRecords(ctx context.Context, zoneRef string, filter RecordFilter) ([]Record, error) {
	zone := NormalizeDomain(zoneRef)
	if zone == "" {
		return nil, &Error{Provider: "arvancloud", Op: "list-records", Kind: KindValidation,
			Message: "zone is empty", Remediation: "resolve the zone first (ResolveZone / --domain)"}
	}
	var out []Record
	for page := 1; page <= 100; page++ {
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if filter.Type != "" {
			q.Set("type", strings.ToLower(string(filter.Type)))
		}
		if filter.Name != "" {
			if sub := Subname(filter.Name, zone); sub != "" {
				q.Set("search", sub)
			}
		}
		env, err := a.do(ctx, http.MethodGet, "/domains/"+url.PathEscape(zone)+"/dns-records", q, nil, "list-records")
		if err != nil {
			return nil, err
		}
		var recs []arvanRecord
		if err := json.Unmarshal(env.Data, &recs); err != nil {
			return nil, &Error{Provider: "arvancloud", Op: "list-records", Kind: KindServer,
				Message: "could not decode the record list: " + err.Error(), Cause: err}
		}
		for _, r := range recs {
			rec := r.toRecord(zone)
			if filter.matches(rec) {
				out = append(out, rec)
			}
		}
		if env.Meta == nil || env.Meta.LastPage <= page || len(recs) == 0 {
			break
		}
	}
	return out, nil
}

// CreateRecord creates a record.
func (a *Arvan) CreateRecord(ctx context.Context, zoneRef string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	zone := NormalizeDomain(zoneRef)
	body, err := toArvan(rec, zone)
	if err != nil {
		return nil, err
	}
	env, err := a.do(ctx, http.MethodPost, "/domains/"+url.PathEscape(zone)+"/dns-records", nil, body, "create-record")
	if err != nil {
		return nil, err
	}
	return decodeArvanRecord(env, zone, "create-record")
}

// UpdateRecord replaces a record.
func (a *Arvan) UpdateRecord(ctx context.Context, zoneRef, id string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, &Error{Provider: "arvancloud", Op: "update-record", Kind: KindValidation,
			Message: "record id is empty", Remediation: "list the record first to obtain its id"}
	}
	zone := NormalizeDomain(zoneRef)
	body, err := toArvan(rec, zone)
	if err != nil {
		return nil, err
	}
	path := "/domains/" + url.PathEscape(zone) + "/dns-records/" + url.PathEscape(id)
	env, err := a.do(ctx, http.MethodPut, path, nil, body, "update-record")
	if err != nil {
		return nil, err
	}
	return decodeArvanRecord(env, zone, "update-record")
}

// DeleteRecord removes a record.
func (a *Arvan) DeleteRecord(ctx context.Context, zoneRef, id string) error {
	if strings.TrimSpace(id) == "" {
		return &Error{Provider: "arvancloud", Op: "delete-record", Kind: KindValidation,
			Message: "record id is empty", Remediation: "list the record first to obtain its id"}
	}
	zone := NormalizeDomain(zoneRef)
	path := "/domains/" + url.PathEscape(zone) + "/dns-records/" + url.PathEscape(id)
	_, err := a.do(ctx, http.MethodDelete, path, nil, nil, "delete-record")
	return err
}

// SetProxied toggles Arvan's "cloud" flag, the equivalent of the orange cloud.
func (a *Arvan) SetProxied(ctx context.Context, zoneRef, recordID string, on bool) (*Record, error) {
	zone := NormalizeDomain(zoneRef)
	recs, err := a.ListRecords(ctx, zone, RecordFilter{})
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		if rec.ID != recordID {
			continue
		}
		switch rec.Type {
		case TypeA, TypeAAAA, TypeCNAME:
		default:
			return nil, &Error{Provider: "arvancloud", Op: "set-proxied", Kind: KindUnsupported,
				Message:     fmt.Sprintf("%s records cannot be put behind the ArvanCloud CDN", rec.Type),
				Remediation: "only a, aaaa and cname records carry the cloud flag"}
		}
		rec.Proxied = on
		return a.UpdateRecord(ctx, zone, recordID, rec)
	}
	return nil, &Error{Provider: "arvancloud", Op: "set-proxied", Kind: KindNotFound,
		Message:     fmt.Sprintf("record %s not found in zone %s", recordID, zone),
		Remediation: "list the zone's records to obtain a current id"}
}

func decodeArvanRecord(env *arvanEnvelope, zone, op string) (*Record, error) {
	var r arvanRecord
	if err := json.Unmarshal(env.Data, &r); err != nil {
		return nil, &Error{Provider: "arvancloud", Op: op, Kind: KindServer,
			Message: "could not decode the record: " + err.Error(), Cause: err}
	}
	out := r.toRecord(zone)
	return &out, nil
}

var (
	_ Provider        = (*Arvan)(nil)
	_ ProxyController = (*Arvan)(nil)
)
