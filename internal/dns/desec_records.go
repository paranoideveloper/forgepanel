package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// desecRRset is deSEC's record object: one per (subname, type).
type desecRRset struct {
	Domain  string   `json:"domain,omitempty"`
	Subname string   `json:"subname"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
	TTL     int      `json:"ttl"`
}

// rrsetID is the synthetic record id: "subname/type", matching the REST path.
// The apex uses "@" because an empty path segment is not addressable.
func rrsetID(subname, rtype string) string {
	if subname == "" {
		subname = "@"
	}
	return subname + "/" + strings.ToUpper(rtype)
}

func parseRRsetID(id string) (subname, rtype string, err error) {
	parts := strings.SplitN(strings.TrimSpace(id), "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", &Error{Provider: "desec", Op: "parse-record-id", Kind: KindValidation,
			Message:     fmt.Sprintf("record id %q is not in deSEC's subname/TYPE form", id),
			Remediation: "list the records first and use the id the panel returns, e.g. \"ws-node1/A\""}
	}
	subname = parts[0]
	if subname == "@" {
		subname = ""
	}
	return subname, strings.ToUpper(parts[1]), nil
}

// toRecord converts an RRset into one neutral Record per value. deSEC has no
// CDN, so Proxied is always false.
func (rr desecRRset) toRecords(zone string) []Record {
	name := NormalizeDomain(zone)
	if rr.Subname != "" {
		name = NormalizeDomain(rr.Subname) + "." + name
	}
	rtype := RecordType(strings.ToUpper(rr.Type))
	out := make([]Record, 0, len(rr.Records))
	for _, value := range rr.Records {
		rec := Record{
			ID: rrsetID(rr.Subname, rr.Type), Type: rtype, Name: name, TTL: rr.TTL,
		}
		switch rtype {
		case TypeTXT:
			// deSEC stores TXT values in presentation format, i.e. quoted.
			rec.Content = unquoteTXT(value)
		case TypeCNAME, TypeNS:
			rec.Content = NormalizeDomain(value)
		case TypeMX:
			// "10 mail.example.com."
			fields := strings.Fields(value)
			if len(fields) == 2 {
				if p, err := strconv.Atoi(fields[0]); err == nil {
					rec.Priority = p
				}
				rec.Content = NormalizeDomain(fields[1])
			} else {
				rec.Content = NormalizeDomain(value)
			}
		case TypeSRV:
			// "10 5 443 edge.example.com."
			fields := strings.Fields(value)
			if len(fields) == 4 {
				srv := &SRVData{Target: NormalizeDomain(fields[3])}
				srv.Priority, _ = strconv.Atoi(fields[0])
				srv.Weight, _ = strconv.Atoi(fields[1])
				srv.Port, _ = strconv.Atoi(fields[2])
				rec.SRV = srv
			}
			rec.Content = value
		default:
			rec.Content = value
		}
		out = append(out, rec)
	}
	return out
}

func unquoteTXT(value string) string {
	v := strings.TrimSpace(value)
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		inner := v[1 : len(v)-1]
		// A long TXT is split into adjacent quoted chunks: "aaa" "bbb".
		inner = strings.ReplaceAll(inner, `" "`, "")
		return strings.ReplaceAll(inner, `\"`, `"`)
	}
	return v
}

func quoteTXT(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// desecValue renders a neutral record into deSEC's presentation format. Targets
// need the trailing root dot or deSEC treats them as relative.
func desecValue(rec Record) (string, error) {
	switch rec.Type {
	case TypeA, TypeAAAA:
		return strings.TrimSpace(rec.Content), nil
	case TypeCNAME, TypeNS:
		return NormalizeDomain(rec.Content) + ".", nil
	case TypeTXT:
		return quoteTXT(rec.Content), nil
	case TypeMX:
		return fmt.Sprintf("%d %s.", rec.Priority, NormalizeDomain(rec.Content)), nil
	case TypeCAA:
		return strings.TrimSpace(rec.Content), nil
	case TypeSRV:
		if rec.SRV == nil {
			return "", &Error{Provider: "desec", Op: "encode-record", Kind: KindValidation,
				Message: "SRV record is missing its data", Remediation: "populate priority, weight, port and target"}
		}
		return fmt.Sprintf("%d %d %d %s.", rec.SRV.Priority, rec.SRV.Weight, rec.SRV.Port, NormalizeDomain(rec.SRV.Target)), nil
	}
	return "", &Error{Provider: "desec", Op: "encode-record", Kind: KindUnsupported,
		Message:     fmt.Sprintf("deSEC support for %s records is not available in this build", rec.Type),
		Remediation: "create the RRset by hand at https://desec.io, or use a provider that supports it"}
}

// ListRecords lists a zone's RRsets, flattened to one Record per value.
func (d *Desec) ListRecords(ctx context.Context, zoneRef string, filter RecordFilter) ([]Record, error) {
	zone := NormalizeDomain(zoneRef)
	if zone == "" {
		return nil, &Error{Provider: "desec", Op: "list-records", Kind: KindValidation,
			Message: "zone is empty", Remediation: "resolve the zone first (ResolveZone / --domain)"}
	}
	path := "/domains/" + zone + "/rrsets/"
	var query []string
	if filter.Type != "" {
		query = append(query, "type="+strings.ToUpper(string(filter.Type)))
	}
	if filter.Name != "" {
		query = append(query, "subname="+Subname(filter.Name, zone))
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}
	_, raw, err := d.do(ctx, http.MethodGet, path, nil, "list-records")
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var rrsets []desecRRset
	if err := json.Unmarshal(raw, &rrsets); err != nil {
		return nil, &Error{Provider: "desec", Op: "list-records", Kind: KindServer,
			Message: "could not decode the RRset list: " + err.Error(), Cause: err}
	}
	var out []Record
	for _, rr := range rrsets {
		for _, rec := range rr.toRecords(zone) {
			if filter.matches(rec) {
				out = append(out, rec)
			}
		}
	}
	return out, nil
}

// CreateRecord creates an RRset holding a single value.
func (d *Desec) CreateRecord(ctx context.Context, zoneRef string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if rec.Proxied {
		return nil, &Error{Provider: "desec", Op: "create-record", Kind: KindUnsupported,
			Message:     "deSEC has no CDN, so a record cannot be proxied",
			Remediation: "deSEC serves authoritative DNS only. Leave proxied off — which is what a REALITY or direct-TLS inbound wants anyway — or move that hostname to a CDN provider such as Cloudflare."}
	}
	zone := NormalizeDomain(zoneRef)
	value, err := desecValue(rec)
	if err != nil {
		return nil, err
	}
	ttl := rec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	body := desecRRset{
		Subname: Subname(rec.Name, zone),
		Type:    string(rec.Type),
		Records: []string{value},
		TTL:     ttl,
	}
	_, raw, err := d.do(ctx, http.MethodPost, "/domains/"+zone+"/rrsets/", body, "create-record")
	if err != nil {
		// deSEC clamps the TTL to the domain minimum and answers 400; retry once
		// at that minimum rather than making the operator work it out.
		if e, ok := AsError(err); ok && e.Kind == KindValidation && strings.Contains(strings.ToLower(e.Message), "ttl") {
			if min := d.minimumTTL(ctx, zone); min > ttl {
				body.TTL = min
				_, raw, err = d.do(ctx, http.MethodPost, "/domains/"+zone+"/rrsets/", body, "create-record")
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return decodeDesecRRset(raw, zone, "create-record")
}

// minimumTTL fetches the domain's floor; 0 when it cannot be determined.
func (d *Desec) minimumTTL(ctx context.Context, zone string) int {
	z, err := d.FindZone(ctx, zone)
	if err != nil || z == nil {
		return 0
	}
	return z.MinimumTTL
}

// UpdateRecord replaces an RRset's values. id is "subname/TYPE".
func (d *Desec) UpdateRecord(ctx context.Context, zoneRef, id string, rec Record) (*Record, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if rec.Proxied {
		return nil, &Error{Provider: "desec", Op: "update-record", Kind: KindUnsupported,
			Message:     "deSEC has no CDN, so a record cannot be proxied",
			Remediation: "leave proxied off for deSEC-hosted names"}
	}
	zone := NormalizeDomain(zoneRef)
	subname, rtype, err := parseRRsetID(id)
	if err != nil {
		return nil, err
	}
	value, err := desecValue(rec)
	if err != nil {
		return nil, err
	}
	ttl := rec.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	path := "/domains/" + zone + "/rrsets/" + rrsetPathSegment(subname) + "/" + rtype + "/"
	_, raw, err := d.do(ctx, http.MethodPatch, path, map[string]any{"records": []string{value}, "ttl": ttl}, "update-record")
	if err != nil {
		return nil, err
	}
	return decodeDesecRRset(raw, zone, "update-record")
}

// DeleteRecord empties an RRset, which is how deSEC deletes one.
func (d *Desec) DeleteRecord(ctx context.Context, zoneRef, id string) error {
	zone := NormalizeDomain(zoneRef)
	subname, rtype, err := parseRRsetID(id)
	if err != nil {
		return err
	}
	path := "/domains/" + zone + "/rrsets/" + rrsetPathSegment(subname) + "/" + rtype + "/"
	_, _, err = d.do(ctx, http.MethodDelete, path, nil, "delete-record")
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// rrsetPathSegment renders the apex as "@" so the URL stays well-formed.
func rrsetPathSegment(subname string) string {
	if subname == "" {
		return "@"
	}
	return subname
}

func decodeDesecRRset(raw []byte, zone, op string) (*Record, error) {
	var rr desecRRset
	if err := json.Unmarshal(raw, &rr); err != nil {
		return nil, &Error{Provider: "desec", Op: op, Kind: KindServer,
			Message: "could not decode the RRset: " + err.Error(), Cause: err}
	}
	recs := rr.toRecords(zone)
	if len(recs) == 0 {
		return nil, &Error{Provider: "desec", Op: op, Kind: KindServer,
			Message:     "deSEC returned an RRset with no values",
			Remediation: "re-list the zone's records to confirm the write landed"}
	}
	return &recs[0], nil
}

var _ Provider = (*Desec)(nil)
