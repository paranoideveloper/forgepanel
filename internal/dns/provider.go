package dns

import (
	"context"
	"fmt"
	"strings"
)

// Credentials is a provider-neutral bag of secret material. Each provider
// documents the keys it needs through ProviderInfo.CredentialFields.
type Credentials map[string]string

// Get returns a trimmed value.
func (c Credentials) Get(key string) string { return strings.TrimSpace(c[key]) }

// Require returns a validation error naming every missing key at once, so an
// operator fixes the whole form in one pass instead of one field per attempt.
func (c Credentials) Require(provider string, keys ...string) error {
	var missing []string
	for _, k := range keys {
		if c.Get(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &Error{
		Provider: provider, Op: "credentials", Kind: KindValidation,
		Message:     fmt.Sprintf("missing credential field(s): %s", strings.Join(missing, ", ")),
		Remediation: fmt.Sprintf("supply %s when registering the %s credential", strings.Join(missing, " and "), provider),
	}
}

// RecordFilter narrows a ListRecords call. A zero filter lists everything.
type RecordFilter struct {
	Type RecordType
	// Name is an exact fully-qualified match when set.
	Name string
	// Contains matches any record whose name contains this substring. Providers
	// without server-side support filter locally.
	Contains string
}

func (f RecordFilter) matches(r Record) bool {
	if f.Type != "" && r.Type != f.Type {
		return false
	}
	if f.Name != "" && NormalizeDomain(f.Name) != NormalizeDomain(r.Name) {
		return false
	}
	if f.Contains != "" && !strings.Contains(NormalizeDomain(r.Name), strings.ToLower(f.Contains)) {
		return false
	}
	return true
}

// Provider is the DNS backend contract. Every implemented provider satisfies
// all of it; capabilities beyond this (proxying, zone settings) are separate
// optional interfaces so a caller can feature-detect with a type assertion.
type Provider interface {
	// Name is the registry key, e.g. "cloudflare".
	Name() string
	// VerifyCredentials proves the credential works and reports what it is. It
	// must return a KindPermission error naming the missing scope when the
	// credential is valid but cannot do what the panel needs.
	VerifyCredentials(ctx context.Context) (*Identity, error)
	// ListZones returns every zone the credential can see.
	ListZones(ctx context.Context) ([]Zone, error)
	// FindZone returns the zone whose name matches exactly, or a KindNotFound
	// error.
	FindZone(ctx context.Context, name string) (*Zone, error)
	// ListRecords lists records in a zone, narrowed by filter.
	ListRecords(ctx context.Context, zoneRef string, filter RecordFilter) ([]Record, error)
	// CreateRecord creates a record and returns it with its provider ID.
	CreateRecord(ctx context.Context, zoneRef string, rec Record) (*Record, error)
	// UpdateRecord replaces the record with the given ID.
	UpdateRecord(ctx context.Context, zoneRef, id string, rec Record) (*Record, error)
	// DeleteRecord removes the record with the given ID.
	DeleteRecord(ctx context.Context, zoneRef, id string) error
}

// ProxyController is implemented by providers with a CDN layer whose per-record
// proxy flag ("orange cloud" on Cloudflare, "cloud" on ArvanCloud) can be
// toggled independently of the record content.
type ProxyController interface {
	SetProxied(ctx context.Context, zoneRef, recordID string, on bool) (*Record, error)
}

// TLSMode is a zone-level origin-pull TLS policy.
type TLSMode string

// Zone TLS modes. Off and Flexible are named for completeness but the wizard
// never selects them: they either break TLS inbounds or strip the encryption
// the protocols depend on.
const (
	TLSOff        TLSMode = "off"
	TLSFlexible   TLSMode = "flexible"
	TLSFull       TLSMode = "full"
	TLSFullStrict TLSMode = "strict"
)

// ZoneSettings is the subset of edge configuration that decides whether a
// WebSocket/gRPC/XHTTP inbound behind the CDN actually carries traffic.
// Pointer fields are "leave alone".
type ZoneSettings struct {
	// SSL is the origin-pull mode: full (origin serves TLS, cert not verified)
	// or strict (origin cert must be valid/CF-Origin-CA issued).
	SSL *TLSMode `json:"ssl,omitempty"`
	// AlwaysUseHTTPS 301-redirects plain HTTP at the edge.
	AlwaysUseHTTPS *bool `json:"always_use_https,omitempty"`
	// MinTLSVersion is "1.0".."1.3" — the floor the edge accepts from clients.
	MinTLSVersion *string `json:"min_tls_version,omitempty"`
	// TLS13 enables TLS 1.3 at the edge.
	TLS13 *bool `json:"tls_1_3,omitempty"`
	// GRPC must be on for a gRPC inbound to survive the edge.
	GRPC *bool `json:"grpc,omitempty"`
	// WebSockets must be on for a ws/httpupgrade inbound to survive the edge.
	WebSockets *bool `json:"websockets,omitempty"`
}

// SettingResult reports one applied setting.
type SettingResult struct {
	Setting string `json:"setting"`
	Value   string `json:"value"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
	// Remediation is populated when Applied is false.
	Remediation string `json:"remediation,omitempty"`
}

// ZoneSettingsController is implemented by providers that expose edge settings.
type ZoneSettingsController interface {
	GetZoneSettings(ctx context.Context, zoneRef string) (map[string]string, error)
	ApplyZoneSettings(ctx context.Context, zoneRef string, s ZoneSettings) ([]SettingResult, error)
}

// EnsureResult says what an upsert did.
type EnsureResult struct {
	Record Record `json:"record"`
	Action string `json:"action"` // created | updated | unchanged
}

// EnsureRecord upserts a record by (type, name): it creates the record when
// absent, updates it when any managed field differs, and reports "unchanged"
// otherwise. Idempotence matters here because the wizard and the rotation pool
// both re-run against zones they have already touched.
func EnsureRecord(ctx context.Context, p Provider, zoneRef string, rec Record) (*EnsureResult, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if rec.TTL == 0 {
		rec.TTL = DefaultTTL
	}
	rec.Name = NormalizeDomain(rec.Name)
	existing, err := p.ListRecords(ctx, zoneRef, RecordFilter{Type: rec.Type, Name: rec.Name})
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		created, err := p.CreateRecord(ctx, zoneRef, rec)
		if err != nil {
			return nil, err
		}
		return &EnsureResult{Record: *created, Action: "created"}, nil
	}
	current := existing[0]
	if recordEquivalent(current, rec) {
		return &EnsureResult{Record: current, Action: "unchanged"}, nil
	}
	updated, err := p.UpdateRecord(ctx, zoneRef, current.ID, rec)
	if err != nil {
		return nil, err
	}
	return &EnsureResult{Record: *updated, Action: "updated"}, nil
}

func recordEquivalent(current, want Record) bool {
	if current.Type != want.Type {
		return false
	}
	if NormalizeDomain(current.Name) != NormalizeDomain(want.Name) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(current.Content), strings.TrimSpace(want.Content)) {
		return false
	}
	if current.Proxied != want.Proxied {
		return false
	}
	// TTL comparison is deliberately loose, because two providers legitimately
	// return something other than what was asked for:
	//
	//   - a proxied record is served on the CDN's own TTL (Cloudflare reports
	//     1, "automatic") and a custom value is rejected outright, so the field
	//     carries no information and comparing it would rewrite every proxied
	//     record on every run;
	//   - deSEC clamps up to the zone minimum, so "the provider gave us at
	//     least what we asked for" counts as equal.
	if !want.Proxied && want.TTL != 0 && current.TTL != 0 && current.TTL < want.TTL {
		return false
	}
	if want.Type == TypeSRV {
		if current.SRV == nil || want.SRV == nil {
			return current.SRV == want.SRV
		}
		if *current.SRV != *want.SRV {
			return false
		}
	}
	if want.Type == TypeMX && current.Priority != want.Priority {
		return false
	}
	return true
}

// DeleteByName removes every record matching (type, name). It returns the
// number deleted; deleting a name that does not exist is not an error.
func DeleteByName(ctx context.Context, p Provider, zoneRef string, rtype RecordType, name string) (int, error) {
	recs, err := p.ListRecords(ctx, zoneRef, RecordFilter{Type: rtype, Name: name})
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, r := range recs {
		if err := p.DeleteRecord(ctx, zoneRef, r.ID); err != nil {
			if IsNotFound(err) {
				continue
			}
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}
