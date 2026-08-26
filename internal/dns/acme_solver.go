package dns

// The bridge that was missing: three working DNS providers on one side, an ACME
// client that needs a TXT record published on the other, and nothing joining
// them. Every provider here could already create and delete records; the panel
// just never asked one to do it for a certificate.

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// ACMESolver publishes ACME DNS-01 challenge records through a Provider.
//
// It satisfies cert.Solver structurally, so internal/cert does not import this
// package and this package does not import internal/cert.
type ACMESolver struct {
	// Provider is the DNS backend holding the zone. Required.
	Provider Provider
	// Resolver is used to resolve the owning zone. Optional.
	Resolver Resolver
	// TTL for challenge records. Short by design — the record exists for the
	// length of one validation and a long TTL only means the next attempt reads
	// a cached stale value.
	TTL int

	mu sync.Mutex
	// created maps fqdn|value to the provider record ID, so CleanUp deletes the
	// exact record this solver made. Matching on name alone would delete a
	// second, still-needed challenge record at the same name — which is the
	// normal case when a wildcard and its apex are issued together.
	created map[string]createdRecord
}

type createdRecord struct {
	zoneRef  string
	recordID string
}

const acmeChallengeTTL = 60

// Present adds a TXT record at fqdn carrying value.
//
// It ADDS. It deliberately does not use EnsureRecord, which upserts by (type,
// name): issuing example.com together with *.example.com produces two
// challenges at the same name with different values, and both must be present
// at once. An upsert would leave whichever was written last and fail the other
// authorization — on a zone that looks perfectly correct by the time anyone
// inspects it, because the surviving record is valid, just not the one the CA
// was checking.
func (s *ACMESolver) Present(ctx context.Context, fqdn, value string) error {
	if s.Provider == nil {
		return &Error{Op: "acme-present", Kind: KindValidation,
			Message:     "no DNS provider was supplied to publish the challenge record",
			Remediation: "register a DNS credential for this domain, then retry issuance"}
	}
	zoneRef, err := s.zoneRef(ctx, fqdn)
	if err != nil {
		return err
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = acmeChallengeTTL
	}
	rec, err := s.Provider.CreateRecord(ctx, zoneRef, Record{
		Type:    TypeTXT,
		Name:    NormalizeDomain(fqdn),
		Content: value,
		TTL:     ttl,
		Comment: "ACME dns-01 challenge (ForgePanel) — safe to delete",
	})
	if err != nil {
		return fmt.Errorf("publish dns-01 record at %s: %w", fqdn, err)
	}
	s.mu.Lock()
	if s.created == nil {
		s.created = map[string]createdRecord{}
	}
	s.created[key(fqdn, value)] = createdRecord{zoneRef: zoneRef, recordID: rec.ID}
	s.mu.Unlock()
	return nil
}

// CleanUp removes the record Present created, and only that one.
//
// A record that is already gone is not an error: CleanUp runs on the failure
// path too, and turning "someone already tidied this" into an error would mask
// the actual reason issuance failed.
func (s *ACMESolver) CleanUp(ctx context.Context, fqdn, value string) error {
	s.mu.Lock()
	rec, known := s.created[key(fqdn, value)]
	delete(s.created, key(fqdn, value))
	s.mu.Unlock()

	if known && rec.recordID != "" {
		if err := s.Provider.DeleteRecord(ctx, rec.zoneRef, rec.recordID); err != nil && !IsNotFound(err) {
			return fmt.Errorf("remove dns-01 record at %s: %w", fqdn, err)
		}
		return nil
	}

	// No remembered ID — a restart between publishing and cleanup. Fall back to
	// finding the record by its exact CONTENT, never by name alone.
	zoneRef, err := s.zoneRef(ctx, fqdn)
	if err != nil {
		return err
	}
	recs, err := s.Provider.ListRecords(ctx, zoneRef, RecordFilter{Type: TypeTXT, Name: NormalizeDomain(fqdn)})
	if err != nil {
		return err
	}
	for _, r := range recs {
		if strings.Trim(strings.TrimSpace(r.Content), `"`) != value {
			continue
		}
		if err := s.Provider.DeleteRecord(ctx, zoneRef, r.ID); err != nil && !IsNotFound(err) {
			return fmt.Errorf("remove dns-01 record at %s: %w", fqdn, err)
		}
	}
	return nil
}

func key(fqdn, value string) string { return NormalizeDomain(fqdn) + "|" + value }

// zoneRef finds the provider zone that owns fqdn, walking up the parent chain so
// that a challenge for _acme-challenge.team.example.com is published in the
// example.com zone.
func (s *ACMESolver) zoneRef(ctx context.Context, fqdn string) (string, error) {
	res, err := ResolveZone(ctx, s.Provider, s.Resolver, fqdn)
	if err != nil {
		return "", err
	}
	return res.Zone.Ref(), nil
}
