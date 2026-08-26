package dns

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// zoneProvider is a Provider that stores records the way DNS does: several
// values may share one name. A map keyed by name alone would hide the exact bug
// these tests exist for.
type zoneProvider struct {
	mu      sync.Mutex
	records []Record
	nextID  int
	// createErr fails the next CreateRecord.
	createErr error
	deletes   []string
}

func newZoneProvider() *zoneProvider { return &zoneProvider{} }

func (z *zoneProvider) Name() string { return "zonetest" }
func (z *zoneProvider) VerifyCredentials(context.Context) (*Identity, error) {
	return &Identity{}, nil
}
func (z *zoneProvider) ListZones(context.Context) ([]Zone, error) {
	return []Zone{{ID: "zone-1", Name: "example.com"}}, nil
}
func (z *zoneProvider) FindZone(_ context.Context, name string) (*Zone, error) {
	if NormalizeDomain(name) == "example.com" {
		return &Zone{ID: "zone-1", Name: "example.com"}, nil
	}
	return nil, &Error{Op: "find-zone", Kind: KindNotFound, Message: "no such zone: " + name}
}
func (z *zoneProvider) ListRecords(_ context.Context, _ string, f RecordFilter) ([]Record, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	var out []Record
	for _, r := range z.records {
		if f.matches(r) {
			out = append(out, r)
		}
	}
	return out, nil
}
func (z *zoneProvider) CreateRecord(_ context.Context, _ string, rec Record) (*Record, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.createErr != nil {
		err := z.createErr
		z.createErr = nil
		return nil, err
	}
	z.nextID++
	rec.ID = string(rune('a'+z.nextID-1)) + "-id"
	z.records = append(z.records, rec)
	return &rec, nil
}
func (z *zoneProvider) UpdateRecord(_ context.Context, _, id string, rec Record) (*Record, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for i, r := range z.records {
		if r.ID == id {
			rec.ID = id
			z.records[i] = rec
			return &rec, nil
		}
	}
	return nil, &Error{Op: "update-record", Kind: KindNotFound, Message: "no record " + id}
}
func (z *zoneProvider) DeleteRecord(_ context.Context, _, id string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.deletes = append(z.deletes, id)
	for i, r := range z.records {
		if r.ID == id {
			z.records = append(z.records[:i], z.records[i+1:]...)
			return nil
		}
	}
	return &Error{Op: "delete-record", Kind: KindNotFound, Message: "no record " + id}
}

func (z *zoneProvider) txtAt(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	var out []string
	for _, r := range z.records {
		if r.Type == TypeTXT && NormalizeDomain(r.Name) == NormalizeDomain(name) {
			out = append(out, r.Content)
		}
	}
	return out
}

func TestSolverAddsASecondRecordAtTheSameNameInsteadOfReplacing(t *testing.T) {
	// The bug: issuing example.com together with *.example.com produces two
	// authorizations whose dns-01 challenges live at the SAME name with
	// DIFFERENT values, and the CA checks both. EnsureRecord upserts by
	// (type, name) and would leave only the second — satisfying one
	// authorization and failing the other, on a zone that reads as correct
	// afterwards because the surviving record IS valid, just not the one being
	// checked. Present must ADD.
	p := newZoneProvider()
	s := &ACMESolver{Provider: p}
	ctx := context.Background()

	if err := s.Present(ctx, "_acme-challenge.example.com", "value-apex"); err != nil {
		t.Fatal(err)
	}
	if err := s.Present(ctx, "_acme-challenge.example.com", "value-wildcard"); err != nil {
		t.Fatal(err)
	}

	got := p.txtAt("_acme-challenge.example.com")
	if len(got) != 2 {
		t.Fatalf("the zone holds %d record(s): %v — both challenges must coexist", len(got), got)
	}
	if !contains(got, "value-apex") || !contains(got, "value-wildcard") {
		t.Fatalf("got %v, want both values", got)
	}
}

func TestCleanUpRemovesOnlyItsOwnRecord(t *testing.T) {
	// Deleting by NAME would take the sibling challenge with it, which is the
	// same failure as the upsert, just at the other end of the run.
	p := newZoneProvider()
	s := &ACMESolver{Provider: p}
	ctx := context.Background()
	_ = s.Present(ctx, "_acme-challenge.example.com", "value-apex")
	_ = s.Present(ctx, "_acme-challenge.example.com", "value-wildcard")

	if err := s.CleanUp(ctx, "_acme-challenge.example.com", "value-apex"); err != nil {
		t.Fatal(err)
	}
	got := p.txtAt("_acme-challenge.example.com")
	if len(got) != 1 || got[0] != "value-wildcard" {
		t.Fatalf("got %v, want only the wildcard's record left", got)
	}
}

func TestCleanUpFindsTheRecordByContentAfterARestart(t *testing.T) {
	// A restart between publishing and cleanup loses the remembered record ID.
	// Falling back to "delete everything at this name" would remove a sibling
	// challenge; the fallback matches on CONTENT.
	p := newZoneProvider()
	warm := &ACMESolver{Provider: p}
	ctx := context.Background()
	_ = warm.Present(ctx, "_acme-challenge.example.com", "value-apex")
	_ = warm.Present(ctx, "_acme-challenge.example.com", "value-wildcard")

	cold := &ACMESolver{Provider: p} // no memory of what was created
	if err := cold.CleanUp(ctx, "_acme-challenge.example.com", "value-apex"); err != nil {
		t.Fatal(err)
	}
	got := p.txtAt("_acme-challenge.example.com")
	if len(got) != 1 || got[0] != "value-wildcard" {
		t.Fatalf("got %v, want only the wildcard's record left", got)
	}
}

func TestCleanUpOfARecordThatIsAlreadyGoneIsNotAnError(t *testing.T) {
	// CleanUp runs on the failure path too. Turning "someone already tidied
	// this" into an error would mask the reason issuance actually failed.
	p := newZoneProvider()
	s := &ACMESolver{Provider: p}
	if err := s.CleanUp(context.Background(), "_acme-challenge.example.com", "never-published"); err != nil {
		t.Fatalf("got %v, want no error", err)
	}
}

func TestSolverPublishesIntoTheOwningZoneOfASubdomain(t *testing.T) {
	// A challenge for team.example.com is published in the example.com zone.
	p := newZoneProvider()
	s := &ACMESolver{Provider: p}
	if err := s.Present(context.Background(), "_acme-challenge.team.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if got := p.txtAt("_acme-challenge.team.example.com"); len(got) != 1 {
		t.Fatalf("got %v, want the record in the example.com zone", got)
	}
}

func TestSolverWithoutAProviderSaysWhatToDo(t *testing.T) {
	s := &ACMESolver{}
	err := s.Present(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("error %q does not tell the operator what to do about it", err)
	}
}

func TestPresentReportsAProviderFailureWithTheRecordName(t *testing.T) {
	p := newZoneProvider()
	p.createErr = &Error{Op: "create-record", Kind: KindPermission, Message: "token lacks DNS:Edit"}
	s := &ACMESolver{Provider: p}
	err := s.Present(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "_acme-challenge.example.com") {
		t.Errorf("error %q does not name the record that could not be published", err)
	}
}

func TestChallengeRecordsGetAShortTTL(t *testing.T) {
	// The record lives for one validation. A long TTL only means the next
	// attempt reads a cached stale value.
	p := newZoneProvider()
	s := &ACMESolver{Provider: p}
	_ = s.Present(context.Background(), "_acme-challenge.example.com", "v")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.records[0].TTL > 300 {
		t.Fatalf("TTL is %d; a challenge record should be short-lived", p.records[0].TTL)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
