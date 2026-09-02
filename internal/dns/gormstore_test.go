package dns

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newGormStore(t *testing.T) *GormStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dns.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	requireNoError(t, err)
	store, err := NewGormStore(db)
	requireNoError(t, err)
	return store
}

func TestNewGormStoreRequiresADatabase(t *testing.T) {
	_, err := NewGormStore(nil)
	e := requireKind(t, err, KindValidation)
	requireContains(t, e.Remediation, "*gorm.DB", "missing db remediation")
}

func TestGormStoreCredentialRoundTrip(t *testing.T) {
	store := newGormStore(t)
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	requireNoError(t, store.PutCredential(CredentialRecord{
		ID: "cf1", Provider: "cloudflare", Label: "main",
		Secret: []byte{0xde, 0xad, 0xbe, 0xef}, CreatedAt: now,
	}))

	got, err := store.GetCredential("cf1")
	requireNoError(t, err)
	if got == nil {
		t.Fatal("expected the credential to be found")
	}
	if !bytes.Equal(got.Secret, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("the ciphertext did not round trip: %x", got.Secret)
	}
	if got.Provider != "cloudflare" || got.Label != "main" {
		t.Fatalf("unexpected metadata: %+v", got)
	}

	// A missing id is (nil, nil), not an error — that is the contract the
	// credential store relies on to distinguish "absent" from "broken".
	missing, err := store.GetCredential("nope")
	requireNoError(t, err)
	if missing != nil {
		t.Fatalf("expected nil for a missing credential, got %+v", missing)
	}

	list, err := store.ListCredentials()
	requireNoError(t, err)
	if len(list) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(list))
	}

	requireNoError(t, store.DeleteCredential("cf1"))
	list, err = store.ListCredentials()
	requireNoError(t, err)
	if len(list) != 0 {
		t.Fatalf("expected the credential to be gone, got %d", len(list))
	}
}

// The full credential store must work over the real database, encryption
// included.
func TestGormStoreWithCredentialStore(t *testing.T) {
	store := newGormStore(t)
	key, err := GenerateKey()
	requireNoError(t, err)
	enc, err := NewAESGCM(key)
	requireNoError(t, err)
	cs, err := NewCredentialStore(store, enc)
	requireNoError(t, err)

	_, err = cs.Put("cf1", "cloudflare", "main", Credentials{"api_token": "super-secret"})
	requireNoError(t, err)

	raw, err := store.GetCredential("cf1")
	requireNoError(t, err)
	if bytes.Contains(raw.Secret, []byte("super-secret")) {
		t.Fatal("the database row contains the plaintext token")
	}

	creds, _, err := cs.Get("cf1")
	requireNoError(t, err)
	if creds.Get("api_token") != "super-secret" {
		t.Fatalf("unexpected decrypted value: %q", creds.Get("api_token"))
	}
}

func TestGormStorePoolRoundTrip(t *testing.T) {
	store := newGormStore(t)
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	requireNoError(t, store.PutPoolEntry("edge", PoolEntry{
		Domain: "A.Example.COM", Zone: "zone1", RecordID: "rec1", Provider: "cloudflare",
		Target: "203.0.113.10", Proxied: true, State: PoolActive, LatencyMs: 42, CreatedAt: now,
	}))
	requireNoError(t, store.PutPoolEntry("edge", PoolEntry{
		Domain: "b.example.com", State: PoolRetired, Failures: 3, CreatedAt: now,
	}))
	requireNoError(t, store.PutPoolEntry("other", PoolEntry{Domain: "c.example.com", CreatedAt: now}))

	entries, err := store.ListPoolEntries("edge")
	requireNoError(t, err)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries in the edge pool, got %d", len(entries))
	}
	if entries[0].Domain != "a.example.com" {
		t.Fatalf("domains must be normalised on write, got %q", entries[0].Domain)
	}
	if !entries[0].Proxied || entries[0].LatencyMs != 42 {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
	if entries[1].State != PoolRetired || entries[1].Failures != 3 {
		t.Fatalf("unexpected entry: %+v", entries[1])
	}

	// Pools must be isolated from each other.
	other, err := store.ListPoolEntries("other")
	requireNoError(t, err)
	if len(other) != 1 {
		t.Fatalf("expected 1 entry in the other pool, got %d", len(other))
	}

	// An upsert on the same (pool, domain) must replace, not duplicate.
	requireNoError(t, store.PutPoolEntry("edge", PoolEntry{
		Domain: "a.example.com", State: PoolDegraded, Failures: 1, CreatedAt: now,
	}))
	entries, err = store.ListPoolEntries("edge")
	requireNoError(t, err)
	if len(entries) != 2 {
		t.Fatalf("upserting must not duplicate, got %d entries", len(entries))
	}

	requireNoError(t, store.DeletePoolEntry("edge", "A.EXAMPLE.COM"))
	entries, err = store.ListPoolEntries("edge")
	requireNoError(t, err)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after deletion, got %d", len(entries))
	}
}

// The pool must work end to end over the real database.
func TestGormStoreDrivesAPool(t *testing.T) {
	store := newGormStore(t)
	prober := newScriptedProber()
	prober.Healthy["a.example.com"] = true
	pool, err := NewPool(PoolConfig{
		Name: "edge", Prober: prober, FailureThreshold: 1,
		Now: fixedNow(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)),
	}, store)
	requireNoError(t, err)

	requireNoError(t, pool.Add(PoolEntry{Domain: "a.example.com"}))
	requireNoError(t, pool.Add(PoolEntry{Domain: "b.example.com"}))

	report, err := pool.Check(t.Context())
	requireNoError(t, err)
	if report.Healthy != 1 || len(report.Retired) != 1 {
		t.Fatalf("unexpected sweep: %+v", report)
	}

	// The verdict must survive a fresh read from the database.
	entries, err := store.ListPoolEntries("edge")
	requireNoError(t, err)
	byDomain := map[string]PoolEntry{}
	for _, e := range entries {
		byDomain[e.Domain] = e
	}
	if byDomain["a.example.com"].State != PoolActive {
		t.Fatalf("expected the healthy entry to persist as active: %+v", byDomain["a.example.com"])
	}
	if byDomain["b.example.com"].State != PoolRetired {
		t.Fatalf("expected the retirement to persist: %+v", byDomain["b.example.com"])
	}
	if byDomain["b.example.com"].LastError == "" {
		t.Fatal("the failure reason must persist so an operator can see why it retired")
	}
}

func TestGormStoreCleanIPRoundTrip(t *testing.T) {
	store := newGormStore(t)
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	requireNoError(t, store.SaveCleanIPs(CleanIPSet{
		Name: "WS.Example.COM", SNI: "ws.example.com", Port: 443, Sampled: 256,
		UpdatedAt: now,
		IPs: []CleanIP{
			{IP: "104.16.0.1", AvgRTTMs: 12, MinRTTMs: 10, LossPct: 0, TLS13: true, ALPN: "h2", Score: 12},
			{IP: "104.16.0.2", AvgRTTMs: 30, MinRTTMs: 28, LossPct: 33.3, TLS13: true, Score: 70},
		},
	}))

	got, err := store.LoadCleanIPs("ws.example.com")
	requireNoError(t, err)
	if got == nil {
		t.Fatal("expected the set to be found under its normalised name")
	}
	if len(got.IPs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(got.IPs))
	}
	if got.IPs[0].IP != "104.16.0.1" || !got.IPs[0].TLS13 || got.IPs[0].ALPN != "h2" {
		t.Fatalf("the ranked set did not round trip: %+v", got.IPs[0])
	}
	if got.IPs[1].LossPct != 33.3 {
		t.Fatalf("loss did not round trip: %+v", got.IPs[1])
	}
	if got.Best() != "104.16.0.1" {
		t.Fatalf("expected the first address to be best, got %q", got.Best())
	}

	missing, err := store.LoadCleanIPs("never-scanned")
	requireNoError(t, err)
	if missing != nil {
		t.Fatalf("expected nil for a missing set, got %+v", missing)
	}

	sets, err := store.ListCleanIPSets()
	requireNoError(t, err)
	if len(sets) != 1 {
		t.Fatalf("expected 1 set, got %d", len(sets))
	}
}

// The three tables must be independent of the panel's own schema: migrating
// twice over the same database must be a no-op.
func TestGormStoreMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	requireNoError(t, err)

	first, err := NewGormStore(db)
	requireNoError(t, err)
	requireNoError(t, first.PutCredential(CredentialRecord{ID: "cf1", Provider: "cloudflare", Secret: []byte{1}}))

	second, err := NewGormStore(db)
	requireNoError(t, err)
	got, err := second.GetCredential("cf1")
	requireNoError(t, err)
	if got == nil {
		t.Fatal("re-migrating must not lose data")
	}
}

func TestMemStoreMatchesTheGormContract(t *testing.T) {
	// The two implementations back the same interfaces, so the same sequence
	// must behave identically. This guards the test double against drifting
	// from the real store.
	for name, store := range map[string]interface {
		CredentialRepo
		PoolRepo
		CleanIPRepo
	}{
		"mem":  NewMemStore(),
		"gorm": newGormStore(t),
	} {
		t.Run(name, func(t *testing.T) {
			missing, err := store.GetCredential("nope")
			requireNoError(t, err)
			if missing != nil {
				t.Fatal("a missing credential must be (nil, nil)")
			}
			requireNoError(t, store.PutCredential(CredentialRecord{ID: "a", Provider: "cloudflare", Secret: []byte{1}}))
			list, err := store.ListCredentials()
			requireNoError(t, err)
			if len(list) != 1 {
				t.Fatalf("expected 1 credential, got %d", len(list))
			}

			missingSet, err := store.LoadCleanIPs("nope")
			requireNoError(t, err)
			if missingSet != nil {
				t.Fatal("a missing clean-IP set must be (nil, nil)")
			}

			entries, err := store.ListPoolEntries("empty")
			requireNoError(t, err)
			if len(entries) != 0 {
				t.Fatalf("an empty pool must list nothing, got %d", len(entries))
			}
			// Deleting from an empty pool is a no-op, not an error.
			requireNoError(t, store.DeletePoolEntry("empty", "a.example.com"))
		})
	}
}
