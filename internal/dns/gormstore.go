package dns

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

// The GORM models below live in their own tables so this package owns its
// schema outright and never has to be migrated in step with internal/store.

// DNSCredential is the encrypted credential row.
type DNSCredential struct {
	ID              string `gorm:"primaryKey;size:64"`
	Provider        string `gorm:"index;size:64;not null"`
	Label           string `gorm:"size:255"`
	Secret          []byte `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastVerifiedAt  *time.Time
	LastVerifyError string `gorm:"size:1024"`
}

// TableName pins the table so a future model rename cannot silently orphan
// stored credentials.
func (DNSCredential) TableName() string { return "dns_credentials" }

// DNSPoolEntry is one rotation-pool member.
type DNSPoolEntry struct {
	Pool      string `gorm:"primaryKey;size:64"`
	Domain    string `gorm:"primaryKey;size:255"`
	Zone      string `gorm:"size:255"`
	RecordID  string `gorm:"size:128"`
	Provider  string `gorm:"size:64"`
	Target    string `gorm:"size:255"`
	Proxied   bool
	State     string `gorm:"size:16;index"`
	Failures  int
	Checks    int
	LatencyMs int64
	LastError string `gorm:"size:1024"`
	CreatedAt time.Time
	CheckedAt time.Time
}

// TableName pins the table.
func (DNSPoolEntry) TableName() string { return "dns_pool_entries" }

// DNSCleanIPSet is a stored scan result. The addresses are kept as JSON because
// they are always read and written as a ranked whole, never queried
// individually.
type DNSCleanIPSet struct {
	Name      string `gorm:"primaryKey;size:255"`
	SNI       string `gorm:"size:255"`
	Port      int
	Sampled   int
	IPsJSON   string `gorm:"type:text"`
	UpdatedAt time.Time
}

// TableName pins the table.
func (DNSCleanIPSet) TableName() string { return "dns_clean_ip_sets" }

// GormStore persists this package's state in the panel database.
type GormStore struct {
	db *gorm.DB
}

// NewGormStore opens a store over an existing *gorm.DB and migrates the three
// tables it owns.
func NewGormStore(db *gorm.DB) (*GormStore, error) {
	if db == nil {
		return nil, &Error{Op: "new-gorm-store", Kind: KindValidation,
			Message: "no database handle was supplied", Remediation: "pass the panel's *gorm.DB"}
	}
	if err := db.AutoMigrate(&DNSCredential{}, &DNSPoolEntry{}, &DNSCleanIPSet{}); err != nil {
		return nil, &Error{Op: "new-gorm-store", Kind: KindServer,
			Message:     "could not migrate the DNS tables: " + err.Error(),
			Remediation: "check the panel database is writable", Cause: err}
	}
	return &GormStore{db: db}, nil
}

// PutCredential implements CredentialRepo with an upsert.
func (g *GormStore) PutCredential(rec CredentialRecord) error {
	row := DNSCredential(rec)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	row.UpdatedAt = time.Now().UTC()
	return g.db.Save(&row).Error
}

// GetCredential implements CredentialRepo. A missing id is (nil, nil).
func (g *GormStore) GetCredential(id string) (*CredentialRecord, error) {
	var row DNSCredential
	if err := g.db.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	rec := credentialFromRow(row)
	return &rec, nil
}

// ListCredentials implements CredentialRepo.
func (g *GormStore) ListCredentials() ([]CredentialRecord, error) {
	var rows []DNSCredential
	if err := g.db.Order("id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]CredentialRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, credentialFromRow(row))
	}
	return out, nil
}

// DeleteCredential implements CredentialRepo.
func (g *GormStore) DeleteCredential(id string) error {
	return g.db.Delete(&DNSCredential{}, "id = ?", id).Error
}

func credentialFromRow(row DNSCredential) CredentialRecord {
	return CredentialRecord(row)
}

// ListPoolEntries implements PoolRepo.
func (g *GormStore) ListPoolEntries(pool string) ([]PoolEntry, error) {
	var rows []DNSPoolEntry
	if err := g.db.Where("pool = ?", pool).Order("domain asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]PoolEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, PoolEntry{
			Domain: row.Domain, Zone: row.Zone, RecordID: row.RecordID, Provider: row.Provider,
			Target: row.Target, Proxied: row.Proxied, State: PoolState(row.State),
			Failures: row.Failures, Checks: row.Checks, LatencyMs: row.LatencyMs,
			LastError: row.LastError, CreatedAt: row.CreatedAt, CheckedAt: row.CheckedAt,
		})
	}
	return out, nil
}

// ListPoolNames implements PoolRepo.
func (g *GormStore) ListPoolNames() ([]string, error) {
	var names []string
	if err := g.db.Model(&DNSPoolEntry{}).
		Distinct().Order("pool asc").Pluck("pool", &names).Error; err != nil {
		return nil, err
	}
	return names, nil
}

// PutPoolEntry implements PoolRepo with an upsert.
func (g *GormStore) PutPoolEntry(pool string, entry PoolEntry) error {
	row := DNSPoolEntry{
		Pool: pool, Domain: NormalizeDomain(entry.Domain), Zone: entry.Zone,
		RecordID: entry.RecordID, Provider: entry.Provider, Target: entry.Target,
		Proxied: entry.Proxied, State: string(entry.State), Failures: entry.Failures,
		Checks: entry.Checks, LatencyMs: entry.LatencyMs, LastError: entry.LastError,
		CreatedAt: entry.CreatedAt, CheckedAt: entry.CheckedAt,
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	return g.db.Save(&row).Error
}

// DeletePoolEntry implements PoolRepo.
func (g *GormStore) DeletePoolEntry(pool, domain string) error {
	return g.db.Delete(&DNSPoolEntry{}, "pool = ? AND domain = ?", pool, NormalizeDomain(domain)).Error
}

// SaveCleanIPs implements CleanIPRepo.
func (g *GormStore) SaveCleanIPs(set CleanIPSet) error {
	name := strings.ToLower(strings.TrimSpace(set.Name))
	if name == "" {
		name = "default"
	}
	blob, err := json.Marshal(set.IPs)
	if err != nil {
		return err
	}
	updated := set.UpdatedAt
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	row := DNSCleanIPSet{
		Name: name, SNI: set.SNI, Port: set.Port, Sampled: set.Sampled,
		IPsJSON: string(blob), UpdatedAt: updated,
	}
	return g.db.Save(&row).Error
}

// LoadCleanIPs implements CleanIPRepo. A missing set is (nil, nil).
func (g *GormStore) LoadCleanIPs(name string) (*CleanIPSet, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "default"
	}
	var row DNSCleanIPSet
	if err := g.db.First(&row, "name = ?", key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	set := cleanIPSetFromRow(row)
	return &set, nil
}

// ListCleanIPSets implements CleanIPRepo.
func (g *GormStore) ListCleanIPSets() ([]CleanIPSet, error) {
	var rows []DNSCleanIPSet
	if err := g.db.Order("name asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]CleanIPSet, 0, len(rows))
	for _, row := range rows {
		out = append(out, cleanIPSetFromRow(row))
	}
	return out, nil
}

func cleanIPSetFromRow(row DNSCleanIPSet) CleanIPSet {
	set := CleanIPSet{
		Name: row.Name, SNI: row.SNI, Port: row.Port,
		Sampled: row.Sampled, UpdatedAt: row.UpdatedAt,
	}
	if strings.TrimSpace(row.IPsJSON) != "" {
		// A malformed blob degrades to an empty set rather than failing the
		// read; the consumer re-scans, which is the right recovery either way.
		_ = json.Unmarshal([]byte(row.IPsJSON), &set.IPs)
	}
	return set
}

var (
	_ CredentialRepo = (*GormStore)(nil)
	_ PoolRepo       = (*GormStore)(nil)
	_ CleanIPRepo    = (*GormStore)(nil)
)
