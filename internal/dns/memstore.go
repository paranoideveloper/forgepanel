package dns

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// MemStore is an in-process implementation of every repository this package
// needs. It backs tests and the `forgectl provision` one-shot run, which has no
// panel database to talk to.
type MemStore struct {
	mu       sync.RWMutex
	creds    map[string]CredentialRecord
	pools    map[string]map[string]PoolEntry
	cleanIPs map[string]CleanIPSet
}

// NewMemStore builds an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		creds:    map[string]CredentialRecord{},
		pools:    map[string]map[string]PoolEntry{},
		cleanIPs: map[string]CleanIPSet{},
	}
}

// PutCredential implements CredentialRepo.
func (m *MemStore) PutCredential(rec CredentialRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := rec
	cp.Secret = append([]byte(nil), rec.Secret...)
	m.creds[rec.ID] = cp
	return nil
}

// GetCredential implements CredentialRepo. A missing id is (nil, nil).
func (m *MemStore) GetCredential(id string) (*CredentialRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.creds[id]
	if !ok {
		return nil, nil
	}
	cp := rec
	cp.Secret = append([]byte(nil), rec.Secret...)
	return &cp, nil
}

// ListCredentials implements CredentialRepo.
func (m *MemStore) ListCredentials() ([]CredentialRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]CredentialRecord, 0, len(m.creds))
	for _, rec := range m.creds {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteCredential implements CredentialRepo.
func (m *MemStore) DeleteCredential(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.creds, id)
	return nil
}

// ListPoolEntries implements PoolRepo.
func (m *MemStore) ListPoolEntries(pool string) ([]PoolEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.pools[pool]
	out := make([]PoolEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// ListPoolNames implements PoolRepo.
func (m *MemStore) ListPoolNames() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.pools))
	for name, entries := range m.pools {
		// Only pools that hold something, matching the SQL store: an empty map
		// entry left behind by the last removal is not a pool to sweep.
		if len(entries) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// PutPoolEntry implements PoolRepo.
func (m *MemStore) PutPoolEntry(pool string, entry PoolEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pools[pool] == nil {
		m.pools[pool] = map[string]PoolEntry{}
	}
	m.pools[pool][NormalizeDomain(entry.Domain)] = entry
	return nil
}

// DeletePoolEntry implements PoolRepo.
func (m *MemStore) DeletePoolEntry(pool, domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pools[pool] != nil {
		delete(m.pools[pool], NormalizeDomain(domain))
	}
	return nil
}

// SaveCleanIPs implements CleanIPRepo.
func (m *MemStore) SaveCleanIPs(set CleanIPSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(set.Name))
	if key == "" {
		key = "default"
	}
	set.Name = key
	if set.UpdatedAt.IsZero() {
		set.UpdatedAt = time.Now().UTC()
	}
	m.cleanIPs[key] = set
	return nil
}

// LoadCleanIPs implements CleanIPRepo. A missing set is (nil, nil).
func (m *MemStore) LoadCleanIPs(name string) (*CleanIPSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = "default"
	}
	set, ok := m.cleanIPs[key]
	if !ok {
		return nil, nil
	}
	cp := set
	cp.IPs = append([]CleanIP(nil), set.IPs...)
	return &cp, nil
}

// ListCleanIPSets implements CleanIPRepo.
func (m *MemStore) ListCleanIPSets() ([]CleanIPSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]CleanIPSet, 0, len(m.cleanIPs))
	for _, set := range m.cleanIPs {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var (
	_ CredentialRepo = (*MemStore)(nil)
	_ PoolRepo       = (*MemStore)(nil)
	_ CleanIPRepo    = (*MemStore)(nil)
)
