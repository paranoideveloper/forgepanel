package store

// Downtime-safe traffic accounting.
//
// The poller used to read the engine's counters with -reset: one call both READ
// the numbers and ZEROED them. That makes the read the only copy of the data,
// and anything that happens between the read and the write loses it for good:
//
//	panel killed mid-cycle      the delta was read, the counters are already
//	                            zero, and the user's usage never records it
//	SaveUser fails              same, silently, per user
//	two pollers ever run        each destroys the other's numbers
//
// Losing usage always fails the same direction — traffic vanishes, quotas never
// trip, and a user on an exhausted plan keeps being served. Nothing looks wrong.
//
// The fix is the standard one: read CUMULATIVELY (never reset), remember the
// last value seen per counter, and derive the delta by subtraction. A re-read
// after a crash returns the same cumulative number, so the delta is recomputed
// rather than lost. The snapshot must be persisted and must move in the same
// transaction as the usage it accounts for, or a crash between the two writes
// double-counts instead.

import (
	"fmt"

	"gorm.io/gorm"
)

// TrafficSnapshot is the last cumulative counter value seen for one key.
//
// Scope separates counter namespaces that reset independently: the local engine
// is one, each remote node is another. Without it a node restart would look like
// a local counter reset.
type TrafficSnapshot struct {
	Scope string `gorm:"primaryKey;size:64" json:"scope"`
	Key   string `gorm:"primaryKey;size:128" json:"key"`
	Value int64  `json:"value"`
}

func (TrafficSnapshot) TableName() string { return "traffic_snapshots" }

// ScopeLocalEngine is the panel's own engine counters.
const ScopeLocalEngine = "local"

// TrafficSnapshots returns every stored counter value for a scope, keyed by
// counter key.
func (s *Store) TrafficSnapshots(scope string) (map[string]int64, error) {
	var rows []TrafficSnapshot
	if err := s.db.Where("scope = ?", scope).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read traffic snapshots for %q: %w", scope, err)
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Value
	}
	return out, nil
}

// ApplyTrafficDelta adds delta to a user's usage and advances that user's
// counter snapshot IN ONE TRANSACTION.
//
// Atomicity is the entire point. Saving the user without advancing the snapshot
// re-applies the same bytes on the next cycle; advancing the snapshot without
// saving the user drops them. Either way the number is wrong and nothing
// reports it, so both writes have to succeed or neither may.
//
// stamp runs on the loaded user inside the transaction, so lifecycle bookkeeping
// that belongs to the same observation — last-seen, the on-hold clock, a status
// change — is committed with the usage that caused it rather than in a second
// write that can fail on its own.
//
// It returns the user's usage after the update, and whether the update pushed
// them over their data limit, so the caller can enforce without a second read.
func (s *Store) ApplyTrafficDelta(scope, key string, userID uint, delta, cumulative int64, stamp func(*User)) (used int64, limited bool, err error) {
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, userID).Error; err != nil {
			return err
		}
		if delta > 0 {
			// Saturate rather than wrap. A wrapped counter reads as a user who
			// has used almost nothing, which silently lifts their quota.
			if maxInt64-delta < u.UsedTraffic {
				u.UsedTraffic = maxInt64
			} else {
				u.UsedTraffic += delta
			}
		}
		if stamp != nil {
			stamp(&u)
		}
		if err := tx.Save(&u).Error; err != nil {
			return err
		}
		if err := upsertSnapshot(tx, scope, key, cumulative); err != nil {
			return err
		}
		used = u.UsedTraffic
		limited = u.DataLimit > 0 && u.UsedTraffic >= u.DataLimit
		return nil
	})
	return used, limited, err
}

// SetTrafficSnapshot records a cumulative value without touching a user. Used
// when a counter belongs to no known user: the value still has to be remembered,
// or the next cycle would treat the whole cumulative total as a fresh delta and
// bill it to whoever the key later resolves to.
func (s *Store) SetTrafficSnapshot(scope, key string, value int64) error {
	return upsertSnapshot(s.db, scope, key, value)
}

func upsertSnapshot(tx *gorm.DB, scope, key string, value int64) error {
	row := TrafficSnapshot{Scope: scope, Key: key, Value: value}
	// Save writes both halves of the composite key, so this is an upsert.
	if err := tx.Where("scope = ? AND key = ?", scope, key).
		Assign(TrafficSnapshot{Value: value}).
		FirstOrCreate(&row).Error; err != nil {
		return fmt.Errorf("record traffic snapshot %s/%s: %w", scope, key, err)
	}
	return nil
}

// ClearTrafficSnapshots drops a scope's snapshots. Called when a scope's
// counters are known to have restarted from zero and the stored values would
// otherwise suppress the next cycle's delta entirely.
func (s *Store) ClearTrafficSnapshots(scope string) error {
	return s.db.Where("scope = ?", scope).Delete(&TrafficSnapshot{}).Error
}

const maxInt64 = int64(^uint64(0) >> 1)

// TrafficDelta derives the bytes used since the last cycle from a cumulative
// counter reading.
//
// A reading LOWER than the snapshot means the counter restarted — the engine was
// restarted, which the panel itself does on every config change. The current
// value is then the whole delta: it is everything that counter has seen since it
// came back. Treating it as a negative delta (or clamping it to zero and keeping
// the old snapshot) would discard real usage on every single config change,
// which is the most common event in a running panel.
func TrafficDelta(previous, current int64) int64 {
	if current < previous {
		return current
	}
	return current - previous
}
