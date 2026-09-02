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
	"strings"
	"time"

	"gorm.io/gorm"
)

// nodeIDFromScope pulls the node id out of a "node:<id>" counter scope.
func nodeIDFromScope(scope string) (string, bool) {
	id, ok := strings.CutPrefix(scope, "node:")
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

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

// UpScope and DownScope are the per-half baselines for a scope.
//
// The uplink and downlink counters need their OWN baselines: a delta is the
// difference from the last observation, and the combined baseline cannot produce
// one for either half. Apportioning the total delta by the cumulative ratio
// instead would put a guessed number in a column an operator reads as measured.
//
// Separate rows rather than extra columns because the total is what quotas are
// enforced on and it must keep its exact current shape — this adds to the
// accounting, it does not restructure it.
func UpScope(scope string) string   { return scope + ":up" }
func DownScope(scope string) string { return scope + ":down" }

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
	return s.ApplyTrafficDeltaAt(scope, key, userID, delta, cumulative, TrafficSplit{}, time.Now(), stamp)
}

// TrafficSplit is one observation's uplink/downlink breakdown.
//
// A zero split means "this source did not report one" — NOT "no traffic". Remote
// nodes send a single combined counter, so their bytes are billed without a
// split, and inventing one would make guessed numbers indistinguishable from
// measured ones.
type TrafficSplit struct {
	Up   int64
	Down int64
}

// Total is the combined byte count, which is the quantity quotas are enforced on.
func (t TrafficSplit) Total() int64 { return t.Up + t.Down }

// ApplyTrafficDeltaAt is ApplyTrafficDelta with an explicit observation time,
// which is what places the usage in the right history bucket. Tests drive it;
// production passes time.Now().
func (s *Store) ApplyTrafficDeltaAt(scope, key string, userID uint, delta, cumulative int64, split TrafficSplit, at time.Time, stamp func(*User)) (used int64, limited bool, err error) {
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
			// The attributed halves, saturating for the same reason. They are
			// recorded only when the source actually reported them.
			if split.Up > 0 {
				if maxInt64-split.Up < u.UploadTraffic {
					u.UploadTraffic = maxInt64
				} else {
					u.UploadTraffic += split.Up
				}
			}
			if split.Down > 0 {
				if maxInt64-split.Down < u.DownloadTraffic {
					u.DownloadTraffic = maxInt64
				} else {
					u.DownloadTraffic += split.Down
				}
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
		// The history is written from the SAME delta, in the SAME transaction,
		// so a chart and an invoice cannot disagree and a crash cannot bill
		// traffic that never lands in the history.
		if err := recordUsage(tx, ScopeUser, UserRollupKey(userID), at, delta); err != nil {
			return err
		}
		// A remote node's scope is "node:<id>"; credit the node too, so "which
		// node carried this" is answerable without re-deriving it from users.
		if nodeID, ok := nodeIDFromScope(scope); ok {
			if err := recordUsage(tx, ScopeNode, nodeID, at, delta); err != nil {
				return err
			}
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
