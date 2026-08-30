package job

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// store.Interface has carried a compile-time assert and seven repositories since
// the day it was written, and not one consumer ever named it. An interface no
// consumer's field is typed as buys nothing: the scheduler was welded to
// *store.Store, so the panel's traffic accounting, quota resets, expiry sweep and
// retention pruning could only ever run against GORM-on-SQLite. These tests hold
// the seam open by driving a real sweep through a store that is not a *store.Store.

// fakeSchedulerStore implements every method of store.SchedulerStore concretely.
//
// It deliberately does NOT embed store.SchedulerStore to fill in the methods it
// does not care about: an embedded nil interface panics on the first unstubbed
// call, which would turn "the seam is not wired" into an unrelated nil panic and
// make a half-done implementation look like a flake.
type fakeSchedulerStore struct {
	users      []store.User
	resetCalls []uint // user IDs passed to ResetUserUsageCAS
	saved      []uint // user IDs passed to SaveUser
}

func (f *fakeSchedulerStore) ListUsers(ownerID uint) ([]store.User, error) {
	out := make([]store.User, len(f.users))
	copy(out, f.users)
	return out, nil
}

func (f *fakeSchedulerStore) UserByID(id uint) (*store.User, error) {
	for i := range f.users {
		if f.users[i].ID == id {
			u := f.users[i]
			return &u, nil
		}
	}
	return nil, fmt.Errorf("no user %d", id)
}

func (f *fakeSchedulerStore) SaveUser(u *store.User) error {
	f.saved = append(f.saved, u.ID)
	return nil
}

func (f *fakeSchedulerStore) UpdateUserFields(uint, map[string]any, time.Time) error { return nil }

func (f *fakeSchedulerStore) ResetUserUsageCAS(userID uint, periodStart, now time.Time) (bool, error) {
	f.resetCalls = append(f.resetCalls, userID)
	return true, nil
}

func (f *fakeSchedulerStore) TrafficSnapshots(string) (map[string]int64, error) {
	return map[string]int64{}, nil
}

func (f *fakeSchedulerStore) SetTrafficSnapshot(string, string, int64) error { return nil }

func (f *fakeSchedulerStore) ApplyTrafficDeltaAt(string, string, uint, int64, int64, store.TrafficSplit, time.Time, func(*store.User)) (int64, bool, error) {
	return 0, false, nil
}

func (f *fakeSchedulerStore) SchemaVersion() (uint64, error) { return 22, nil }

func (f *fakeSchedulerStore) PruneRollups(time.Time, time.Time) (int64, error) { return 0, nil }

func (f *fakeSchedulerStore) PruneAuditLogs(time.Time) (int64, error) { return 0, nil }

// TestSchedulerRunsAgainstAnAlternativeStore is the substitutability proof: a
// full lifecycle sweep, driven end to end by a backend with no GORM and no
// *store.Store anywhere in it.
func TestSchedulerRunsAgainstAnAlternativeStore(t *testing.T) {
	fake := &fakeSchedulerStore{users: []store.User{
		{Base: store.Base{ID: 7}, Username: "alt", Status: store.StatusActive,
			ResetStrategy: store.ResetMonth},
	}}

	s := New(Config{DB: fake})
	if err := s.sweepAt(time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("sweepAt against alternative store: %v", err)
	}

	if len(fake.resetCalls) != 1 || fake.resetCalls[0] != 7 {
		t.Fatalf("the scheduler did not reset usage through the alternative store: "+
			"ResetUserUsageCAS calls = %v, want [7]", fake.resetCalls)
	}
}

// TestSchedulerConfigTakesAnInterfaceNotTheConcreteStore catches the re-death of
// this row: someone flipping Config.DB back to a concrete type while leaving
// store.SchedulerStore behind as decoration, exactly as store.Interface stands
// today.
func TestSchedulerConfigTakesAnInterfaceNotTheConcreteStore(t *testing.T) {
	f, ok := reflect.TypeOf(Config{}).FieldByName("DB")
	if !ok {
		t.Fatal("job.Config has no DB field")
	}
	if f.Type.Kind() != reflect.Interface {
		t.Fatalf("job.Config.DB is %s (%s): internal/job is welded to the concrete "+
			"store, so no alternative backend can substitute", f.Type.Kind(), f.Type)
	}
	if want := reflect.TypeOf((*store.SchedulerStore)(nil)).Elem(); f.Type != want {
		t.Fatalf("job.Config.DB is %s, want store.SchedulerStore", f.Type)
	}
}

// TestSchedulerStoreDoesNotLeakGorm blocks the cheap way to make everything
// compile: hang DB() *gorm.DB off the interface and let the scheduler keep
// reaching through it. An alternative backend that has to manufacture a *gorm.DB
// is not an alternative backend.
func TestSchedulerStoreDoesNotLeakGorm(t *testing.T) {
	it := reflect.TypeOf((*store.SchedulerStore)(nil)).Elem()
	for i := 0; i < it.NumMethod(); i++ {
		if it.Method(i).Name == "DB" {
			t.Fatal("store.SchedulerStore exposes DB(): any alternative backend must " +
				"now manufacture a *gorm.DB, which is the gap this row exists to close")
		}
	}
}

// TestSchedulerSkipsJobsWhenGivenATypedNilStore guards the trap the interface
// itself creates. A nil *store.Store stored in an interface field is a NON-nil
// interface value, so the old `s.db == nil` guards all read false and every job
// below them dereferences a nil receiver inside GORM.
func TestSchedulerSkipsJobsWhenGivenATypedNilStore(t *testing.T) {
	var nilStore *store.Store
	dir := seedForBackup(t)
	s := New(Config{DB: nilStore, AuditRetention: time.Hour,
		RollupHourlyRetention: time.Hour, RollupDailyRetention: time.Hour,
		PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
			return map[string]store.TrafficSplit{}, nil
		},
		ActiveAddresses: func(string) int { return 0 },
		BackupConfig: func() (string, string, time.Duration, int) {
			return dir, "master-key", time.Hour, 7
		},
	})

	if err := s.sweepAt(time.Now()); err != nil {
		t.Fatalf("sweepAt with a typed-nil store: %v", err)
	}
	if err := s.pollAndAccount(); err != nil {
		t.Fatalf("pollAndAccount with a typed-nil store: %v", err)
	}
	if err := s.pruneRollups(); err != nil {
		t.Fatalf("pruneRollups with a typed-nil store: %v", err)
	}
	if err := s.pruneAudit(); err != nil {
		t.Fatalf("pruneAudit with a typed-nil store: %v", err)
	}
	if err := s.runScheduledBackup(); err != nil {
		t.Fatalf("runScheduledBackup with a typed-nil store: %v", err)
	}
	if s.enforceIPLimits() {
		t.Fatal("enforceIPLimits reported a change with no store")
	}
}
