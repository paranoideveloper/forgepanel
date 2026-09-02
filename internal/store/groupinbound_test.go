package store

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// "Which groups reference inbound N" must be an indexed lookup, and it must stay
// true through every writer.
//
// Group membership lived only in Group.InboundIDs, a comma-separated TEXT column
// with no foreign key and no index. The reverse question could be answered only
// by loading every group and filtering in Go, which is what cascade.go did, and
// nothing stopped the column naming an inbound that had been deleted.
func TestGroupsForInboundUsesTheJoinIndexAndNotAScan(t *testing.T) {
	s := testStore(t)
	a, b := &Inbound{Remark: "a", Port: 1001}, &Inbound{Remark: "b", Port: 1002}
	for _, in := range []*Inbound{a, b} {
		if err := s.db.Create(in).Error; err != nil {
			t.Fatal(err)
		}
	}
	g1 := &Group{Name: "g1", InboundIDs: IntSlice{a.ID}}
	g2 := &Group{Name: "g2", InboundIDs: IntSlice{a.ID, b.ID}}
	g3 := &Group{Name: "g3", InboundIDs: IntSlice{b.ID}}
	for _, g := range []*Group{g1, g2, g3} {
		if err := s.CreateGroup(g); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GroupsForInbound(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint{g1.ID, g2.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("GroupsForInbound(a) = %v, want %v — CreateGroup did not maintain the join table", got, want)
	}
	if got, _ := s.GroupsForInbound(b.ID); !reflect.DeepEqual(got, []uint{g2.ID, g3.ID}) {
		t.Fatalf("GroupsForInbound(b) = %v", got)
	}

	// The index is the point of the row. Asserting only on the returned ids
	// would pass just as well against a full-table load filtered in Go, which
	// is exactly what this replaces.
	var plan []struct {
		ID, Parent, NotUsed int
		Detail              string
	}
	if err := s.db.Raw("EXPLAIN QUERY PLAN SELECT group_id FROM group_inbounds WHERE inbound_id = ?", a.ID).
		Scan(&plan).Error; err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, r := range plan {
		joined += r.Detail + " "
	}
	if !strings.Contains(joined, "USING INDEX") && !strings.Contains(joined, "USING COVERING INDEX") {
		t.Errorf("the reverse lookup is a scan, not an index seek: %s", joined)
	}
}

// Every writer has to maintain the table, or it drifts from the column it
// mirrors and answers confidently with stale rows. A join table that only
// CreateGroup maintains is worse than none: it looks authoritative.
func TestEveryGroupWriterMaintainsTheJoinTable(t *testing.T) {
	s := testStore(t)
	a, b := &Inbound{Remark: "a", Port: 2001}, &Inbound{Remark: "b", Port: 2002}
	for _, in := range []*Inbound{a, b} {
		if err := s.db.Create(in).Error; err != nil {
			t.Fatal(err)
		}
	}
	g := &Group{Name: "g", InboundIDs: IntSlice{a.ID}}
	if err := s.CreateGroup(g); err != nil {
		t.Fatal(err)
	}

	// PATCH: the API's inbound_ids path goes through UpdateGroupFields.
	if err := s.UpdateGroupFields(g.ID, map[string]any{"inbound_ids": IntSlice{b.ID}}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupsForInbound(a.ID); len(got) != 0 {
		t.Errorf("after re-assignment the group is still joined to the old inbound: %v", got)
	}
	if got, _ := s.GroupsForInbound(b.ID); !reflect.DeepEqual(got, []uint{g.ID}) {
		t.Errorf("UpdateGroupFields did not write the new join rows: %v", got)
	}

	// Deleting the INBOUND must not leave the group joined to a row that is gone.
	if err := s.DeleteInbound(b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupsForInbound(b.ID); len(got) != 0 {
		t.Errorf("deleting an inbound leaked join rows: %v — the same shape as the pre-cascade user bug", got)
	}

	// Deleting the GROUP must not leak either.
	g2 := &Group{Name: "g2", InboundIDs: IntSlice{a.ID}}
	if err := s.CreateGroup(g2); err != nil {
		t.Fatal(err)
	}
	if err := func() error { _, e := s.DeleteGroupSafely(g2.ID, 0, true); return e }(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupsForInbound(a.ID); len(got) != 0 {
		t.Errorf("deleting a group leaked its join rows: %v", got)
	}
}

// An already-installed panel must get its existing memberships backfilled.
//
// Without the backfill the migration creates an EMPTY table on every panel that
// predates it: the table exists, the reverse query returns nothing, and nothing
// looks broken until a delete cascade quietly misses every group made before the
// upgrade. That is worse than not having the table at all, because the answer is
// now authoritative-looking.
//
// This runs the migration's own Up function, not a copy of its logic — an
// earlier version of this test re-implemented the backfill and passed against a
// migration that did not have one.
func TestTheMigrationBackfillsExistingGroups(t *testing.T) {
	s := testStore(t)
	in := &Inbound{Remark: "a", Port: 3001}
	if err := s.db.Create(in).Error; err != nil {
		t.Fatal(err)
	}
	// A group as an older build left it: text column set, no join rows.
	g := &Group{Name: "legacy", InboundIDs: IntSlice{in.ID}}
	if err := s.db.Create(g).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Where("group_id = ?", g.ID).Delete(&GroupInbound{}).Error; err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupsForInbound(in.ID); len(got) != 0 {
		t.Fatalf("precondition: expected no join rows, got %v", got)
	}

	var up func(*gorm.DB) error
	for _, m := range migrations() {
		if m.Version == migVGroupInbounds {
			up = m.Up
		}
	}
	if up == nil {
		t.Fatalf("migration %d is not in the registry", migVGroupInbounds)
	}
	if err := up(s.db); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	if got, _ := s.GroupsForInbound(in.ID); len(got) != 1 || got[0] != g.ID {
		t.Errorf("the migration did not backfill a pre-existing group: %v — every panel upgraded "+
			"from an older build would have an empty join table", got)
	}
}
