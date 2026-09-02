package store

import (
	"testing"

	"gorm.io/gorm"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// makeInbound creates a throwaway inbound so a test can talk about ids.
func makeInbound(t *testing.T, s *Store, remark string, port int) *Inbound {
	t.Helper()
	in, err := s.CreateInbound(&model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.1", Port: port, Remark: remark,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: model.Transport{Network: model.NetTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// countAssignments reports how many join rows still name an inbound.
func countAssignments(t *testing.T, s *Store, column string, id uint) int64 {
	t.Helper()
	var n int64
	if err := s.db.Model(&UserInbound{}).Where(column+" = ?", id).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDeleteInboundLeavesNoOrphans: before the cascade, deleting an inbound left
// its user_inbounds join rows and its id inside every group binding. A
// subscription then kept resolving through an inbound that no longer existed,
// and because SQLite hands out the lowest free rowid, the next inbound created
// inherited the dead one's users outright.
func TestDeleteInboundLeavesNoOrphans(t *testing.T) {
	s := testStore(t)
	doomed := makeInbound(t, s, "doomed", 443)
	keep := makeInbound(t, s, "keep", 8443)

	g := &Group{Name: "g", InboundIDs: IntSlice{doomed.ID, keep.ID}}
	if err := s.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	other := &Group{Name: "untouched", InboundIDs: IntSlice{keep.ID}}
	if err := s.CreateGroup(other); err != nil {
		t.Fatal(err)
	}
	u := &User{Username: "alice", SubToken: "tok", GroupID: g.ID}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserInbounds(u.ID, []uint{doomed.ID, keep.ID}, nil); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteInbound(doomed.ID); err != nil {
		t.Fatal(err)
	}

	if n := countAssignments(t, s, "inbound_id", doomed.ID); n != 0 {
		t.Fatalf("%d user_inbounds rows still point at the deleted inbound", n)
	}
	if n := countAssignments(t, s, "inbound_id", keep.ID); n != 1 {
		t.Fatalf("the surviving inbound's assignment was collateral damage: %d rows", n)
	}
	gotGroup, err := s.GroupByID(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotGroup.InboundIDs) != 1 || gotGroup.InboundIDs[0] != keep.ID {
		t.Fatalf("group binding still names the deleted inbound: %v", gotGroup.InboundIDs)
	}
	gotOther, err := s.GroupByID(other.ID)
	if err != nil || len(gotOther.InboundIDs) != 1 || gotOther.InboundIDs[0] != keep.ID {
		t.Fatalf("an unrelated group was rewritten: %+v %v", gotOther, err)
	}

	// What the user's subscription now renders is the real test.
	eff, err := s.InboundsForUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff) != 1 || eff[0] != keep.ID {
		t.Fatalf("subscription still resolves through a deleted inbound: %v", eff)
	}

	// Deleting again must stay quiet; a retried delete is not a failure.
	if err := s.DeleteInbound(doomed.ID); err != nil {
		t.Fatalf("re-deleting a gone inbound errored: %v", err)
	}
}

// TestDeleteUserLeavesNoOrphans: the join rows are keyed by user id and the
// traffic baselines by username, so both have to go with the account — a
// recreated account would otherwise inherit stale assignments and a stale
// byte counter.
func TestDeleteUserLeavesNoOrphans(t *testing.T) {
	s := testStore(t)
	in := makeInbound(t, s, "in", 443)
	u := &User{Username: "bob", SubToken: "tok-bob"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	keeper := &User{Username: "carol", SubToken: "tok-carol"}
	if err := s.CreateUser(keeper); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserInbounds(u.ID, []uint{in.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserInbounds(keeper.ID, []uint{in.ID}, nil); err != nil {
		t.Fatal(err)
	}
	node := &Node{Name: "n1", Address: "203.0.113.7", EnrollToken: "tk"}
	if err := s.CreateNode(node); err != nil {
		t.Fatal(err)
	}
	// Traffic baselines for both users, on this node's scope.
	for _, id := range []uint{u.ID, keeper.ID} {
		if err := s.SetTrafficSnapshot(NodeScope(node.ID), UserCounterKey(id), 100); err != nil {
			t.Fatal(err)
		}
	}

	// DeleteUser and DeleteUserCascade must behave identically.
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if n := countAssignments(t, s, "user_id", u.ID); n != 0 {
		t.Fatalf("%d assignment rows outlived the user", n)
	}
	snaps, err := s.TrafficSnapshots(NodeScope(node.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, still := snaps[UserCounterKey(u.ID)]; still {
		t.Fatal("the deleted user's traffic baseline survived; SQLite reuses the lowest free rowid, " +
			"so a recreated account would inherit it and transfer free until it caught up")
	}
	if _, ok := snaps[UserCounterKey(keeper.ID)]; !ok {
		t.Fatal("another user's traffic baseline was destroyed")
	}
	if n := countAssignments(t, s, "user_id", keeper.ID); n != 1 {
		t.Fatalf("another user's assignments were destroyed: %d", n)
	}
	if _, err := s.UserByID(u.ID); err == nil {
		t.Fatal("the user row itself survived")
	}
}

// TestDeleteNodeClearsEveryReference: an inbound outlives its node on purpose,
// but the dangling node_id must not — the panel resolves an inbound's public
// address through it, so a recycled node id would silently re-point live
// subscriptions at a different machine.
func TestDeleteNodeClearsEveryReference(t *testing.T) {
	s := testStore(t)
	node := &Node{Name: "n1", Address: "203.0.113.7", EnrollToken: "tk1"}
	if err := s.CreateNode(node); err != nil {
		t.Fatal(err)
	}
	survivor := &Node{Name: "n2", Address: "203.0.113.8", EnrollToken: "tk2"}
	if err := s.CreateNode(survivor); err != nil {
		t.Fatal(err)
	}
	attached := makeInbound(t, s, "attached", 443)
	attached.NodeID = node.ID
	if err := s.SaveInbound(attached); err != nil {
		t.Fatal(err)
	}
	elsewhere := makeInbound(t, s, "elsewhere", 8443)
	elsewhere.NodeID = survivor.ID
	if err := s.SaveInbound(elsewhere); err != nil {
		t.Fatal(err)
	}
	// One baseline per node for the same user, so the sweep must be scoped to
	// the node being deleted and not to the user.
	if err := s.SetTrafficSnapshot(NodeScope(node.ID), UserCounterKey(1), 10); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTrafficSnapshot(NodeScope(survivor.ID), UserCounterKey(1), 20); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteNode(node.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.InboundByID(attached.ID)
	if err != nil {
		t.Fatalf("the inbound was deleted with its node: %v", err)
	}
	if got.NodeID != 0 {
		t.Fatalf("inbound still points at the deleted node %d", got.NodeID)
	}
	stillThere, err := s.InboundByID(elsewhere.ID)
	if err != nil || stillThere.NodeID != survivor.ID {
		t.Fatalf("another node's inbound was detached: %+v %v", stillThere, err)
	}
	dead, err := s.TrafficSnapshots(NodeScope(node.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(dead) != 0 {
		t.Fatalf("traffic baselines outlived their node: %v", dead)
	}
	alive, err := s.TrafficSnapshots(NodeScope(survivor.ID))
	if err != nil {
		t.Fatal(err)
	}
	if alive[UserCounterKey(1)] != 20 {
		t.Fatalf("another node's traffic baseline was destroyed: %v", alive)
	}
}

// TestDeleteGroupSafelyLeavesNoDanglingMembers: losing a group must never leave a
// user pointing at a group id that no longer exists, whichever disposition the
// operator chose.
func TestDeleteGroupSafelyLeavesNoDanglingMembers(t *testing.T) {
	s := testStore(t)
	doomed := &Group{Name: "doomed"}
	target := &Group{Name: "target"}
	if err := s.CreateGroup(doomed); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup(target); err != nil {
		t.Fatal(err)
	}
	moved := &User{Username: "m", SubToken: "t-m", GroupID: doomed.ID}
	orphaned := &User{Username: "o", SubToken: "t-o", GroupID: doomed.ID}
	if err := s.CreateUser(moved); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(orphaned); err != nil {
		t.Fatal(err)
	}

	// Refuse while members have no disposition.
	if _, err := s.DeleteGroupSafely(doomed.ID, 0, false); err == nil {
		t.Fatal("a group with members was deleted without a disposition")
	}

	n, err := s.DeleteGroupSafely(doomed.ID, target.ID, false)
	if err != nil || n != 2 {
		t.Fatalf("reassignment failed: moved=%d err=%v", n, err)
	}
	for _, id := range []uint{moved.ID, orphaned.ID} {
		u, err := s.UserByID(id)
		if err != nil {
			t.Fatalf("a member was deleted with its group: %v", err)
		}
		if u.GroupID != target.ID {
			t.Fatalf("user %d points at group %d, want %d", id, u.GroupID, target.ID)
		}
	}

	// The allow-orphan path must clear the pointer rather than leave it dangling.
	if _, err := s.DeleteGroupSafely(target.ID, 0, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{moved.ID, orphaned.ID} {
		u, err := s.UserByID(id)
		if err != nil {
			t.Fatal(err)
		}
		if u.GroupID != 0 {
			t.Fatalf("user %d still points at the deleted group %d", id, u.GroupID)
		}
	}
	rep, err := repairOrphansIn(s)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Empty() {
		t.Fatalf("group deletion left orphans behind: %+v", rep)
	}
}

// repairOrphansIn runs the sweep the way the migration does — inside a
// transaction — so the tests exercise the real path. A transactional *gorm.DB
// does not clone its statement between chained calls, so a condition leaking
// from one sweep into the next would corrupt a different table; running it here
// is what proves that does not happen.
func repairOrphansIn(s *Store) (OrphanReport, error) {
	var rep OrphanReport
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var e error
		rep, e = repairOrphans(tx)
		return e
	})
	return rep, err
}

// TestRepairOrphansSweepsPreCascadeDamage: databases in the field already carry
// the rows the old non-cascading deletes left behind, so the migration has to
// find and remove them — and find nothing on a second pass.
func TestRepairOrphansSweepsPreCascadeDamage(t *testing.T) {
	s := testStore(t)
	live := makeInbound(t, s, "live", 443)
	u := &User{Username: "alice", SubToken: "tok"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	node := &Node{Name: "n", Address: "203.0.113.7", EnrollToken: "tk"}
	if err := s.CreateNode(node); err != nil {
		t.Fatal(err)
	}
	g := &Group{Name: "g", InboundIDs: IntSlice{live.ID, 4242}}
	if err := s.CreateGroup(g); err != nil {
		t.Fatal(err)
	}

	// Exactly the wreckage a pre-cascade delete leaves: join rows naming a gone
	// user and a gone inbound, a baseline for a gone node, and users/inbounds
	// pointing at ids that were removed out from under them.
	seed := []any{
		&UserInbound{UserID: u.ID, InboundID: live.ID},                                   // healthy, must survive
		&UserInbound{UserID: 9001, InboundID: live.ID},                                   // user is gone
		&UserInbound{UserID: u.ID, InboundID: 9002},                                      // inbound is gone
		&TrafficSnapshot{Scope: NodeScope(node.ID), Key: UserCounterKey(u.ID), Value: 5}, // healthy
		&TrafficSnapshot{Scope: NodeScope(node.ID), Key: UserCounterKey(9003), Value: 5}, // user is gone
	}
	for _, row := range seed {
		if err := s.db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	if err := s.db.Model(&User{}).Where("id = ?", u.ID).Update("group_id", 9004).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&Inbound{}).Where("id = ?", live.ID).Update("node_id", 9005).Error; err != nil {
		t.Fatal(err)
	}

	rep, err := repairOrphansIn(s)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Assignments != 2 || rep.TrafficBaselines != 1 || rep.GroupBindings != 1 ||
		rep.UserGroups != 1 || rep.InboundNodes != 1 {
		t.Fatalf("sweep did not find the expected damage: %+v", rep)
	}

	if n := countAssignments(t, s, "user_id", u.ID); n != 1 {
		t.Fatalf("healthy assignment count is %d, want 1", n)
	}
	if n := countAssignments(t, s, "inbound_id", live.ID); n != 1 {
		t.Fatalf("healthy inbound assignment count is %d, want 1", n)
	}
	snaps, err := s.TrafficSnapshots(NodeScope(node.ID))
	if err != nil {
		t.Fatal(err)
	}
	if snaps[UserCounterKey(u.ID)] != 5 {
		t.Fatalf("a healthy traffic baseline was swept: %v", snaps)
	}
	if _, orphan := snaps[UserCounterKey(9003)]; orphan {
		t.Fatalf("the orphaned baseline survived the sweep: %v", snaps)
	}
	gotGroup, err := s.GroupByID(g.ID)
	if err != nil || len(gotGroup.InboundIDs) != 1 || gotGroup.InboundIDs[0] != live.ID {
		t.Fatalf("group binding not pruned: %+v %v", gotGroup, err)
	}
	gotUser, err := s.UserByID(u.ID)
	if err != nil || gotUser.GroupID != 0 {
		t.Fatalf("dangling group pointer not cleared: %+v %v", gotUser, err)
	}
	gotIn, err := s.InboundByID(live.ID)
	if err != nil || gotIn.NodeID != 0 {
		t.Fatalf("dangling node pointer not cleared: %+v %v", gotIn, err)
	}

	rep2, err := repairOrphansIn(s)
	if err != nil {
		t.Fatal(err)
	}
	if !rep2.Empty() {
		t.Fatalf("the sweep is not idempotent: %+v", rep2)
	}
}
