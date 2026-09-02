package store

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	return s
}

func TestStore_NodeOperations(t *testing.T) {
	s := newTestStore(t)

	// CreateNode
	node := &Node{
		Name:        "Edge-1",
		Address:     "192.168.1.100",
		EnrollToken: "tok-12345",
		Enrolled:    false,
		Healthy:     true,
	}
	if err := s.CreateNode(node); err != nil {
		t.Fatalf("CreateNode failed: %v", err)
	}
	if node.ID == 0 {
		t.Fatalf("expected non-zero ID after CreateNode")
	}

	// ListNodes
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes expected 1 node, got %d (err: %v)", len(nodes), err)
	}

	// NodeByToken
	fetched, err := s.NodeByToken("tok-12345")
	if err != nil || fetched.Name != "Edge-1" {
		t.Fatalf("NodeByToken failed: %v, node: %+v", err, fetched)
	}

	// SaveNode
	fetched.Address = "10.0.0.1"
	fetched.CoreVersion = "1.8.0"
	if err := s.SaveNode(fetched); err != nil {
		t.Fatalf("SaveNode failed: %v", err)
	}

	updated, _ := s.NodeByToken("tok-12345")
	if updated.Address != "10.0.0.1" || updated.CoreVersion != "1.8.0" {
		t.Fatalf("SaveNode changes not reflected: %+v", updated)
	}

	// DeleteNode
	if err := s.DeleteNode(node.ID); err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}

	afterDelete, _ := s.ListNodes()
	if len(afterDelete) != 0 {
		t.Fatalf("expected 0 nodes after DeleteNode, got %d", len(afterDelete))
	}
}

func TestStore_ZoneOperations(t *testing.T) {
	s := newTestStore(t)

	// CreateZone
	zone := &ForgeDNSZone{
		Zone:     "example.com",
		Adapter:  "cottendns",
		Enabled:  true,
		BindHost: "0.0.0.0",
		BindPort: 53,
	}
	if err := s.CreateZone(zone); err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}

	// ListZones
	zones, err := s.ListZones()
	if err != nil || len(zones) != 1 {
		t.Fatalf("ListZones expected 1 zone, got %d (err: %v)", len(zones), err)
	}

	// ZoneByID
	fz, err := s.ZoneByID(zone.ID)
	if err != nil || fz.Zone != "example.com" {
		t.Fatalf("ZoneByID failed: %v, zone: %+v", err, fz)
	}

	// SaveZone
	fz.Enabled = false
	fz.BindPort = 5300
	if err := s.SaveZone(fz); err != nil {
		t.Fatalf("SaveZone failed: %v", err)
	}

	updatedZone, _ := s.ZoneByID(zone.ID)
	if updatedZone.Enabled || updatedZone.BindPort != 5300 {
		t.Fatalf("SaveZone changes not saved properly: %+v", updatedZone)
	}

	// DeleteZone
	if err := s.DeleteZone(zone.ID); err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}

	_, err = s.ZoneByID(zone.ID)
	if err == nil {
		t.Fatalf("expected error fetching deleted zone, got nil")
	}
}

func TestStore_AdminSecurityOperations(t *testing.T) {
	s := newTestStore(t)

	admin := &Admin{
		Username:     "admin",
		PasswordHash: "hashedpass",
		Role:         RoleOwner,
		TOTPSecret:   "JBSWY3DPEHPK3PXP",
		SessionEpoch: 1,
	}
	if err := s.CreateAdmin(admin); err != nil {
		t.Fatalf("CreateAdmin failed: %v", err)
	}

	// AdminByID
	fa, err := s.AdminByID(admin.ID)
	if err != nil || fa.Username != "admin" {
		t.Fatalf("AdminByID failed: %v", err)
	}

	// SaveAdmin
	fa.Disabled = true
	if err := s.SaveAdmin(fa); err != nil {
		t.Fatalf("SaveAdmin failed: %v", err)
	}

	// SetAdminRecoveryCodes
	codesJSON := `["hash1","hash2","hash3"]`
	if err := s.SetAdminRecoveryCodes(admin.ID, codesJSON); err != nil {
		t.Fatalf("SetAdminRecoveryCodes failed: %v", err)
	}

	fa, _ = s.AdminByID(admin.ID)
	if fa.RecoveryCodes != codesJSON {
		t.Fatalf("expected recovery codes %s, got %s", codesJSON, fa.RecoveryCodes)
	}

	// ConsumeRecoveryCode
	used, remaining, err := s.ConsumeRecoveryCode(admin.ID, func(h string) bool {
		return h == "hash2"
	})
	if err != nil || !used || remaining != 2 {
		t.Fatalf("ConsumeRecoveryCode failed: used=%v, remaining=%d, err=%v", used, remaining, err)
	}

	// BumpAdminSessionEpoch & AdminSessionEpoch
	epoch, err := s.AdminSessionEpoch(admin.ID)
	if err != nil || epoch != 1 {
		t.Fatalf("AdminSessionEpoch failed: epoch=%d, err=%v", epoch, err)
	}

	if err := s.BumpAdminSessionEpoch(admin.ID); err != nil {
		t.Fatalf("BumpAdminSessionEpoch failed: %v", err)
	}

	newEpoch, _ := s.AdminSessionEpoch(admin.ID)
	if newEpoch != 2 {
		t.Fatalf("expected epoch 2 after bump, got %d", newEpoch)
	}

	// ClaimTOTPStep
	claimed, err := s.ClaimTOTPStep(admin.ID, 100)
	if err != nil || !claimed {
		t.Fatalf("ClaimTOTPStep step 100 failed: %v", err)
	}

	// Re-claim step 100 should fail or return false
	claimedAgain, err := s.ClaimTOTPStep(admin.ID, 100)
	if err != nil || claimedAgain {
		t.Fatalf("ClaimTOTPStep replay should fail, got claimed=%v, err=%v", claimedAgain, err)
	}
}

func TestStore_AssignmentsAndUsers(t *testing.T) {
	s := newTestStore(t)

	// Create Group
	grp := &Group{Name: "VIP", Description: "VIP Group"}
	if err := s.CreateGroup(grp); err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// SetDefaultGroup & DefaultGroup
	if err := s.SetDefaultGroup(grp.ID); err != nil {
		t.Fatalf("SetDefaultGroup failed: %v", err)
	}
	defGrp := s.DefaultGroup()
	if defGrp == nil || defGrp.ID != grp.ID {
		t.Fatalf("DefaultGroup mismatch: %+v", defGrp)
	}

	// Create Inbounds
	node1 := &model.Node{Tag: "inbound-1", Protocol: model.ProtoVLESS, Port: 443}
	node2 := &model.Node{Tag: "inbound-2", Protocol: model.ProtoVMess, Port: 8443}

	in1, err := s.CreateInbound(node1)
	if err != nil {
		t.Fatalf("CreateInbound 1 failed: %v", err)
	}
	in2, err := s.CreateInbound(node2)
	if err != nil {
		t.Fatalf("CreateInbound 2 failed: %v", err)
	}

	// Create User
	usr := &User{
		Username: "john_doe",
		GroupID:  grp.ID,
		Status:   StatusActive,
		SubToken: "subtoken123",
	}
	if err := s.CreateUser(usr); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// UsersInGroup
	count, err := s.UsersInGroup(grp.ID)
	if err != nil || count != 1 {
		t.Fatalf("UsersInGroup expected 1, got %d (err: %v)", count, err)
	}

	// SetUserInbounds
	if err := s.SetUserInbounds(usr.ID, []uint{in1.ID, in2.ID}, nil); err != nil {
		t.Fatalf("SetUserInbounds failed: %v", err)
	}

	// UserAssignments & InboundsForUser
	assigns, err := s.UserAssignments(usr.ID)
	if err != nil || len(assigns.Direct) != 2 {
		t.Fatalf("UserAssignments failed: %+v (err: %v)", assigns, err)
	}

	effInbounds, err := s.InboundsForUser(usr.ID)
	if err != nil || len(effInbounds) != 2 {
		t.Fatalf("InboundsForUser failed: %v (err: %v)", effInbounds, err)
	}

	// UpdateUserFields
	err = s.UpdateUserFields(usr.ID, map[string]any{"data_limit": int64(5000000)}, time.Time{})
	if err != nil {
		t.Fatalf("UpdateUserFields failed: %v", err)
	}

	freshUser, _ := s.UserByID(usr.ID)
	if freshUser.DataLimit != 5000000 {
		t.Fatalf("DataLimit not updated: %d", freshUser.DataLimit)
	}

	// UpdateGroupFields
	err = s.UpdateGroupFields(grp.ID, map[string]any{"name": "VIP Premium"}, time.Time{})
	if err != nil {
		t.Fatalf("UpdateGroupFields failed: %v", err)
	}

	// DeleteGroupSafely
	moved, err := s.DeleteGroupSafely(grp.ID, 0, true)
	if err != nil || moved != 1 {
		t.Fatalf("DeleteGroupSafely failed: moved=%d, err=%v", moved, err)
	}

	// DeleteUserCascade
	if err := s.DeleteUserCascade(usr.ID); err != nil {
		t.Fatalf("DeleteUserCascade failed: %v", err)
	}

	_, err = s.UserByID(usr.ID)
	if err == nil {
		t.Fatalf("expected error fetching deleted user, got nil")
	}
}

func TestStore_SettingsAndAudit(t *testing.T) {
	s := newTestStore(t)

	// SetSetting & GetSetting
	if err := s.SetSetting("panel_name", "ForgePanel Pro"); err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	val := s.GetSetting("panel_name")
	if val != "ForgePanel Pro" {
		t.Fatalf("GetSetting failed: got %q", val)
	}

	// Audit
	s.Audit(&AuditLog{Actor: "admin", Action: "user.create", IP: "1.2.3.4", Target: "bob"})
}

// A deleted user's traffic baselines must go with them, on EVERY scope. SQLite
// hands out the lowest free rowid, so the next user created can be given this
// id — and inheriting a large stale baseline means their first real traffic
// computes a delta of zero and they transfer free until their own usage passes
// the dead account's total.
func TestDeleteUserCascadePurgesTrafficBaselines(t *testing.T) {
	s := newTestStore(t)
	u := &User{Username: "purge_test_user"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	other := &User{Username: "keeper", SubToken: "kt"}
	if err := s.CreateUser(other); err != nil {
		t.Fatal(err)
	}

	// One baseline on the local engine, one on a node, plus a bystander.
	for _, scope := range []string{ScopeLocalEngine, NodeScope(10)} {
		if err := s.SetTrafficSnapshot(scope, UserCounterKey(u.ID), 5000); err != nil {
			t.Fatal(err)
		}
		if err := s.SetTrafficSnapshot(scope, UserCounterKey(other.ID), 7000); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.DeleteUserCascade(u.ID); err != nil {
		t.Fatalf("DeleteUserCascade failed: %v", err)
	}

	for _, scope := range []string{ScopeLocalEngine, NodeScope(10)} {
		snaps, err := s.TrafficSnapshots(scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, still := snaps[UserCounterKey(u.ID)]; still {
			t.Errorf("scope %s kept the deleted user's baseline; a reused id would transfer free", scope)
		}
		if snaps[UserCounterKey(other.ID)] != 7000 {
			t.Errorf("scope %s lost another user's baseline: %v", scope, snaps)
		}
	}
}
