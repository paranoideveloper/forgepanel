package service_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/service"
	"github.com/forgepanel/forgepanel/internal/store"
)

func setupTestService(t *testing.T) (*service.Manager, store.Interface) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	return service.NewManager(s), s
}

func TestFullPanelComplexLifecycle(t *testing.T) {
	ctx := context.Background()
	mgr, db := setupTestService(t)

	// Step 1: Enroll Node A
	nodeA, enrollCmd, tokenA, err := mgr.EnrollNode(ctx, "Node-Alpha", "192.168.1.10")
	if err != nil {
		t.Fatalf("EnrollNode Alpha failed: %v", err)
	}
	if nodeA.ID == 0 || tokenA == "" || enrollCmd == "" {
		t.Fatalf("Invalid Node Alpha output: id=%d token=%q", nodeA.ID, tokenA)
	}

	// Step 2: Create Inbound 1 attached to Node A
	nodeSpec1 := &model.Node{
		Protocol: model.ProtoVLESS,
		Port:     443,
		Address:  "192.168.1.10",
		Remark:   "VLESS-NodeA",
		UUID:     "a0a0a0a0-b1b1-c2c2-d3d3-e4e4e4e4e4e4",
	}
	inbound1, err := mgr.CreateInbound(ctx, nodeSpec1)
	if err != nil {
		t.Fatalf("CreateInbound 1 failed: %v", err)
	}

	// Step 3: Create User and assign to Inbound 1
	grp := &store.Group{Name: "VIP-Group", InboundIDs: store.IntSlice{inbound1.ID}}
	if err := db.CreateGroup(grp); err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	usr := &store.User{
		Username:  "user_alice",
		GroupID:   grp.ID,
		DataLimit: 10 * 1024 * 1024 * 1024, // 10 GB limit in bytes
		Status:    store.StatusActive,
	}
	if err := db.CreateUser(usr); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Step 4: Track traffic consumption & verify limit enforcement
	stats := map[string]int64{
		"user_alice": 5 * 1024 * 1024 * 1024, // 5 GB
	}
	expired, err := mgr.PollAndSyncTraffic(ctx, stats)
	if err != nil {
		t.Fatalf("PollAndSyncTraffic failed: %v", err)
	}
	if len(expired) != 0 {
		t.Errorf("Expected 0 expired users at 5GB usage, got %d", len(expired))
	}

	uCheck, _ := db.UserByID(usr.ID)
	if uCheck.UsedTraffic != 5*1024*1024*1024 {
		t.Errorf("Expected 5GB used, got %d", uCheck.UsedTraffic)
	}

	// Consume remaining 6 GB -> total 11 GB (exceeding 10 GB limit)
	statsOver := map[string]int64{
		"user_alice": 6 * 1024 * 1024 * 1024,
	}
	expired, err = mgr.PollAndSyncTraffic(ctx, statsOver)
	if err != nil {
		t.Fatalf("PollAndSyncTraffic (over limit) failed: %v", err)
	}
	if len(expired) != 1 || expired[0] != usr.ID {
		t.Errorf("Expected user %d to expire over limit, got %v", usr.ID, expired)
	}

	uCheckDisabled, _ := db.UserByID(usr.ID)
	if uCheckDisabled.Status != store.StatusDisabled {
		t.Errorf("Expected user status disabled, got %s", uCheckDisabled.Status)
	}

	// Reset traffic & verify reactivation
	if err := mgr.ResetUserTraffic(ctx, usr.ID); err != nil {
		t.Fatalf("ResetUserTraffic failed: %v", err)
	}
	uCheckReset, _ := db.UserByID(usr.ID)
	if uCheckReset.UsedTraffic != 0 || uCheckReset.Status != store.StatusActive {
		t.Errorf("Expected 0 traffic and Active status, got %d / %s", uCheckReset.UsedTraffic, uCheckReset.Status)
	}

	// Step 5: Add Node B
	nodeB, _, _, err := mgr.EnrollNode(ctx, "Node-Beta", "192.168.1.20")
	if err != nil {
		t.Fatalf("EnrollNode Beta failed: %v", err)
	}

	// Step 6: Create Group 2 and migrate user to Group 2 + Node B inbounds
	grp2 := &store.Group{Name: "Global-Group"}
	if err := db.CreateGroup(grp2); err != nil {
		t.Fatalf("CreateGroup 2 failed: %v", err)
	}

	nodeSpec2 := &model.Node{
		Protocol: model.ProtoTrojan,
		Port:     8443,
		Address:  "192.168.1.20",
		Remark:   "Trojan-NodeB",
		Password: "trojanpassword123",
	}
	inbound2, err := mgr.CreateInbound(ctx, nodeSpec2)
	if err != nil {
		t.Fatalf("CreateInbound 2 failed: %v", err)
	}

	// Migrate user alice to Group 2 with direct inbound 2
	if err := mgr.MigrateUser(ctx, usr.ID, grp2.ID, []uint{inbound2.ID}); err != nil {
		t.Fatalf("MigrateUser failed: %v", err)
	}

	uMigrated, _ := db.UserByID(usr.ID)
	if uMigrated.GroupID != grp2.ID {
		t.Errorf("Expected user group %d, got %d", grp2.ID, uMigrated.GroupID)
	}

	assigns, err := db.UserAssignments(usr.ID)
	if err != nil {
		t.Fatalf("UserAssignments failed: %v", err)
	}
	if len(assigns.Direct) != 1 || assigns.Direct[0] != inbound2.ID {
		t.Errorf("Expected direct inbound %d, got %v", inbound2.ID, assigns.Direct)
	}

	// Step 7: Migrate all Node A inbounds to Node B and Decommission Node A
	migratedCount, err := mgr.MigrateNodeInbounds(ctx, nodeA.ID, nodeB.ID)
	if err != nil {
		t.Fatalf("MigrateNodeInbounds failed: %v", err)
	}
	if migratedCount != 1 {
		t.Errorf("Expected 1 inbound migrated from Node A, got %d", migratedCount)
	}

	// Verify inbound 1 address is updated to Node B address
	in1Updated, _ := db.InboundByID(inbound1.ID)
	n1Spec, _ := in1Updated.Node()
	if n1Spec.Address != "192.168.1.20" {
		t.Errorf("Expected inbound 1 address updated to 192.168.1.20, got %s", n1Spec.Address)
	}

	// Decommission Node A with fallback to Node B
	if err := mgr.DecommissionNode(ctx, nodeA.ID, nodeB.ID); err != nil {
		t.Fatalf("DecommissionNode failed: %v", err)
	}

	nodes, _ := mgr.ListNodes(ctx)
	if len(nodes) != 1 || nodes[0].ID != nodeB.ID {
		t.Errorf("Expected only Node B remaining, got %v", nodes)
	}
}

func TestServiceEdgeCases(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupTestService(t)

	// Test non-existent node decommission
	if err := mgr.DecommissionNode(ctx, 9999, 0); err == nil {
		t.Error("Expected error decommissioning non-existent node, got nil")
	}

	// Test invalid inbound spec
	invalidSpec := &model.Node{Protocol: "unknown_proto"}
	if _, err := mgr.CreateInbound(ctx, invalidSpec); err == nil {
		t.Error("Expected error creating inbound with invalid protocol, got nil")
	}

	// Test user migration with invalid group
	if err := mgr.MigrateUser(ctx, 1, 9999, nil); err == nil {
		t.Error("Expected error migrating user to non-existent group, got nil")
	}
}

func TestTrafficCounterOverflowProtection(t *testing.T) {
	ctx := context.Background()
	mgr, db := setupTestService(t)

	usr := &store.User{Username: "user_overflow", Status: store.StatusActive}
	if err := db.CreateUser(usr); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Record huge traffic near int64 limit
	hugeTraffic := int64(9223372036854775800)
	if err := mgr.RecordTraffic(ctx, "user_overflow", hugeTraffic); err != nil {
		t.Fatalf("RecordTraffic failed: %v", err)
	}

	// Add more traffic that would overflow int64
	if err := mgr.RecordTraffic(ctx, "user_overflow", 1000); err != nil {
		t.Fatalf("RecordTraffic second pass failed: %v", err)
	}

	uReloaded, _ := db.UserByID(usr.ID)
	if uReloaded.UsedTraffic != 9223372036854775807 {
		t.Errorf("expected traffic clamped to MaxInt64 (9223372036854775807), got %d", uReloaded.UsedTraffic)
	}
}

func TestNodeDecommissionBlockedWhenInboundsAttached(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupTestService(t)

	nodeA, _, _, err := mgr.EnrollNode(ctx, "Node-Attached", "192.168.1.50")
	if err != nil {
		t.Fatalf("EnrollNode failed: %v", err)
	}

	nodeSpec := &model.Node{
		Protocol: model.ProtoVLESS, Port: 443, Address: "192.168.1.50", UUID: "a0a0a0a0-b1b1-c2c2-d3d3-e4e4e4e4e4e4",
	}
	if _, err := mgr.CreateInbound(ctx, nodeSpec); err != nil {
		t.Fatalf("CreateInbound failed: %v", err)
	}

	// Attempting to decommission Node A without a fallback node must fail
	if err := mgr.DecommissionNode(ctx, nodeA.ID, 0); err == nil {
		t.Error("expected error decommissioning node with attached inbounds without fallback, got nil")
	}
}

func TestNodeClientTrafficMergeAntiDoubleCount(t *testing.T) {
	ctx := context.Background()
	mgr, db := setupTestService(t)

	usr := &store.User{Username: "user_anti_double", Status: store.StatusActive}
	if err := db.CreateUser(usr); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// First heartbeat: cumulative = 1,000,000 bytes (1MB)
	delta1, err := mgr.MergeNodeClientTraffic(ctx, 1, "user_anti_double", 1000000)
	if err != nil {
		t.Fatalf("MergeNodeClientTraffic pass 1 failed: %v", err)
	}
	if delta1 != 1000000 {
		t.Errorf("expected initial delta = 1,000,000, got %d", delta1)
	}

	// Second heartbeat: cumulative = 1,500,000 bytes (500KB new delta)
	delta2, err := mgr.MergeNodeClientTraffic(ctx, 1, "user_anti_double", 1500000)
	if err != nil {
		t.Fatalf("MergeNodeClientTraffic pass 2 failed: %v", err)
	}
	if delta2 != 500000 {
		t.Errorf("expected delta 2 = 500,000, got %d", delta2)
	}

	// Third heartbeat after node restart: cumulative resets to 200,000 bytes
	delta3, err := mgr.MergeNodeClientTraffic(ctx, 1, "user_anti_double", 200000)
	if err != nil {
		t.Fatalf("MergeNodeClientTraffic pass 3 failed: %v", err)
	}
	if delta3 != 200000 {
		t.Errorf("expected delta 3 after restart = 200,000, got %d", delta3)
	}

	uReloaded, _ := db.UserByID(usr.ID)
	// Total traffic = 1,000,000 + 500,000 + 200,000 = 1,700,000 bytes
	if uReloaded.UsedTraffic != 1700000 {
		t.Errorf("expected total traffic = 1,700,000, got %d", uReloaded.UsedTraffic)
	}
}

func TestNodeAddressSSRFGuard(t *testing.T) {
	if err := service.ValidateNodeAddress("127.0.0.1"); err == nil {
		t.Error("expected SSRF error for 127.0.0.1, got nil")
	}
	if err := service.ValidateNodeAddress("localhost"); err == nil {
		t.Error("expected SSRF error for localhost, got nil")
	}
	if err := service.ValidateNodeAddress("192.168.1.100"); err != nil {
		t.Errorf("expected valid address 192.168.1.100, got %v", err)
	}
}

func TestNodeProactiveDirtyMarking(t *testing.T) {
	ctx := context.Background()
	mgr, db := setupTestService(t)

	nodeA, _, _, err := mgr.EnrollNode(ctx, "Node-Dirty", "192.168.1.88")
	if err != nil {
		t.Fatalf("EnrollNode failed: %v", err)
	}

	if err := mgr.MarkNodeDirty(ctx, nodeA.ID); err != nil {
		t.Fatalf("MarkNodeDirty failed: %v", err)
	}

	nDirty, _ := db.NodeByToken(nodeA.EnrollToken)
	if !nDirty.ConfigDirty || nDirty.ConfigDirtyAt == nil {
		t.Error("expected node marked dirty with timestamp")
	}

	if err := mgr.ClearNodeDirty(ctx, nodeA.ID); err != nil {
		t.Fatalf("ClearNodeDirty failed: %v", err)
	}

	nClean, _ := db.NodeByToken(nodeA.EnrollToken)
	if nClean.ConfigDirty || nClean.ConfigDirtyAt != nil {
		t.Error("expected node dirty flag cleared")
	}
}
