package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInboundRoundTrip(t *testing.T) {
	s := testStore(t)
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision",
		Remark: "in-1", Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, ServerName: "a.com",
			Reality: &model.Reality{PublicKey: "pk", ShortID: "0123abcd"}},
	}
	in, err := s.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.InboundByID(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	rn, err := got.Node()
	if err != nil {
		t.Fatal(err)
	}
	if rn.UUID != n.UUID || rn.Protocol != n.Protocol || rn.Security.Type != model.SecReality {
		t.Fatalf("inbound did not round-trip through the DB: %+v", rn)
	}
}

func TestGroupBindingAndUsers(t *testing.T) {
	s := testStore(t)
	in, _ := s.CreateInbound(&model.Node{Protocol: model.ProtoVLESS, Address: "h", Port: 1,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: model.Transport{Network: model.NetTCP}})
	g := &Group{Name: "g1", InboundIDs: IntSlice{in.ID}}
	if err := s.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GroupByID(g.ID)
	if err != nil || len(got.InboundIDs) != 1 || got.InboundIDs[0] != in.ID {
		t.Fatalf("group binding not persisted: %+v %v", got, err)
	}
	u := &User{Username: "alice", GroupID: g.ID, SubToken: "tok123", UUID: "u-uuid", Status: StatusActive}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	back, err := s.UserBySubToken("tok123")
	if err != nil || back.Username != "alice" {
		t.Fatalf("user by sub token failed: %+v %v", back, err)
	}
}

func TestResellerIsolation(t *testing.T) {
	s := testStore(t)
	_ = s.CreateUser(&User{Username: "a", OwnerAdminID: 1, SubToken: "t1"})
	_ = s.CreateUser(&User{Username: "b", OwnerAdminID: 2, SubToken: "t2"})
	only1, _ := s.ListUsers(1)
	if len(only1) != 1 || only1[0].Username != "a" {
		t.Fatalf("reseller isolation broken: %+v", only1)
	}
	all, _ := s.ListUsers(0)
	if len(all) != 2 {
		t.Fatalf("owner should see all users, got %d", len(all))
	}
}

func TestStore_NodeAndZoneOperations(t *testing.T) {
	s := testStore(t)

	n := &Node{Name: "Node1", Address: "10.0.0.1", EnrollToken: "sec123"}
	if err := s.CreateNode(n); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 {
		t.Fatalf("ListNodes: %v, count=%d", err, len(nodes))
	}

	byID, err := s.NodeByID(n.ID)
	if err != nil || byID.Name != "Node1" {
		t.Fatalf("NodeByID: %v", err)
	}

	byToken, err := s.NodeByToken("sec123")
	if err != nil || byToken.ID != n.ID {
		t.Fatalf("NodeByToken: %v", err)
	}

	n.Name = "Node1-Updated"
	if err := s.SaveNode(n); err != nil {
		t.Fatalf("SaveNode: %v", err)
	}

	// Traffic baselines round-trip and are scoped to their node.
	if err := s.SetTrafficSnapshot(NodeScope(n.ID), UserCounterKey(42), 100); err != nil {
		t.Fatalf("SetTrafficSnapshot: %v", err)
	}
	snaps, err := s.TrafficSnapshots(NodeScope(n.ID))
	if err != nil || snaps[UserCounterKey(42)] != 100 {
		t.Fatalf("TrafficSnapshots: %v %v", snaps, err)
	}
	if err := s.ClearTrafficSnapshots(NodeScope(n.ID)); err != nil {
		t.Fatalf("ClearTrafficSnapshots: %v", err)
	}

	if err := s.DeleteNode(n.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}

	// Zone tests
	z := &ForgeDNSZone{Zone: "example.com", Enabled: true}
	if err := s.CreateZone(z); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	zones, err := s.ListZones()
	if err != nil || len(zones) != 1 {
		t.Fatalf("ListZones: %v", err)
	}
	zByID, err := s.ZoneByID(z.ID)
	if err != nil || zByID.Zone != "example.com" {
		t.Fatalf("ZoneByID: %v", err)
	}
	z.Zone = "example.org"
	if err := s.SaveZone(z); err != nil {
		t.Fatalf("SaveZone: %v", err)
	}
	if err := s.DeleteZone(z.ID); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
}

func TestStore_AdminAndSettings(t *testing.T) {
	s := testStore(t)

	a := &Admin{Username: "admin", PasswordHash: "hash", Role: RoleOwner}
	if err := s.CreateAdmin(a); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	count, err := s.CountAdmins()
	if err != nil || count != 1 {
		t.Fatalf("CountAdmins: %v, count=%d", err, count)
	}

	gotA, err := s.AdminByUsername("admin")
	if err != nil || gotA.ID != a.ID {
		t.Fatalf("AdminByUsername: %v", err)
	}

	gotByID, err := s.AdminByID(a.ID)
	if err != nil || gotByID.Username != "admin" {
		t.Fatalf("AdminByID: %v", err)
	}

	if err := s.BumpAdminSessionEpoch(a.ID); err != nil {
		t.Fatalf("BumpAdminSessionEpoch: %v", err)
	}
	epoch, err := s.AdminSessionEpoch(a.ID)
	if err != nil || epoch != 1 {
		t.Fatalf("AdminSessionEpoch: %d, %v", epoch, err)
	}

	claimed, err := s.ClaimTOTPStep(a.ID, 1000)
	if err != nil || !claimed {
		t.Fatalf("ClaimTOTPStep: %v, %v", claimed, err)
	}
	claimedAgain, _ := s.ClaimTOTPStep(a.ID, 1000)
	if claimedAgain {
		t.Fatalf("ClaimTOTPStep expected false for duplicate step")
	}

	if err := s.SetSetting("key1", "val1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if v := s.GetSetting("key1"); v != "val1" {
		t.Fatalf("GetSetting: %s", v)
	}

	s.Audit(&AuditLog{AdminID: a.ID, Action: "test", Actor: "admin"})
}

// TestResetUserUsageCASReactivatesLimited: a periodic reset (monthly renewal)
// must both zero the usage AND lift a StatusLimited user back to active, or a
// user who once hit their cap would stay cut off forever after their quota
// renews. An account past its expiry stays limited — a renewed quota does not
// resurrect an expired account.
func TestResetUserUsageCASReactivatesLimited(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	// A limited, not-yet-expired user.
	limited := &User{Username: "limited", SubToken: "lt", Status: StatusLimited,
		DataLimit: 1000, UsedTraffic: 1500}
	if err := s.CreateUser(limited); err != nil {
		t.Fatal(err)
	}
	applied, err := s.ResetUserUsageCAS(limited.ID, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("reset was not applied on a fresh period")
	}
	got, _ := s.UserByID(limited.ID)
	if got.UsedTraffic != 0 {
		t.Fatalf("usage not reset: %d", got.UsedTraffic)
	}
	if got.Status != StatusActive {
		t.Fatalf("a limited user was not reactivated on reset: status=%s", got.Status)
	}

	// A limited AND expired user: reset zeroes usage but must NOT reactivate.
	past := now.Add(-time.Hour)
	expired := &User{Username: "expired", SubToken: "ex", Status: StatusLimited,
		DataLimit: 1000, UsedTraffic: 1500, ExpireAt: &past}
	if err := s.CreateUser(expired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetUserUsageCAS(expired.ID, now, now); err != nil {
		t.Fatal(err)
	}
	got2, _ := s.UserByID(expired.ID)
	if got2.Status != StatusLimited {
		t.Fatalf("an expired user must stay limited after a quota reset, got status=%s", got2.Status)
	}
}

// TestCreatingADisabledInboundKeepsItDisabled guards a GORM landmine.
//
// Inbound.Enabled carries `gorm:"default:true"`, and GORM omits a zero-valued
// field on INSERT when its column declares a default — so creating an inbound
// with Enabled:false stored it as ENABLED. A caller that asked for a disabled
// inbound got a live listener on a port they had not agreed to open.
//
// GORM also writes the applied default BACK into the struct, so the in-memory
// value reads true afterwards too: nothing anywhere retained what was asked for.
func TestCreatingADisabledInboundKeepsItDisabled(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	in := &Inbound{Remark: "deliberately-off", Protocol: "vless", Port: 1443, Enabled: false}
	if err := db.SaveInbound(in); err != nil {
		t.Fatal(err)
	}
	if in.Enabled {
		t.Error("the struct was rewritten to enabled; the caller's request is gone")
	}
	got, err := db.InboundByID(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatal("an inbound created as disabled was stored as ENABLED — a listener on a port nobody agreed to open")
	}

	// The default must still apply when the caller says nothing about it, or
	// every existing creation path starts producing dead inbounds.
	on := &Inbound{Remark: "default-on", Protocol: "vless", Port: 1444, Enabled: true}
	if err := db.SaveInbound(on); err != nil {
		t.Fatal(err)
	}
	back, err := db.InboundByID(on.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Enabled {
		t.Fatal("an inbound created as enabled is disabled")
	}

	// And disabling an EXISTING inbound must keep working: that path writes
	// every field and was never affected, but it is the one operators use.
	back.Enabled = false
	if err := db.SaveInbound(back); err != nil {
		t.Fatal(err)
	}
	again, _ := db.InboundByID(on.ID)
	if again.Enabled {
		t.Fatal("disabling an existing inbound did not stick")
	}
}

// The username column has always carried a unique index and the store had no
// query that used it, so every caller that needed a user by name loaded the
// WHOLE user table and walked it. The Telegram bot did that on every command.
func TestUserByUsernameUsesTheIndexAndNotAScan(t *testing.T) {
	s := testStore(t)
	for _, n := range []string{"alice", "bob", "carol"} {
		if err := s.CreateUser(&User{Username: n, SubToken: "tok-" + n}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := s.UserByUsername("bob")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "bob" {
		t.Fatalf("got %q", u.Username)
	}

	// A miss must be an error, not the zero user. A caller that checked only
	// the name would treat a zero-valued User as "found, with no data".
	if _, err := s.UserByUsername("nobody"); err == nil {
		t.Error("an unknown username returned no error")
	}

	// SQLite tells us whether the plan is a scan. This is the whole point of the
	// change, and asserting only on the returned row would pass just as well
	// against the loop this replaced.
	var plan []struct {
		ID, Parent, NotUsed int
		Detail              string
	}
	if err := s.db.Raw("EXPLAIN QUERY PLAN SELECT * FROM users WHERE username = ?", "bob").Scan(&plan).Error; err != nil {
		t.Fatal(err)
	}
	if len(plan) == 0 {
		t.Fatal("no query plan returned")
	}
	joined := ""
	for _, r := range plan {
		joined += r.Detail + " "
	}
	if !strings.Contains(joined, "USING INDEX") && !strings.Contains(joined, "USING COVERING INDEX") {
		t.Errorf("the lookup does not use an index: %s", joined)
	}
}

func TestCountsDoesNotLoadTheTables(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 5; i++ {
		if err := s.CreateUser(&User{Username: fmt.Sprintf("u%d", i), SubToken: fmt.Sprintf("tok%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	ins, us, gs, err := s.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if us != 5 {
		t.Errorf("users = %d, want 5", us)
	}
	if ins != 0 || gs != 0 {
		t.Errorf("inbounds/groups = %d/%d, want 0/0", ins, gs)
	}
}
