package store

import (
	"testing"

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
