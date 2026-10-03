package api

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// An inbound marked sub_hidden is left out of every subscription a user can
// fetch, and nothing else about it changes: it is still in the running core
// configuration, so existing users keep their connection and their traffic
// keeps being counted.
func TestAHiddenInboundServesButIsNotHandedOut(t *testing.T) {
	s := dbServerT(t)
	visible, err := s.db.CreateInbound(&model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Domain: "vpn.example.com", Port: 4431,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "shown"})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := s.db.CreateInbound(&model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Domain: "vpn.example.com", Port: 4432,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "kept-quiet", SubHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "g", InboundIDs: []uint{visible.ID, hidden.ID}}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "alice", GroupID: g.ID, SubToken: "subhidden123",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	nodes := s.subscriptionNodes(u.SubToken, "panel.example.com")
	if len(nodes) != 1 || nodes[0].Port != 4431 {
		var ports []int
		for _, n := range nodes {
			ports = append(ports, n.Port)
		}
		t.Fatalf("subscription carries ports %v, want only 4431", ports)
	}
	if links := plainLinks(nodes); strings.Contains(links, "4432") {
		t.Fatalf("hidden inbound in the links: %s", links)
	}

	specs, _ := s.reloadSpecs()
	served := map[int]bool{}
	for _, sp := range specs {
		served[sp.Node.Port] = true
	}
	if !served[4431] || !served[4432] {
		t.Fatalf("both inbounds must keep serving; core config has %v", served)
	}
}
