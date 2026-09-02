package api

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func storeAWG(t *testing.T, s *Server, port int, serverAddr, peerAddr string) {
	t.Helper()
	n := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "0.0.0.0", Port: port,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "S", PublicKey: "P", PeerPrivateKey: "C", PeerPublicKey: "CP",
			ServerAddress: []string{serverAddr}, PeerAddress: []string{peerAddr}, MTU: 1420,
		}}}
	if _, err := s.db.CreateInbound(n); err != nil {
		t.Fatal(err)
	}
}

// TestASecondTunnelInboundGetsItsOwnSubnet is the fix for two kernel interfaces
// holding the same address.
//
// Every WireGuard inbound was given 10.66.66.0/24 and every AmneziaWG inbound
// 10.67.67.0/24. A live panel ended up with awg5454 and awg8448 both on
// 10.67.67.1/24 and two routes for the same prefix: the kernel answers for one,
// and the other completes a handshake whose return traffic leaves by the wrong
// interface. The inbound looks configured, shows a peer, and carries nothing.
func TestASecondTunnelInboundGetsItsOwnSubnet(t *testing.T) {
	s := dbServerT(t)
	storeAWG(t, s, 5454, "10.67.67.1/24", "10.67.67.2/32")

	second := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "0.0.0.0", Port: 8448}
	s.allocateTunnelSubnet(second)
	applyCreateDefaults(second)

	got := second.AmneziaWG.ServerAddress
	if len(got) == 0 {
		t.Fatal("no server address was allocated at all")
	}
	if strings.HasPrefix(got[0], "10.67.67.") {
		t.Fatalf("second AmneziaWG inbound landed on the first one's prefix (%s); "+
			"two interfaces would hold the same address", got[0])
	}
	if !strings.HasPrefix(got[0], "10.67.") {
		t.Errorf("allocated outside the AmneziaWG block: %s", got[0])
	}
	// The peer must move with the server, or the clients collide instead.
	if p := second.AmneziaWG.PeerAddress; len(p) == 0 || strings.HasPrefix(p[0], "10.67.67.") {
		t.Errorf("peer address still on the old prefix: %v", p)
	}
}

// TestTheFirstTunnelInboundKeepsItsHistoricalSubnet: an upgrade must not move a
// tunnel whose config operators have already handed out.
func TestTheFirstTunnelInboundKeepsItsHistoricalSubnet(t *testing.T) {
	s := dbServerT(t)
	for _, tc := range []struct {
		proto model.Protocol
		want  string
	}{{model.ProtoWireGuard, "10.66.66."}, {model.ProtoAmneziaWG, "10.67.67."}} {
		n := &model.Node{Protocol: tc.proto, Address: "0.0.0.0", Port: 51820}
		s.allocateTunnelSubnet(n)
		applyCreateDefaults(n)
		var got []string
		if n.WireGuard != nil {
			got = n.WireGuard.ServerAddress
		} else {
			got = n.AmneziaWG.ServerAddress
		}
		if len(got) == 0 || !strings.HasPrefix(got[0], tc.want) {
			t.Errorf("%s first inbound = %v, want the historical %s0/24", tc.proto, got, tc.want)
		}
	}
}

// TestWireGuardAndAmneziaWGDoNotShareAPrefix: a WireGuard and an AmneziaWG
// inbound on the same prefix collide exactly as two of the same protocol would,
// so the allocator consults both families.
func TestWireGuardAndAmneziaWGDoNotShareAPrefix(t *testing.T) {
	s := dbServerT(t)
	n := &model.Node{Protocol: model.ProtoWireGuard, Address: "0.0.0.0", Port: 3445,
		WireGuard: &model.WireGuardOptions{
			PrivateKey: "S", PublicKey: "P", PeerPrivateKey: "C", PeerPublicKey: "CP",
			ServerAddress: []string{"10.67.70.1/24"}, PeerAddress: []string{"10.67.70.2/32"}, MTU: 1420,
		}}
	if _, err := s.db.CreateInbound(n); err != nil {
		t.Fatal(err)
	}
	used := s.usedTunnelOctets(awgBlock)
	if !used[70] {
		t.Error("a WireGuard inbound sitting in the AmneziaWG block was not counted as used")
	}
}

// TestAnOperatorChosenSubnetIsLeftAlone.
func TestAnOperatorChosenSubnetIsLeftAlone(t *testing.T) {
	s := dbServerT(t)
	n := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "0.0.0.0", Port: 9999,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			ServerAddress: []string{"172.30.1.1/24"}, PeerAddress: []string{"172.30.1.2/32"},
		}}}
	s.allocateTunnelSubnet(n)
	if n.AmneziaWG.ServerAddress[0] != "172.30.1.1/24" {
		t.Errorf("overwrote the operator's address: %v", n.AmneziaWG.ServerAddress)
	}
}

var _ = store.Inbound{}
