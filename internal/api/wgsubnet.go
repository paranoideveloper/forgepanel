package api

// Tunnel subnet allocation for WireGuard and AmneziaWG inbounds.
//
// Every WireGuard inbound was given 10.66.66.0/24 and every AmneziaWG inbound
// 10.67.67.0/24, hard-coded. Creating a SECOND inbound of either protocol
// therefore produced two kernel interfaces holding the same address, two routes
// for the same prefix, and two peers on the same client IP:
//
//	awg5454   10.67.67.1/24
//	awg8448   10.67.67.1/24
//	10.67.67.0/24 dev awg5454
//	10.67.67.0/24 dev awg8448
//
// The kernel answers for one of them. The other completes a handshake and its
// return traffic leaves through the wrong interface, so the inbound looks
// configured, reports a peer, and carries nothing. Observed on a live panel
// where the operator's second AmneziaWG inbound could not be made to work.
//
// Each inbound now takes the next free /24 from its protocol's block, skipping
// anything an existing inbound already holds.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Tunnel address blocks, one per protocol so the two families never interleave
// and an operator reading `ip addr` can tell at a glance which is which.
const (
	wgBlock  = "10.66."
	awgBlock = "10.67."
)

// allocateTunnelSubnet gives n a server and peer address that no other inbound
// is using. It leaves an address the operator chose alone.
func (s *Server) allocateTunnelSubnet(n *model.Node) {
	var w *model.WireGuardOptions
	block := wgBlock
	// The options block is created here when absent, because this runs BEFORE
	// applyCreateDefaults — at which point a freshly posted inbound has none.
	// Returning early on nil was why the first version of this allocated
	// nothing and the constant won anyway.
	switch n.Protocol {
	case model.ProtoWireGuard:
		if n.WireGuard == nil {
			n.WireGuard = &model.WireGuardOptions{}
		}
		w = n.WireGuard
	case model.ProtoAmneziaWG:
		if n.AmneziaWG == nil {
			n.AmneziaWG = &model.AmneziaWGOptions{}
		}
		w, block = &n.AmneziaWG.WireGuardOptions, awgBlock
	default:
		return
	}
	// An operator-chosen address is theirs; only fill in what was left blank.
	if len(w.ServerAddress) != 0 && len(w.PeerAddress) != 0 {
		return
	}
	third := s.freeTunnelOctet(block)
	if len(w.ServerAddress) == 0 {
		w.ServerAddress = []string{fmt.Sprintf("%s%d.1/24", block, third)}
	}
	if len(w.PeerAddress) == 0 {
		w.PeerAddress = []string{fmt.Sprintf("%s%d.2/32", block, third)}
	}
}

// freeTunnelOctet returns the lowest third octet in the block that no stored
// inbound is already using.
//
// It starts at 66/67 so the FIRST inbound of each protocol keeps the address
// the panel has always given it — an upgrade must not move a tunnel that
// operators have already handed configs out for.
func (s *Server) freeTunnelOctet(block string) int {
	start := 66
	if block == awgBlock {
		start = 67
	}
	used := s.usedTunnelOctets(block)
	for i := 0; i < 254; i++ {
		// 66, 67, … 253, then wrap to 1.
		o := start + i
		if o > 253 {
			o = 1 + (o - 254)
		}
		if !used[o] {
			return o
		}
	}
	return start
}

// usedTunnelOctets reads the third octet of every tunnel address already
// stored, for either protocol. Both families are consulted rather than just the
// one being allocated: a WireGuard and an AmneziaWG inbound on the same prefix
// collide exactly as two of the same protocol would.
func (s *Server) usedTunnelOctets(block string) map[int]bool {
	used := map[int]bool{}
	if s.db == nil {
		return used
	}
	rows, err := s.db.ListInbounds()
	if err != nil {
		return used
	}
	for i := range rows {
		n, err := rows[i].Node()
		if err != nil || n == nil {
			continue
		}
		for _, w := range tunnelOptionsOf(n) {
			for _, a := range append(append([]string{}, w.ServerAddress...), w.PeerAddress...) {
				if o, ok := thirdOctetIn(block, a); ok {
					used[o] = true
				}
			}
		}
	}
	return used
}

func tunnelOptionsOf(n *model.Node) []*model.WireGuardOptions {
	var out []*model.WireGuardOptions
	if n.WireGuard != nil {
		out = append(out, n.WireGuard)
	}
	if n.AmneziaWG != nil {
		out = append(out, &n.AmneziaWG.WireGuardOptions)
	}
	return out
}

// thirdOctetIn reports the third octet of addr when it falls inside block.
func thirdOctetIn(block, addr string) (int, bool) {
	addr = strings.TrimSpace(addr)
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return 0, false
	}
	if !strings.HasPrefix(addr, block) {
		return 0, false
	}
	return int(ip.As4()[2]), true
}
