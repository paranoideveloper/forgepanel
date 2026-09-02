package api

// Materialising per-client WireGuard peers into the served config.
//
// A WireGuard inbound carried exactly ONE client keypair, so assigning several
// users to it could not be expressed: WireGuard keys a session by public key,
// and five clients sharing a key take the tunnel from each other in turn rather
// than sharing it. The server-config renderer has always accepted a LIST of
// peers; both callers passed a one-element slice containing the inbound itself.

import (
	"fmt"
	"os"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/wgpeer"
)

// peerManager returns the WireGuard peer manager.
//
// Held on the Server, not in a package-level sync.Once: a package singleton
// would make every Server in one process share the first one's database and
// encryption key, which is silently wrong in tests and wrong outright for any
// process that runs two panels.
func (s *Server) peerManager() (*wgpeer.Manager, error) {
	s.wgOnce.Do(func() {
		if s.db == nil {
			s.wgErr = fmt.Errorf("per-client WireGuard peers need the database")
			return
		}
		enc, err := dns.NewAESGCMFromPassphrase(deriveSecret(s.cfg))
		if err != nil {
			s.wgErr = err
			return
		}
		s.wgMgr = wgpeer.New(s.db, enc)
	})
	return s.wgMgr, s.wgErr
}

// wgServerCIDR is the address range an inbound allocates peers from.
func wgServerCIDR(n *model.Node) string {
	var w *model.WireGuardOptions
	switch {
	case n.Protocol == model.ProtoWireGuard && n.WireGuard != nil:
		w = n.WireGuard
	case n.Protocol == model.ProtoAmneziaWG && n.AmneziaWG != nil:
		w = &n.AmneziaWG.WireGuardOptions
	default:
		return ""
	}
	if len(w.ServerAddress) > 0 {
		return w.ServerAddress[0]
	}
	if len(w.LocalAddress) > 0 {
		return w.LocalAddress[0]
	}
	return ""
}

// applyWGPeers fills a WireGuard-family node's peer list from its assigned
// users, minting a peer for any user that does not have one yet.
//
// A node with no assigned users is left alone, so it renders exactly as it
// always did — this cannot change what a single-user inbound serves.
func (s *Server) applyWGPeers(n *model.Node, inboundID uint, users []store.User) {
	if n.Protocol != model.ProtoWireGuard && n.Protocol != model.ProtoAmneziaWG {
		return
	}
	if len(users) == 0 {
		return
	}
	cidr := wgServerCIDR(n)
	if cidr == "" {
		return
	}
	mgr, err := s.peerManager()
	if err != nil {
		fmt.Fprintln(os.Stderr, "forgepanel: per-client WireGuard peers unavailable:", err)
		return
	}
	for _, u := range users {
		if _, err := mgr.EnsurePeer(inboundID, u.ID, cidr); err != nil {
			// One user who cannot be allocated must not blank the peer list and
			// disconnect everyone else on the inbound. Report and carry on.
			fmt.Fprintf(os.Stderr, "forgepanel: no WireGuard peer for user %d on inbound %d: %v\n",
				u.ID, inboundID, err)
		}
	}
	peers, err := mgr.ServerPeers(inboundID)
	if err != nil || len(peers) == 0 {
		return
	}
	entries := make([]model.WGPeerEntry, 0, len(peers)+1)
	for _, p := range peers {
		entries = append(entries, model.WGPeerEntry{
			PublicKey: p.PublicKey, PresharedKey: p.Preshared, AllowedIPs: []string{p.Address},
		})
		// A rotated-away key inside its grace window gets its own entry with the
		// same AllowedIPs. They are the same client and only one of the two keys
		// will ever complete a handshake, so this is what lets a rotation happen
		// without cutting off a client that has not fetched its new config —
		// and a rotation that disconnects everyone is one nobody performs.
		if p.PreviousPublicKey != "" {
			entries = append(entries, model.WGPeerEntry{
				PublicKey: p.PreviousPublicKey, PresharedKey: p.Preshared,
				AllowedIPs: []string{p.Address},
			})
		}
	}
	switch {
	case n.Protocol == model.ProtoWireGuard && n.WireGuard != nil:
		n.WireGuard.Peers = entries
	case n.Protocol == model.ProtoAmneziaWG && n.AmneziaWG != nil:
		n.AmneziaWG.Peers = entries
	}
}

// wgClientOptions returns the per-user overrides for a client config: that
// user's own key and tunnel address, rather than the inbound's shared pair.
func (s *Server) wgClientOptions(n *model.Node, inboundID, userID uint) (*wgpeer.Peer, bool) {
	if n.Protocol != model.ProtoWireGuard && n.Protocol != model.ProtoAmneziaWG {
		return nil, false
	}
	cidr := wgServerCIDR(n)
	if cidr == "" {
		return nil, false
	}
	mgr, err := s.peerManager()
	if err != nil {
		return nil, false
	}
	p, err := mgr.EnsurePeer(inboundID, userID, cidr)
	if err != nil {
		return nil, false
	}
	return p, true
}

// stampWGIdentity puts a user's own peer material onto their copy of a
// WireGuard node, so the .conf they download is theirs and not the inbound's.
func (s *Server) stampWGIdentity(n *model.Node, inboundID, userID uint) {
	p, ok := s.wgClientOptions(n, inboundID, userID)
	if !ok {
		return
	}
	var w *model.WireGuardOptions
	switch {
	case n.Protocol == model.ProtoWireGuard && n.WireGuard != nil:
		w = n.WireGuard
	case n.Protocol == model.ProtoAmneziaWG && n.AmneziaWG != nil:
		w = &n.AmneziaWG.WireGuardOptions
	default:
		return
	}
	w.PeerPrivateKey = p.PrivateKey
	w.PeerPublicKey = p.PublicKey
	w.PeerAddress = []string{p.Address}
	w.PreSharedKey = p.Preshared
	// The server's own peer list has no business in a client config: it names
	// every other user's public key and tunnel address on this inbound.
	w.Peers = nil
}
