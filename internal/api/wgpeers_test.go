package api

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func awgInbound(t *testing.T, s *Server, remark string) *store.Inbound {
	t.Helper()
	in, err := s.db.CreateInbound(&model.Node{
		Protocol: model.ProtoAmneziaWG, Address: "203.0.113.20", Port: 51820, Remark: remark,
		AmneziaWG: &model.AmneziaWGOptions{
			WireGuardOptions: model.WireGuardOptions{
				PrivateKey:    "cGVlcnByaXZhdGVrZXlmb3J0ZXN0aW5nMTIzNDU2Nzg5MA==",
				PublicKey:     "cHVibGlja2V5Zm9ydGVzdGluZzEyMzQ1Njc4OTAxMjM0NTY=",
				ServerAddress: []string{"10.66.66.1/24"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func makeUser(t *testing.T, s *Server, name, token string) *store.User {
	t.Helper()
	u := &store.User{Username: name, SubToken: token, Status: store.StatusActive,
		UUID: "11111111-2222-3333-4444-55555555555" + string(name[len(name)-1])}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestEveryUserOnAWireGuardInboundGetsTheirOwnKeyAndAddress(t *testing.T) {
	// The defect: a WireGuard inbound carried exactly ONE client keypair, so
	// assigning several users to it could not be expressed. Handing them all the
	// same key does not share the tunnel — WireGuard keys a session by public
	// key, so the second client to connect takes it from the first, repeatedly.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-1")

	var users []store.User
	for _, name := range []string{"alice1", "bob2", "carol3"} {
		u := makeUser(t, s, name, "tok-"+name)
		if err := s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil); err != nil {
			t.Fatal(err)
		}
		users = append(users, *u)
	}

	n, err := in.Node()
	if err != nil {
		t.Fatal(err)
	}
	s.applyWGPeers(n, in.ID, users)

	peers := n.AmneziaWG.Peers
	if len(peers) != 3 {
		t.Fatalf("got %d peer(s), want one per user", len(peers))
	}
	keys, addrs := map[string]bool{}, map[string]bool{}
	for _, p := range peers {
		if p.PublicKey == "" {
			t.Fatal("a peer has no public key")
		}
		if keys[p.PublicKey] {
			t.Fatalf("two users share the public key %s — they take the tunnel from each other", p.PublicKey)
		}
		keys[p.PublicKey] = true
		if len(p.AllowedIPs) != 1 {
			t.Fatalf("AllowedIPs = %v, want exactly one host", p.AllowedIPs)
		}
		if addrs[p.AllowedIPs[0]] {
			t.Fatalf("two users share the tunnel address %s", p.AllowedIPs[0])
		}
		addrs[p.AllowedIPs[0]] = true
		if !strings.HasSuffix(p.AllowedIPs[0], "/32") {
			t.Fatalf("AllowedIPs = %q; wider than one host lets a peer receive its neighbours' traffic", p.AllowedIPs[0])
		}
	}
}

func TestThePeerListIsStableAcrossReloads(t *testing.T) {
	// Config building runs on every reload. Minting a fresh keypair each time
	// would rewrite the server config continuously and disconnect every client
	// that had just fetched one.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-2")
	u := makeUser(t, s, "dave4", "tok-dave")
	_ = s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil)

	first, _ := in.Node()
	s.applyWGPeers(first, in.ID, []store.User{*u})
	second, _ := in.Node()
	s.applyWGPeers(second, in.ID, []store.User{*u})

	if len(first.AmneziaWG.Peers) != 1 || len(second.AmneziaWG.Peers) != 1 {
		t.Fatal("expected one peer each time")
	}
	if first.AmneziaWG.Peers[0].PublicKey != second.AmneziaWG.Peers[0].PublicKey {
		t.Fatal("a reload minted a new keypair, which disconnects the client that just connected")
	}
	if first.AmneziaWG.Peers[0].AllowedIPs[0] != second.AmneziaWG.Peers[0].AllowedIPs[0] {
		t.Fatal("a reload moved the peer's tunnel address")
	}
}

func TestAnInboundWithNoAssignedUsersRendersAsBefore(t *testing.T) {
	// This must not change what a single-user inbound serves.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-3")
	n, _ := in.Node()
	s.applyWGPeers(n, in.ID, nil)
	if len(n.AmneziaWG.Peers) != 0 {
		t.Fatal("an inbound with no assigned users grew a peer list")
	}
}

func TestTheServerConfigRendersOnePeerBlockPerUser(t *testing.T) {
	// End to end into the actual awg-quick config the kernel reads.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-4")
	var users []store.User
	for _, name := range []string{"eve5", "frank6"} {
		u := makeUser(t, s, name, "tok-"+name)
		_ = s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil)
		users = append(users, *u)
	}
	n, _ := in.Node()
	s.applyWGPeers(n, in.ID, users)

	conf, err := export.AmneziaWGServerConf(n, []*model.Node{n})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(conf, "[Peer]"); got != 2 {
		t.Fatalf("the server config has %d [Peer] block(s), want 2:\n%s", got, conf)
	}
	for _, p := range n.AmneziaWG.Peers {
		if !strings.Contains(conf, p.PublicKey) {
			t.Fatalf("the config is missing a peer's public key:\n%s", conf)
		}
	}
}

func TestAUsersConfigCarriesTheirOwnKeyNotTheInbounds(t *testing.T) {
	// Otherwise every user downloads the same .conf.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-5")
	u1 := makeUser(t, s, "gina7", "tok-gina")
	u2 := makeUser(t, s, "hank8", "tok-hank")
	_ = s.db.SetUserInbounds(u1.ID, []uint{in.ID}, nil)
	_ = s.db.SetUserInbounds(u2.ID, []uint{in.ID}, nil)

	// Populate the SERVER peer list first, then stamp. Without this the list is
	// empty to begin with and the "must not leak" assertion below holds for the
	// wrong reason — an earlier version of this test did exactly that and stayed
	// green when the clearing was removed.
	n1, _ := in.Node()
	s.applyWGPeers(n1, in.ID, []store.User{*u1, *u2})
	if len(n1.AmneziaWG.Peers) < 2 {
		t.Fatalf("precondition: the server peer list has %d entries", len(n1.AmneziaWG.Peers))
	}
	s.stampWGIdentity(n1, in.ID, u1.ID)
	n2, _ := in.Node()
	s.applyWGPeers(n2, in.ID, []store.User{*u1, *u2})
	s.stampWGIdentity(n2, in.ID, u2.ID)

	w1 := &n1.AmneziaWG.WireGuardOptions
	w2 := &n2.AmneziaWG.WireGuardOptions
	if w1.PeerPrivateKey == "" || w2.PeerPrivateKey == "" {
		t.Fatal("a user's config has no private key")
	}
	if w1.PeerPrivateKey == w2.PeerPrivateKey {
		t.Fatal("two users were handed the same private key")
	}
	if len(w1.PeerAddress) == 0 || len(w2.PeerAddress) == 0 || w1.PeerAddress[0] == w2.PeerAddress[0] {
		t.Fatalf("two users share the tunnel address (%v / %v)", w1.PeerAddress, w2.PeerAddress)
	}
	// A client config must NOT list the other users on the inbound.
	if len(w1.Peers) != 0 {
		t.Fatal("a user's config carries the server's peer list, naming every other user's key and address")
	}
}

func TestAPrivateKeyIsNotStoredInTheClear(t *testing.T) {
	// A WireGuard private key is a standing credential with no expiry: whoever
	// holds it is that peer until an operator removes it. A readable database
	// must not be a readable tunnel for every user on it.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-6")
	u := makeUser(t, s, "iris9", "tok-iris")
	_ = s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil)

	n, _ := in.Node()
	s.stampWGIdentity(n, in.ID, u.ID)
	plain := n.AmneziaWG.PeerPrivateKey
	if plain == "" {
		t.Fatal("no private key was issued")
	}
	row, err := s.db.PeerFor(in.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row.PrivateKeyEnc), plain) {
		t.Fatal("the private key is stored in the clear")
	}
	if len(row.PrivateKeyEnc) == 0 {
		t.Fatal("no sealed private key was stored")
	}
}

func TestRotationKeepsTheOldKeyWorkingForItsGrace(t *testing.T) {
	// A rotation that cuts every client off the moment it runs is a rotation
	// nobody performs — which is how a key that should have been rotated never
	// is.
	s := storeServer(t)
	in := awgInbound(t, s, "wg-7")
	u := makeUser(t, s, "jack0", "tok-jack")
	_ = s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil)

	mgr, err := s.peerManager()
	if err != nil {
		t.Fatal(err)
	}
	before, err := mgr.EnsurePeer(in.ID, u.ID, "10.66.66.1/24")
	if err != nil {
		t.Fatal(err)
	}
	after, err := mgr.Rotate(in.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.PublicKey == before.PublicKey {
		t.Fatal("rotation did not change the key")
	}
	if after.Address != before.Address {
		t.Fatal("rotation moved the tunnel address, breaking every rule that names the peer")
	}

	n, _ := in.Node()
	s.applyWGPeers(n, in.ID, []store.User{*u})
	var keys []string
	for _, p := range n.AmneziaWG.Peers {
		keys = append(keys, p.PublicKey)
	}
	if len(keys) != 2 {
		t.Fatalf("the server config has %d peer entries (%v), want the new key AND the old one during its grace", len(keys), keys)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k] = true
	}
	if !seen[before.PublicKey] || !seen[after.PublicKey] {
		t.Fatalf("keys = %v, want both %s and %s", keys, before.PublicKey, after.PublicKey)
	}
}
