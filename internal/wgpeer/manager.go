package wgpeer

// The peer lifecycle: mint, hand out, rotate, release.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// RotationGrace is how long a rotated-away public key stays registered.
//
// A rotation that cuts every client off the moment it runs is a rotation nobody
// performs — which is how a key that should have been rotated never is. The old
// key keeps working just long enough for clients to fetch the new config.
const RotationGrace = 24 * time.Hour

// Sealer encrypts peer private keys at rest. The panel's DNS credential
// encryptor satisfies it.
type Sealer interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// Repo is the persistence this manager needs.
type Repo interface {
	PeersForInbound(inboundID uint) ([]store.WGPeer, error)
	ActivePeersForInbound(inboundID uint) ([]store.WGPeer, error)
	PeerFor(inboundID, userID uint) (*store.WGPeer, error)
	CreatePeer(p *store.WGPeer) error
	SavePeer(p *store.WGPeer) error
	ReleasePeer(id uint, now time.Time) error
}

// Manager mints and retires peers.
type Manager struct {
	repo   Repo
	sealer Sealer
	now    func() time.Time
}

// New builds a manager.
func New(repo Repo, sealer Sealer) *Manager {
	return &Manager{repo: repo, sealer: sealer, now: time.Now}
}

// SetClock is for tests.
func (m *Manager) SetClock(f func() time.Time) { m.now = f }

// Peer describes one client's presence, decrypted and ready to render.
type Peer struct {
	UserID     uint
	PublicKey  string
	PrivateKey string
	Preshared  string
	// Address is the peer's tunnel address in host-CIDR form ("10.66.66.4/32").
	Address string
	// PreviousPublicKey is a rotated-away key still inside its grace window.
	PreviousPublicKey string
	DeviceLimit       int
}

// EnsurePeer returns the user's peer on this inbound, minting one on first use.
//
// Idempotent: called on every subscription fetch, and a second call must return
// the SAME key and address. Minting a fresh keypair per fetch would rewrite the
// server config on every client refresh and disconnect the client that asked.
func (m *Manager) EnsurePeer(inboundID, userID uint, serverCIDR string) (*Peer, error) {
	if existing, err := m.repo.PeerFor(inboundID, userID); err == nil && existing != nil {
		if existing.ReleasedAt == nil {
			return m.decode(existing)
		}
		// The peer was released and the user is back. Revive the row rather than
		// minting a second one for the same (inbound, user) — the unique index
		// forbids a duplicate, and reviving keeps their address if it has not
		// been reissued in the meantime.
		existing.ReleasedAt = nil
		existing.Enabled = true
		if err := m.repo.SavePeer(existing); err != nil {
			return nil, err
		}
		return m.decode(existing)
	}

	pool, err := NewPool(serverCIDR)
	if err != nil {
		return nil, err
	}
	rows, err := m.repo.PeersForInbound(inboundID)
	if err != nil {
		return nil, err
	}
	addr, err := pool.Allocate(reservations(rows), m.now())
	if err != nil {
		return nil, err
	}

	keys, err := keygen.WireGuardKeys()
	if err != nil {
		return nil, fmt.Errorf("wgpeer: generate keypair: %w", err)
	}
	psk, err := presharedKey()
	if err != nil {
		return nil, err
	}
	privEnc, err := m.sealer.Encrypt([]byte(keys.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("wgpeer: seal the private key: %w", err)
	}
	pskEnc, err := m.sealer.Encrypt([]byte(psk))
	if err != nil {
		return nil, fmt.Errorf("wgpeer: seal the pre-shared key: %w", err)
	}

	row := &store.WGPeer{
		InboundID: inboundID, UserID: userID,
		PublicKey: keys.PublicKey, PrivateKeyEnc: privEnc, PresharedKeyEnc: pskEnc,
		Address: addr.String(), Enabled: true,
	}
	if err := m.repo.CreatePeer(row); err != nil {
		return nil, err
	}
	return m.decode(row)
}

// Rotate issues a new keypair for a peer, keeping the old public key registered
// for the grace window.
func (m *Manager) Rotate(inboundID, userID uint) (*Peer, error) {
	row, err := m.repo.PeerFor(inboundID, userID)
	if err != nil {
		return nil, err
	}
	keys, err := keygen.WireGuardKeys()
	if err != nil {
		return nil, err
	}
	privEnc, err := m.sealer.Encrypt([]byte(keys.PrivateKey))
	if err != nil {
		return nil, err
	}
	until := m.now().Add(RotationGrace)
	row.PreviousPublicKey = row.PublicKey
	row.PreviousUntil = &until
	row.PublicKey = keys.PublicKey
	row.PrivateKeyEnc = privEnc
	// The ADDRESS is deliberately unchanged. Rotating the key answers "this
	// credential may have leaked"; moving the address as well would break every
	// routing rule and firewall entry that names the peer, for no gain — the old
	// key stops working either way.
	if err := m.repo.SavePeer(row); err != nil {
		return nil, err
	}
	return m.decode(row)
}

// Release retires a peer, starting its address cooldown.
func (m *Manager) Release(inboundID, userID uint) error {
	row, err := m.repo.PeerFor(inboundID, userID)
	if err != nil {
		return err
	}
	return m.repo.ReleasePeer(row.ID, m.now())
}

// ServerPeers returns the [Peer] entries an inbound's server config should hold.
//
// A rotated-away key inside its grace window is included as its own entry, so a
// client that has not fetched its new config keeps working. Both entries carry
// the same AllowedIPs, which is correct: they are the same client, and only one
// of the two keys will ever complete a handshake.
func (m *Manager) ServerPeers(inboundID uint) ([]Peer, error) {
	rows, err := m.repo.ActivePeersForInbound(inboundID)
	if err != nil {
		return nil, err
	}
	now := m.now()
	out := make([]Peer, 0, len(rows))
	for i := range rows {
		p, err := m.decode(&rows[i])
		if err != nil {
			// One unreadable row must not blank the whole server config: that
			// would disconnect every OTHER user on the inbound because one
			// record could not be decrypted.
			continue
		}
		if rows[i].PreviousUntil != nil && now.After(*rows[i].PreviousUntil) {
			p.PreviousPublicKey = ""
		}
		out = append(out, *p)
	}
	return out, nil
}

func (m *Manager) decode(row *store.WGPeer) (*Peer, error) {
	p := &Peer{
		UserID: row.UserID, PublicKey: row.PublicKey,
		PreviousPublicKey: row.PreviousPublicKey, DeviceLimit: row.DeviceLimit,
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(row.Address)); err == nil {
		p.Address = HostCIDR(a)
	} else {
		return nil, fmt.Errorf("wgpeer: peer %d has an unusable address %q", row.ID, row.Address)
	}
	if len(row.PrivateKeyEnc) > 0 {
		raw, err := m.sealer.Decrypt(row.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("wgpeer: peer %d private key could not be decrypted: %w", row.ID, err)
		}
		p.PrivateKey = string(raw)
	}
	if len(row.PresharedKeyEnc) > 0 {
		if raw, err := m.sealer.Decrypt(row.PresharedKeyEnc); err == nil {
			p.Preshared = string(raw)
		}
	}
	if p.PublicKey == "" {
		return nil, errors.New("wgpeer: peer has no public key")
	}
	return p, nil
}

// reservations turns stored rows into what the allocator needs.
func reservations(rows []store.WGPeer) []Reservation {
	out := make([]Reservation, 0, len(rows))
	for _, r := range rows {
		a, err := netip.ParseAddr(strings.TrimSpace(r.Address))
		if err != nil {
			continue
		}
		res := Reservation{Addr: a}
		if r.ReleasedAt != nil {
			res.ReleasedAt = *r.ReleasedAt
		}
		out = append(out, res)
	}
	return out
}

// presharedKey generates a WireGuard pre-shared key.
//
// Per peer, not per inbound: a PSK shared across every client is a second secret
// that leaks with the first client that leaks anything, and adds nothing over
// the keypair it accompanies.
func presharedKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("wgpeer: generate pre-shared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}
