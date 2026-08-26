package store

// Per-client WireGuard / AmneziaWG peers.
//
// A WireGuard inbound carried exactly ONE client keypair and ONE tunnel
// address, so assigning several users to it could not be expressed. Every user
// handed the same key does not merely share an identity — WireGuard keys a
// session by public key, so the second client to connect takes the tunnel away
// from the first, over and over.

import (
	"time"
)

// WGPeer is one client's presence on one WireGuard-family inbound.
type WGPeer struct {
	Base
	InboundID uint `gorm:"index:idx_wgpeer_inbound_user,unique;not null" json:"inbound_id"`
	UserID    uint `gorm:"index:idx_wgpeer_inbound_user,unique;not null" json:"user_id"`

	// PublicKey is what the server registers as a [Peer]. It is not a secret.
	PublicKey string `gorm:"index" json:"public_key"`
	// PrivateKeyEnc and PresharedKeyEnc are AES-GCM sealed.
	//
	// A WireGuard private key is a standing credential with no expiry and no
	// revocation of its own: whoever holds it is that peer until an operator
	// removes it. Storing it in the clear means a readable database is a
	// readable tunnel for every user on it.
	PrivateKeyEnc   []byte `json:"-"`
	PresharedKeyEnc []byte `json:"-"`

	// Address is the peer's tunnel address, without a prefix ("10.66.66.4").
	Address string `gorm:"index" json:"address"`

	// PreviousPublicKey stays registered until PreviousUntil, so rotating a key
	// does not cut off a client that has not fetched its new config yet. A
	// rotation that disconnects everyone immediately is one nobody performs,
	// which is how a key that should have been rotated never is.
	PreviousPublicKey string     `json:"previous_public_key,omitempty"`
	PreviousUntil     *time.Time `json:"previous_until,omitempty"`

	// DeviceLimit caps simultaneous devices for this peer. 0 means the user's
	// own limit applies.
	DeviceLimit int `json:"device_limit"`

	Enabled bool `gorm:"default:true" json:"enabled"`
	// ReleasedAt marks a peer whose address is in its reuse cooldown. The row is
	// kept rather than deleted precisely so the cooldown can be observed — a
	// deleted row is an address that looks free.
	ReleasedAt *time.Time `gorm:"index" json:"released_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// PeersForInbound returns every peer row for an inbound, released ones included.
//
// Released peers are part of the answer on purpose: they are what the allocator
// consults to honour the reuse cooldown, and omitting them would hand a
// just-freed address straight to the next client.
func (s *Store) PeersForInbound(inboundID uint) ([]WGPeer, error) {
	var out []WGPeer
	err := s.db.Where("inbound_id = ?", inboundID).Order("address asc, id asc").Find(&out).Error
	return out, err
}

// ActivePeersForInbound returns only the peers that belong in the server config.
func (s *Store) ActivePeersForInbound(inboundID uint) ([]WGPeer, error) {
	var out []WGPeer
	err := s.db.Where("inbound_id = ? AND enabled = ? AND released_at IS NULL", inboundID, true).
		Order("address asc, id asc").Find(&out).Error
	return out, err
}

// PeerFor returns one user's peer on one inbound.
func (s *Store) PeerFor(inboundID, userID uint) (*WGPeer, error) {
	var p WGPeer
	if err := s.db.Where("inbound_id = ? AND user_id = ?", inboundID, userID).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// CreatePeer persists a peer.
func (s *Store) CreatePeer(p *WGPeer) error {
	// GORM omits zero values on INSERT when a column declares a default, so a
	// peer created disabled would be stored ENABLED — and an enabled peer is a
	// [Peer] block in the server config, which is a tunnel someone can use.
	wantEnabled := p.Enabled
	if err := s.db.Create(p).Error; err != nil {
		return err
	}
	if !wantEnabled {
		return s.db.Model(p).UpdateColumn("enabled", false).Error
	}
	return nil
}

// SavePeer updates a peer.
func (s *Store) SavePeer(p *WGPeer) error {
	return s.db.Model(p).Select("*").Omit("created_at").Updates(p).Error
}

// ReleasePeer marks a peer's address as free-after-cooldown without deleting the
// row, so the cooldown can actually be observed.
func (s *Store) ReleasePeer(id uint, now time.Time) error {
	return s.db.Model(&WGPeer{}).Where("id = ?", id).
		Updates(map[string]any{"released_at": now, "enabled": false}).Error
}

// DeletePeersForInbound removes every peer of an inbound.
func (s *Store) DeletePeersForInbound(inboundID uint) error {
	return s.db.Where("inbound_id = ?", inboundID).Delete(&WGPeer{}).Error
}

// PurgeReleasedPeers deletes released rows whose cooldown has fully elapsed.
//
// Only after the cooldown: deleting earlier is exactly the reuse race the
// cooldown exists to prevent, because a missing row reads as a free address.
func (s *Store) PurgeReleasedPeers(before time.Time) (int64, error) {
	res := s.db.Where("released_at IS NOT NULL AND released_at < ?", before).Delete(&WGPeer{})
	return res.RowsAffected, res.Error
}
