package store

// Reverse-tunnel bridges: the hop that lets a client inside Iran reach a server
// outside it.

import "time"

// Bridge is one reverse tunnel. The panel manages the EXIT half; the bridge
// half runs on a machine the panel usually cannot reach.
type Bridge struct {
	Base
	Name    string `gorm:"uniqueIndex;not null" json:"name"`
	Backend string `gorm:"not null" json:"backend"` // backhaul | rathole | frp | wstunnel

	// ExitAddr is this server's public address as the BRIDGE will dial it.
	// Stored rather than derived: the address a bridge in Iran can reach is
	// often not the one the panel sees itself on.
	ExitAddr   string `json:"exit_addr"`
	TunnelPort int    `json:"tunnel_port"`
	// Transport is backend-specific ("tcp", "ws", "wss"); empty takes the
	// backend default.
	Transport string `json:"transport"`

	// TokenEnc is the shared secret, sealed at rest. It is the whole of the
	// tunnel's authentication: anyone holding it can attach to the exit.
	TokenEnc []byte `json:"-"`

	// Services is the forwarded port list as JSON.
	Services datatypesJSON `gorm:"type:text" json:"services"`

	Enabled bool `gorm:"default:true" json:"enabled"`

	LastState string     `json:"last_state,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// ListBridges returns every bridge, oldest first.
func (s *Store) ListBridges() ([]Bridge, error) {
	var out []Bridge
	err := s.db.Order("id asc").Find(&out).Error
	return out, err
}

// BridgeByID loads one bridge.
func (s *Store) BridgeByID(id uint) (*Bridge, error) {
	var b Bridge
	if err := s.db.First(&b, id).Error; err != nil {
		return nil, err
	}
	return &b, nil
}

// BridgeByName loads one bridge by its name.
func (s *Store) BridgeByName(name string) (*Bridge, error) {
	var b Bridge
	if err := s.db.Where("name = ?", name).First(&b).Error; err != nil {
		return nil, err
	}
	return &b, nil
}

// CreateBridge persists a bridge.
func (s *Store) CreateBridge(b *Bridge) error {
	// GORM omits zero values on INSERT when a column declares a default, so a
	// bridge created disabled would be stored ENABLED — and an enabled bridge is
	// a listening tunnel port on the exit.
	wantEnabled := b.Enabled
	if err := s.db.Create(b).Error; err != nil {
		return err
	}
	if !wantEnabled {
		return s.db.Model(b).UpdateColumn("enabled", false).Error
	}
	return nil
}

// SaveBridge updates a bridge.
func (s *Store) SaveBridge(b *Bridge) error {
	return s.db.Model(b).Select("*").Omit("created_at").Updates(b).Error
}

// DeleteBridge removes a bridge.
func (s *Store) DeleteBridge(id uint) error {
	return s.db.Delete(&Bridge{}, id).Error
}
