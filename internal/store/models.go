// Package store is the GORM-backed persistence layer (spec §4). It defines the
// canonical DB models, opens a pure-Go SQLite database by default (MySQL/Postgres
// drivers slot in the same way), auto-migrates, and exposes typed repositories.
// User semantics are a superset of common panels: data limits with reset
// strategies, absolute or on-first-use expiry, and group→inbound bindings whose
// subscription materialises every binding.
package store

import (
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Base carries the columns every table shares.
type Base struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Role is a reseller-RBAC role (spec §4).
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleReseller Role = "reseller"
	RoleViewer   Role = "viewer"
)

// Admin is a panel operator. Passwords are stored as an argon2id PHC string,
// never plaintext.
type Admin struct {
	Base
	Username     string `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash string `gorm:"not null" json:"-"`
	Role         Role   `gorm:"default:owner" json:"role"`
	TOTPSecret   string `json:"-"`
	Disabled     bool   `json:"disabled"`
	// Reseller quotas (enforced at the repository layer, spec §4).
	UserQuota     int   `json:"user_quota"`
	TrafficCredit int64 `json:"traffic_credit"`
}

// UserStatus enumerates the account states (spec §4).
type UserStatus string

const (
	StatusActive   UserStatus = "active"
	StatusDisabled UserStatus = "disabled"
	StatusLimited  UserStatus = "limited"
	StatusExpired  UserStatus = "expired"
	StatusOnHold   UserStatus = "on_hold"
)

// ResetStrategy is the data-limit reset cadence (spec §4).
type ResetStrategy string

const (
	ResetNo       ResetStrategy = "no_reset"
	ResetDay      ResetStrategy = "day"
	ResetWeek     ResetStrategy = "week"
	ResetMonth    ResetStrategy = "month"
	ResetYear     ResetStrategy = "year"
	ResetOnExpire ResetStrategy = "on_expire"
)

// Group binds a set of inbounds; a user granted the group gets a subscription
// materialising every bound inbound (spec §4).
type Group struct {
	Base
	Name       string   `gorm:"uniqueIndex;not null" json:"name"`
	InboundIDs IntSlice `gorm:"type:text" json:"inbound_ids"`
}

// User is a proxy account.
type User struct {
	Base
	Username     string     `gorm:"uniqueIndex;not null" json:"username"`
	Status       UserStatus `gorm:"default:active" json:"status"`
	GroupID      uint       `json:"group_id"`
	OwnerAdminID uint       `gorm:"index" json:"owner_admin_id"` // reseller multi-tenancy

	// Shared identity used to materialise per-protocol credentials.
	UUID     string `json:"uuid"`
	Password string `json:"-"`
	SubToken string `gorm:"uniqueIndex" json:"sub_token"`

	// Limits (spec §4).
	DataLimit     int64         `json:"data_limit"` // bytes; 0 = unlimited
	UsedTraffic   int64         `json:"used_traffic"`
	ResetStrategy ResetStrategy `gorm:"default:no_reset" json:"reset_strategy"`

	// Expiry: absolute time, OR an on-first-use duration in seconds that starts
	// counting on first connection.
	ExpireAt       *time.Time `json:"expire_at"`
	OnHoldDuration int64      `json:"on_hold_duration"` // seconds; used when Status=on_hold
	FirstConnectAt *time.Time `json:"first_connect_at"`

	IPLimit    int        `json:"ip_limit"`
	TelegramID int64      `json:"telegram_id"`
	Note       string     `json:"note"`
	SubRevoked *time.Time `json:"sub_revoked_at"`
}

// Inbound is a canonical model.Node persisted plus panel bookkeeping. The
// canonical node is stored as JSON in NodeJSON and rehydrated on read.
type Inbound struct {
	Base
	Remark   string `gorm:"index" json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Enabled  bool   `gorm:"default:true" json:"enabled"`
	NodeJSON string `gorm:"type:text" json:"-"` // marshalled model.Node
}

// Node rehydrates the canonical model.Node from the stored JSON.
func (i *Inbound) Node() (*model.Node, error) { return unmarshalNode(i.NodeJSON) }

// SetNode stores a canonical node (and mirrors the indexed columns).
func (i *Inbound) SetNode(n *model.Node) error {
	raw, err := marshalNode(n)
	if err != nil {
		return err
	}
	i.NodeJSON = raw
	i.Remark = n.Remark
	i.Protocol = string(n.Protocol)
	i.Port = n.Port
	return nil
}

// Setting is a key/value config row (spec §4).
type Setting struct {
	Key   string `gorm:"primaryKey" json:"key"`
	Value string `json:"value"`
}

// AuditLog records every mutating action (spec §12).
type AuditLog struct {
	Base
	AdminID uint   `gorm:"index" json:"admin_id"`
	Actor   string `json:"actor"`
	IP      string `json:"ip"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Diff    string `gorm:"type:text" json:"diff"`
}

// AllModels is the migration set.
func AllModels() []any {
	return []any{&Admin{}, &Group{}, &User{}, &Inbound{}, &Setting{}, &AuditLog{}, &Node{}, &ForgeDNSZone{}}
}

// Node is a remote ForgePanel node agent (spec §10). The panel is the source of
// truth; the node reports health and receives engine configs. EnrollToken is a
// one-time secret printed in the `curl | bash` enrollment command.
type Node struct {
	Base
	Name        string     `gorm:"uniqueIndex;not null" json:"name"`
	Address     string     `json:"address"`
	EnrollToken string     `gorm:"uniqueIndex" json:"-"`
	Enrolled    bool       `json:"enrolled"`
	LastSeen    *time.Time `json:"last_seen"`
	CoreVersion string     `json:"core_version"`
	CPU         float64    `json:"cpu"`
	MemMB       int        `json:"mem_mb"`
	Healthy     bool       `json:"healthy"`
}

// ForgeDNSZone is a panel-managed DNS-tunnel zone (spec §5). The operator creates
// it in the UI, picks an adapter, and activates it — the panel starts the
// authoritative listener; no terminal needed.
//
// Adapter selects the implementation: `forge`/`native` keep the panel's own
// codec (internal/forgedns/*), while `stormdns`, `masterdns` and `cottendns`
// drive the real upstream binaries as supervised external processes
// (docs/FORGEDNS_UPSTREAM_SETUP.md §4). The fields below the divider only apply
// to those three; GORM AutoMigrate adds them as nullable columns, so an existing
// database picks them up with zero values and Normalize supplies the defaults.
type ForgeDNSZone struct {
	Base
	Zone    string `gorm:"uniqueIndex;not null" json:"zone"`
	Adapter string `gorm:"default:cottendns" json:"adapter"`
	Enabled bool   `gorm:"default:true" json:"enabled"`
	NSHost  string `json:"ns_host"`
	Key     string `json:"key"`

	// --- upstream (real-binary) settings, §4b ------------------------------

	// Domains carries the ADDITIONAL tunnel domains this zone answers, comma
	// separated. Zone stays the primary for back-compat and display; the
	// rendered DOMAIN array is Zone followed by these. CottenDNS is the reason
	// this exists: one instance can be authoritative for many tunnel zones at
	// once, provided every one of them is delegated to it (§3).
	Domains string `json:"domains"`

	BindHost string `json:"bind_host"` // UDP_HOST, default 0.0.0.0
	BindPort int    `json:"bind_port"` // UDP_PORT, default 53
	Mode     string `json:"mode"`      // socks5 | tcp -> PROTOCOL_TYPE
	Cipher   int    `json:"cipher"`    // DATA_ENCRYPTION_METHOD 0..5

	ForwardIP      string `json:"forward_ip"`
	ForwardPort    int    `json:"forward_port"`
	ExternalSocks5 bool   `json:"external_socks5"`

	// CottenDNS-only toggles (§3); ignored by the leaner adapters.
	TCPListener     bool   `json:"tcp_listener"`
	DoTListener     bool   `json:"dot_listener"` // :853
	DoHListener     bool   `json:"doh_listener"` // :443
	AutoDetect      bool   `json:"encryption_auto_detect"`
	ARecordDelivery bool   `json:"a_record_delivery"`
	QueryTypes      string `json:"query_types"` // client-side rotation, comma separated

	// EncryptKey is the shared secret the panel generates once per zone and
	// reuses for the client bundle. It is a server-side secret: it is written to
	// encrypt_key.txt beside the config and returned only by the authenticated
	// bundle endpoint, never in a listing or an exported link.
	EncryptKey string `json:"-"`

	// PinnedTag is the upstream release this zone runs. The panel writes it back
	// after the first successful install so a restart can never silently pull a
	// newer build — upgrading means clearing or changing this field (§4a).
	PinnedTag string `json:"pinned_tag"`
}
