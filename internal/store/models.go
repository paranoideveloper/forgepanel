// Package store is the GORM-backed persistence layer (spec §4). It defines the
// canonical DB models, opens a pure-Go SQLite database by default (MySQL/Postgres
// drivers slot in the same way), auto-migrates, and exposes typed repositories.
// User semantics are a superset of common panels: data limits with reset
// strategies, absolute or on-first-use expiry, and group→inbound bindings whose
// subscription materialises every binding.
package store

import (
	"strings"
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
	// RecoveryCodes is a JSON array of SHA-256 hashes of the UNUSED 2FA recovery
	// codes. Never plaintext. Empty when 2FA is off or codes were never generated
	// (existing 2FA admins migrate here with an empty set and can regenerate).
	RecoveryCodes string `json:"-"`
	// SessionEpoch is stamped into every issued token. Bumping it invalidates all
	// tokens the account already holds, which is what makes "sign out everywhere"
	// possible with stateless JWTs. It is bumped whenever the account's
	// authentication state changes under recovery conditions — a recovery code is
	// used, 2FA is disabled, or the password is changed — so an attacker who
	// already had a session does not keep it after the legitimate owner recovers.
	SessionEpoch uint `json:"-"`
	// LastTOTPStep is the most recent RFC 6238 time step accepted for this admin.
	// A code stays valid across the skew window, so without this an intercepted
	// code could be replayed for up to 90 seconds.
	LastTOTPStep int64 `json:"-"`
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
	// Description is free text shown in the group list.
	Description string `json:"description"`
	// IsDefault marks the group offered as the pre-selection when creating a
	// user. It is a visible suggestion, never a silent assignment: user creation
	// always records exactly the group the administrator chose, including none.
	// At most one group holds this flag.
	IsDefault bool `gorm:"index" json:"is_default"`
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
	// LifetimeTraffic accumulates all bytes ever used, preserved across periodic
	// resets. LastResetAt records the start of the period whose usage is currently
	// counted, making scheduled resets idempotent and recoverable after downtime.
	LifetimeTraffic int64      `json:"lifetime_traffic"`
	LastResetAt     *time.Time `json:"last_reset_at"`

	// Expiry: absolute time, OR an on-first-use duration in seconds that starts
	// counting on first connection.
	ExpireAt       *time.Time `json:"expire_at"`
	OnHoldDuration int64      `json:"on_hold_duration"` // seconds; used when Status=on_hold
	FirstConnectAt *time.Time `json:"first_connect_at"`
	// LastSeenAt is the last time the user actually transferred bytes, stamped by
	// the traffic-poll cycle. It is the basis for the "online" indicator (seen
	// within a recent window) — a universal, core-agnostic signal that works for
	// xray and sing-box alike, unlike a core-specific connection API.
	LastSeenAt *time.Time `json:"last_seen_at"`

	// IPLimit is the maximum number of distinct source addresses this user may
	// connect from at once. Zero is unlimited.
	//
	// It was stored and editable from the day it was added and NOTHING read it:
	// an operator set a limit, the panel accepted it, and it did nothing. That
	// is worse than not offering the field, because the operator believes the
	// account is capped.
	// UploadTraffic and DownloadTraffic are the ATTRIBUTED halves of UsedTraffic.
	//
	// Their sum can be LESS than UsedTraffic, and that is not a bug: a remote
	// node reports one combined counter per user with no split available, so its
	// bytes are billed (UsedTraffic is authoritative) while remaining
	// unattributed here. Deriving one half by subtraction instead would silently
	// present unknown traffic as though it had been measured.
	UploadTraffic   int64 `json:"upload_traffic"`
	DownloadTraffic int64 `json:"download_traffic"`

	IPLimit int `json:"ip_limit"`
	// IPLimitedUntil is set when a user is over their IP limit, and excludes
	// them from every generated core config until it passes.
	//
	// It is deliberately NOT a Status value. Status carries why an account is
	// unusable in a way an operator acts on — expired, over quota, disabled by
	// hand — and each has its own recovery. Folding a transient, self-clearing
	// IP cooldown into it would overwrite the real reason and leave the account
	// wrong once the cooldown lifted.
	IPLimitedUntil *time.Time `json:"ip_limited_until"`
	TelegramID     int64      `json:"telegram_id"`
	Note           string     `json:"note"`
	SubRevoked     *time.Time `json:"sub_revoked_at"`

	// SubUpdatedAt / SubLastUA are the denormalised newest row of sub_requests,
	// so the users LIST can show last-fetch for 500 users without 500 queries.
	// Written by RecordSubRequest in the same transaction as the row itself.
	//
	// The explicit column name is not decoration: GORM's naming of SubLastUA is a
	// guess the migration and the adoption test would otherwise have to match.
	SubUpdatedAt *time.Time `json:"sub_updated_at"`
	SubLastUA    string     `gorm:"column:sub_last_ua;size:512" json:"sub_last_user_agent"`
}

// Inbound is a canonical model.Node persisted plus panel bookkeeping. The
// canonical node is stored as JSON in NodeJSON and rehydrated on read.
type Inbound struct {
	Base
	NodeID   uint   `gorm:"index" json:"node_id"`
	Remark   string `gorm:"index" json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Enabled  bool   `gorm:"default:true" json:"enabled"`
	NodeJSON string `gorm:"type:text" json:"-"` // marshalled model.Node
	// PrevNodeJSON holds the config as it was BEFORE the last edit, so a single
	// level of undo can restore it. Empty means there is nothing to undo.
	PrevNodeJSON string `gorm:"type:text" json:"-"`

	// ImportSource identifies where this row came from, as "<panel>:<row id>".
	//
	// It is what makes a re-import idempotent under renaming: matching on the
	// remark means an inbound renamed on either side is imported again as a
	// duplicate, and the operator ends up with two of everything they touched.
	ImportSource string `gorm:"index;size:128" json:"import_source,omitempty"`

	// NotServingReason is why this inbound is not in the running configuration,
	// or empty when it is serving normally.
	//
	// An inbound no core can serve is left OUT of the generated config so that
	// one bad inbound cannot take the whole panel down — which is right, and was
	// already the behaviour. What was missing is that nothing told anyone. The
	// operator created an inbound, the panel accepted it, it never carried a
	// byte, and the only trace was a field in a bundle the reload path threw
	// away.
	NotServingReason string     `gorm:"type:text" json:"not_serving_reason,omitempty"`
	NotServingSince  *time.Time `json:"not_serving_since,omitempty"`
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

// Domain is an operator-owned domain in the Domains registry. Inbounds reference
// it by name; new inbounds inherit the one flagged IsDefault. Provider links it
// to the §5 DNS-automation credentials so a domain can be provisioned end to end.
type Domain struct {
	Base
	Name      string `gorm:"uniqueIndex;not null" json:"name"`
	IsDefault bool   `gorm:"index" json:"is_default"`
	Provider  string `json:"provider,omitempty"` // cloudflare | arvan | desec | ...
	TLSMode   string `json:"tls_mode,omitempty"` // acme | manual | none
	CertPath  string `json:"cert_path,omitempty"`
	KeyPath   string `json:"key_path,omitempty"`
	Note      string `json:"note,omitempty"`
}

// EdgeDeployment is a ForgeEdge Cloudflare Worker (or Pages project) this panel
// feeds (§6, deploy/cloudflare/forgeedge/docs/GO_WIRING.md §2.3). The panel is
// the source of truth for users; the edge holds a copy of the canonical feed so
// one subscription URL can carry both VPS inbounds and edge entries.
//
// Registering a deployment here does not create anything at Cloudflare, and
// deleting the row does not destroy the Worker — the two lifecycles are kept
// separate on purpose, so forgetting an edge in the panel can never take a live
// subscription offline by accident.
type EdgeDeployment struct {
	Base
	Name   string `gorm:"uniqueIndex;not null" json:"name"` // worker / pages project name
	Target string `gorm:"default:workers" json:"target"`    // workers | pages
	Origin string `gorm:"not null" json:"origin"`           // https://name.acct.workers.dev
	// SecurePath is the unguessable path prefix the Worker mints (or is given at
	// deploy time). It is not a secret on its own — the password is — but it is
	// what keeps the panel and every subscription URL off a scanner's radar.
	SecurePath string `json:"secure_path"`
	// PushToken authorises `POST <origin>/<secure_path>/feed`. It is a bearer
	// credential, so it never appears in an API response; the operator reads it
	// from the Worker's own status page.
	PushToken string `json:"-"`
	AccountID string `json:"account_id,omitempty"`
	// SelfManage records that this Worker was deployed with the account's
	// Cloudflare credential bound into it, which is what its own Deployment
	// panel reads. `forgectl edge update` re-sends a CLOSED bindings list, so
	// without this flag the next update silently strips the credential back out.
	//
	// The TOKEN itself is never stored: the panel deliberately holds no
	// long-lived Cloudflare secret, and every deploy and update supplies its own
	// api_token.
	SelfManage bool       `json:"self_manage"`
	LastPushAt *time.Time `json:"last_push_at"`
	LastStatus string     `json:"last_status"`
}

// FeedURL is the endpoint a canonical feed is POSTed to.
func (e *EdgeDeployment) FeedURL() string {
	return strings.TrimSuffix(e.Origin, "/") + "/" + strings.Trim(e.SecurePath, "/") + "/feed"
}

// StatusURL is the Worker's own status endpoint (session-authenticated).
func (e *EdgeDeployment) StatusURL() string {
	return strings.TrimSuffix(e.Origin, "/") + "/" + strings.Trim(e.SecurePath, "/") + "/api/status"
}

// AllModels is the migration set.
func AllModels() []any {
	return []any{&Admin{}, &Group{}, &User{}, &Inbound{}, &Setting{}, &AuditLog{}, &Node{},
		&ForgeDNSZone{}, &UserInbound{}, &Domain{}, &EdgeDeployment{}, &TrafficSnapshot{}, &TrafficRollup{},
		&InboundHost{}, &WGPeer{}, &Bridge{}, &GroupInbound{},
		&Outbound{}, &RoutingRule{}, &OutboundGroup{}, &APIToken{},
		&Profile{}, &ProfileBinding{}, &WebhookEndpoint{}, &SubRequest{}, &UserTemplate{},
		&CorePin{}}
}

// Node is a remote ForgePanel node agent (spec §10). The panel is the source of
// truth; the node reports health and receives engine configs. EnrollToken is a
// one-time secret printed in the `curl | bash` enrollment command.
type Node struct {
	Base
	Name    string `gorm:"uniqueIndex;not null" json:"name"`
	Address string `json:"address"`
	// EnrollToken is the LEGACY credential: a permanent bearer string that was
	// the whole of a node's identity. It is kept so a fleet enrolled before
	// mTLS keeps working, and is refused outright once RequireNodeMTLS is set.
	EnrollToken string `gorm:"uniqueIndex" json:"-"`

	// --- mTLS control plane -------------------------------------------------

	// BootstrapHash is the SHA-256 of the one-time bootstrap token, hex.
	//
	// Hashed, not stored: the token is spent once to obtain a certificate, and
	// a panel database that has been read should not hand over a working
	// credential for every node in it. Cleared the moment it is used.
	BootstrapHash string `gorm:"index" json:"-"`
	// BootstrapExpires bounds how long the bootstrap token is usable. An
	// enrolment command pasted into a chat six months ago should not still work.
	BootstrapExpires *time.Time `json:"-"`
	// CertSerial identifies the node's current client certificate, so it can be
	// revoked by the panel alone.
	CertSerial string `gorm:"index" json:"cert_serial,omitempty"`
	// CertNotAfter is when that certificate stops being accepted.
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`

	Enrolled    bool       `json:"enrolled"`
	LastSeen    *time.Time `json:"last_seen"`
	CoreVersion string     `json:"core_version"`
	// SingboxStats is whether THIS node's sing-box binary can report per-user
	// counters, as reported by the node itself.
	//
	// The panel cannot detect it: the capability belongs to the binary installed
	// on the node. Enabling the config section on a build without it is a
	// STARTUP failure that takes every sing-box inbound on that node down, so
	// the panel only asks for what the node says it can serve.
	SingboxStats bool    `json:"singbox_stats"`
	CPU          float64 `json:"cpu"`
	MemMB        int     `json:"mem_mb"`
	// Disk, connection count and core uptime. Disk is the metric that turns
	// into an outage with no warning — a node whose filesystem fills stops
	// writing configs and simply goes quiet — and core uptime is the only
	// signal that separates a node which is "connected" from one whose core is
	// crash-looping and serving nothing.
	DiskUsedMB    int        `json:"disk_used_mb"`
	DiskTotalMB   int        `json:"disk_total_mb"`
	TCPConns      int        `json:"tcp_conns"`
	CoreUptimeSec int        `json:"core_uptime_sec"`
	Healthy       bool       `json:"healthy"`
	ConfigDirty   bool       `json:"config_dirty"`
	ConfigDirtyAt *time.Time `json:"config_dirty_at"`

	// --- lifecycle ----------------------------------------------------------

	// Status is where this node is in its life, not merely whether it answered.
	// Healthy is one bit and the table needed four states: a node mid-install,
	// a node that has died, a node whose core is refusing its config, and a node
	// the operator switched off all read the same "not healthy" before this, so
	// the Nodes page reported three emergencies where there was one.
	//
	// It is STORED so the last thing the node said survives a panel restart, and
	// DERIVED again on every read (api.nodeStatus): the read path is what stops
	// this becoming another Healthy — a column written only true, at heartbeat,
	// that still says "connected" an hour after the node stopped answering.
	Status NodeStatus `gorm:"default:connecting" json:"status"`
	// StatusMessage is why, in the node's own words where it has any. An error
	// state with no message tells the operator something is wrong and not what.
	StatusMessage string `json:"status_message"`
	// Disabled is the operator deliberately taking a node out of service.
	//
	// Enforced at the control plane, not painted on the list: handleNodeHeartbeat
	// and handleNodeRegister refuse a disabled node, so it stops receiving config
	// bundles and drifts out of service instead of quietly serving yesterday's
	// config while the UI says it is off.
	Disabled bool `json:"disabled"`
}

// NodeStatus enumerates a node's lifecycle states (spec §10).
type NodeStatus string

const (
	// NodeConnecting is enrolled but not yet heard from — an install in
	// progress, which is not a fault and must not be alerted on as one.
	NodeConnecting NodeStatus = "connecting"
	NodeConnected  NodeStatus = "connected"
	// NodeError is reporting a failure, or no longer reporting at all.
	NodeError NodeStatus = "error"
	// NodeDisabled is switched off by the operator. Deliberate, so it is neither
	// an error nor a thing to page anyone about.
	NodeDisabled NodeStatus = "disabled"
)

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

	// OverrideTOML / ClientOverrideTOML hold the operator's advanced-override
	// layer as raw TOML text, stored SEPARATELY from the managed columns above
	// so the two can be merged deterministically and so an upstream key this
	// panel has never heard of survives an import untouched
	// (internal/forgedns/upstream/layers.go).
	//
	// json:"-" because an operator can paste anything in here, including key
	// material: these documents are returned only by the zone-config endpoint,
	// and only with secret values masked. AutoMigrate adds them as nullable
	// text columns, so an existing database picks them up empty.
	OverrideTOML       string `gorm:"type:text" json:"-"`
	ClientOverrideTOML string `gorm:"type:text" json:"-"`
}
