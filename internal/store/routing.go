package store

// Server-side routing: named outbounds, and ordered rules that select between
// them.
//
// The panel could send an inbound's whole traffic through a relay chain and
// nothing else. There was no way to say "block these domains", "send Iranian
// destinations direct and everything else through the tunnel", or "this
// customer group exits through that provider" — the decisions that make a proxy
// panel usable for anything past a single tunnel.
//
// TWO ENTITIES, because they are edited on different rhythms. An outbound is a
// destination an operator configures once and reuses; a rule is policy that
// changes as circumstances do. Folding rules into the inbound (as the existing
// per-inbound egress does) forces every policy change to be repeated on every
// inbound it should apply to.

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Outbound is a named exit the routing rules can select.
type Outbound struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// Tag is the identifier the core uses and rules refer to. Unique, because a
	// duplicate makes "which outbound" ambiguous inside the core, which resolves
	// it silently in whatever order it indexed them.
	Tag string `gorm:"uniqueIndex;size:64" json:"tag"`
	// Protocol is the core's outbound protocol: freedom, blackhole, socks, http,
	// vless, vmess, trojan, shadowsocks, wireguard.
	Protocol string `gorm:"size:32" json:"protocol"`
	// Settings and StreamSettings are the core's own JSON objects, stored
	// verbatim.
	//
	// Verbatim on purpose: modelling every field of every outbound protocol
	// would mean re-implementing the core's schema and then lagging behind it
	// forever, and an operator who needs one field the panel has not modelled
	// yet is stuck. The core validates the result, which is the only opinion
	// that matters.
	Settings       datatypesJSON `gorm:"type:text" json:"settings"`
	StreamSettings datatypesJSON `gorm:"type:text" json:"stream_settings"`
	// SendThrough binds the outbound to a specific local source address, for a
	// host with several egress IPs.
	SendThrough string `gorm:"size:64" json:"send_through"`
	// SortOrder fixes the position in the generated outbounds array. The FIRST
	// outbound is the core's default for anything no rule matched, so this is
	// not cosmetic.
	SortOrder int  `json:"sort_order"`
	Enabled   bool `json:"enabled"`
	// Note is the operator's own reminder of what this exit is for.
	Note      string    `gorm:"size:255" json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (Outbound) TableName() string { return "outbounds" }

// RoutingRule is one ordered matcher-to-outbound decision.
type RoutingRule struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"size:128" json:"name"`
	// SortOrder is the evaluation order, and rules are FIRST-MATCH. A rule list
	// without a defined order is a different config every time it is generated.
	SortOrder int  `gorm:"index" json:"sort_order"`
	Enabled   bool `json:"enabled"`

	// Matchers. All non-empty ones must match (AND); within one matcher any
	// entry matches (OR) — which is the core's own semantics, kept identical so
	// an operator's knowledge of Xray rules transfers.
	Domain  stringList `gorm:"type:text" json:"domain"`
	IP      stringList `gorm:"type:text" json:"ip"`
	Port    string     `gorm:"size:64" json:"port"`
	Network string     `gorm:"size:16" json:"network"` // tcp | udp | tcp,udp
	// Protocol matches the SNIFFED application protocol (http, tls, bittorrent),
	// which requires sniffing to be on for the inbound. A rule that matches
	// nothing because sniffing is off looks broken rather than misconfigured, so
	// the API says so when one is saved.
	Protocol stringList `gorm:"type:text" json:"protocol"`
	// InboundTags scopes a rule to particular inbounds.
	InboundTags stringList `gorm:"type:text" json:"inbound_tags"`
	// UserIDs scopes a rule to particular users. Stored as ids and rendered as
	// the counter emails the core knows them by, so renaming a user cannot
	// silently detach their rules.
	UserIDs uintList `gorm:"type:text" json:"user_ids"`

	// OutboundTag is where matching traffic goes. It may name a stored Outbound
	// or one of the built-in tags.
	OutboundTag string    `gorm:"size:64" json:"outbound_tag"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (RoutingRule) TableName() string { return "routing_rules" }

// Built-in outbound tags that always exist in a generated config.
const (
	OutboundDirect = "direct"
	OutboundBlock  = "block"
)

// datatypesJSON is a raw JSON value stored as text.
//
// It is its own type rather than a string so that a malformed value fails when
// it is written, not when the config is generated — at which point the operator
// is looking at an engine error instead of the field they typed it into.
type datatypesJSON json.RawMessage

func (j datatypesJSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

func (j *datatypesJSON) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*j = nil
	case []byte:
		*j = datatypesJSON(append([]byte(nil), v...))
	case string:
		*j = datatypesJSON(v)
	default:
		return fmt.Errorf("scan json: unsupported type %T", src)
	}
	return nil
}

func (j datatypesJSON) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

func (j *datatypesJSON) UnmarshalJSON(b []byte) error {
	*j = datatypesJSON(append([]byte(nil), b...))
	return nil
}

// stringList is a []string stored as JSON text.
type stringList []string

func (l stringList) Value() (driver.Value, error) { return marshalList(l) }

func (l *stringList) Scan(src any) error {
	b, err := scanBytes(src)
	if err != nil || b == nil {
		*l = nil
		return err
	}
	return json.Unmarshal(b, l)
}

// uintList is a []uint stored as JSON text.
type uintList []uint

func (l uintList) Value() (driver.Value, error) { return marshalList(l) }

func (l *uintList) Scan(src any) error {
	b, err := scanBytes(src)
	if err != nil || b == nil {
		*l = nil
		return err
	}
	return json.Unmarshal(b, l)
}

func marshalList(v any) (driver.Value, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// "null" and "[]" both round-trip to an empty list; storing the shorter one
	// keeps the rows readable when someone opens the database by hand.
	if string(b) == "null" {
		return "[]", nil
	}
	return string(b), nil
}

func scanBytes(src any) ([]byte, error) {
	switch v := src.(type) {
	case nil:
		return nil, nil
	case []byte:
		return v, nil
	case string:
		if v == "" {
			return nil, nil
		}
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("scan list: unsupported type %T", src)
	}
}

// --- outbound queries -------------------------------------------------------

// ListOutbounds returns every outbound in render order.
func (s *Store) ListOutbounds() ([]Outbound, error) {
	var out []Outbound
	// Ordered by sort_order then id: two outbounds sharing a sort order would
	// otherwise swap places between generations, and the FIRST outbound is the
	// core's default exit.
	if err := s.db.Order("sort_order asc, id asc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list outbounds: %w", err)
	}
	return out, nil
}

// OutboundByID loads one outbound.
func (s *Store) OutboundByID(id uint) (*Outbound, error) {
	var o Outbound
	if err := s.db.First(&o, id).Error; err != nil {
		return nil, err
	}
	return &o, nil
}

// SaveOutbound creates or updates an outbound, refusing a tag that would
// collide with a built-in.
func (s *Store) SaveOutbound(o *Outbound) error {
	o.Tag = strings.TrimSpace(o.Tag)
	if o.Tag == "" {
		return fmt.Errorf("an outbound needs a tag: rules refer to it by name")
	}
	if o.Tag == OutboundDirect || o.Tag == OutboundBlock || o.Tag == "api" {
		// Shadowing a built-in produces a config with two outbounds of one name.
		// The core picks one without saying which, so traffic an operator sent
		// to "block" could leave the machine.
		return fmt.Errorf("%q is a built-in outbound tag and cannot be reused", o.Tag)
	}
	if strings.HasPrefix(o.Tag, "egress-") {
		// The egress renderer generates tags in this space. A collision would
		// reroute a relay chain to an operator's outbound, silently.
		return fmt.Errorf("outbound tags starting with %q are reserved for per-inbound relay chains", "egress-")
	}
	if o.Protocol == "" {
		return fmt.Errorf("an outbound needs a protocol")
	}
	return s.db.Save(o).Error
}

// DeleteOutbound removes an outbound, refusing while a rule still points at it.
func (s *Store) DeleteOutbound(id uint) error {
	o, err := s.OutboundByID(id)
	if err != nil {
		return err
	}
	var users []RoutingRule
	if err := s.db.Find(&users).Error; err != nil {
		return err
	}
	var refs []string
	for _, r := range users {
		if r.OutboundTag == o.Tag {
			refs = append(refs, r.Name)
		}
	}
	if len(refs) > 0 {
		// Deleting it anyway would leave rules pointing at a tag the config no
		// longer defines, and the core refuses the whole config — so one delete
		// takes down every inbound on the box.
		return fmt.Errorf("%q is still used by %d rule(s): %s", o.Tag, len(refs), strings.Join(refs, ", "))
	}
	return s.db.Delete(&Outbound{}, id).Error
}

// --- rule queries -----------------------------------------------------------

// ListRoutingRules returns every rule in evaluation order.
func (s *Store) ListRoutingRules() ([]RoutingRule, error) {
	var out []RoutingRule
	if err := s.db.Order("sort_order asc, id asc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list routing rules: %w", err)
	}
	return out, nil
}

// RoutingRuleByID loads one rule.
func (s *Store) RoutingRuleByID(id uint) (*RoutingRule, error) {
	var r RoutingRule
	if err := s.db.First(&r, id).Error; err != nil {
		return nil, err
	}
	return &r, nil
}

// SaveRoutingRule creates or updates a rule after checking it can ever match and
// has somewhere to send traffic.
func (s *Store) SaveRoutingRule(r *RoutingRule) error {
	r.Name = strings.TrimSpace(r.Name)
	r.OutboundTag = strings.TrimSpace(r.OutboundTag)
	if r.OutboundTag == "" {
		return fmt.Errorf("a rule needs an outbound to send matching traffic to")
	}
	if !r.hasMatcher() {
		// A rule with no matcher matches EVERYTHING. Saved above a chain of
		// careful rules it silently swallows all of them, and the operator sees
		// a panel where routing "stopped working".
		return fmt.Errorf("a rule with no matchers would match all traffic; add at least one condition")
	}
	if r.OutboundTag != OutboundDirect && r.OutboundTag != OutboundBlock {
		var n int64
		if err := s.db.Model(&Outbound{}).Where("tag = ?", r.OutboundTag).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			// The core refuses a config whose rule names an undefined outbound,
			// which takes down every inbound. Catching it here means the rule is
			// rejected instead of the whole panel.
			return fmt.Errorf("no outbound is named %q", r.OutboundTag)
		}
	}
	return s.db.Save(r).Error
}

func (r *RoutingRule) hasMatcher() bool {
	return len(r.Domain) > 0 || len(r.IP) > 0 || r.Port != "" ||
		len(r.Protocol) > 0 || len(r.InboundTags) > 0 || len(r.UserIDs) > 0 ||
		(r.Network != "" && r.Network != "tcp,udp")
}

// DeleteRoutingRule removes a rule.
func (s *Store) DeleteRoutingRule(id uint) error {
	return s.db.Delete(&RoutingRule{}, id).Error
}

// ReorderRoutingRules writes a new evaluation order in one transaction.
//
// One transaction because rules are FIRST-MATCH: a partially applied reorder is
// a routing table nobody designed, live, for however long the failure goes
// unnoticed.
func (s *Store) ReorderRoutingRules(idsInOrder []uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for i, id := range idsInOrder {
			if err := tx.Model(&RoutingRule{}).Where("id = ?", id).
				UpdateColumn("sort_order", i).Error; err != nil {
				return fmt.Errorf("reorder rule %d: %w", id, err)
			}
		}
		return nil
	})
}
