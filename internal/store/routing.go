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

// SetSettings replaces the core settings blob.
//
// The field's type is unexported — deliberately, so a malformed value fails on
// write rather than when the config is generated — which also means no other
// package can assign to it. Callers that build an outbound programmatically
// (the WARP provisioner is the first) need this rather than a JSON round-trip
// through the whole struct.
//
// It validates, for the same reason the type exists: a caller that renders
// settings itself can hand over something that only fails later, inside the
// core, as an error naming neither this outbound nor the field.
func (o *Outbound) SetSettings(raw []byte) error {
	if len(raw) == 0 {
		o.Settings = nil
		return nil
	}
	if !json.Valid(raw) {
		return fmt.Errorf("outbound %q: settings are not valid JSON", o.Tag)
	}
	o.Settings = datatypesJSON(append([]byte(nil), raw...))
	return nil
}

// SetStreamSettings replaces the transport blob, with the same contract.
func (o *Outbound) SetStreamSettings(raw []byte) error {
	if len(raw) == 0 {
		o.StreamSettings = nil
		return nil
	}
	if !json.Valid(raw) {
		return fmt.Errorf("outbound %q: stream settings are not valid JSON", o.Tag)
	}
	o.StreamSettings = datatypesJSON(append([]byte(nil), raw...))
	return nil
}

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

// OutboundGroup is several outbounds behind one tag, health-probed, so traffic
// moves off a member that stops answering.
//
// It exists because a rule could name exactly ONE exit. An operator with two
// relays had to choose which one every rule used, and when that relay went down
// their users' traffic went down with it until someone noticed and edited the
// rule by hand — on a panel whose whole point is keeping people connected.
//
// A THIRD ENTITY rather than a field on Outbound, because the core treats it as
// a different kind of thing: a rule aimed at a group is rendered with
// "balancerTag", not "outboundTag". Nothing catches that mistake — the config
// validates and the core starts — and every connection the rule matches is then
// dropped with one line in the log.
type OutboundGroup struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// Tag is what rules point at. It shares a namespace with Outbound.Tag —
	// SaveOutboundGroup and SaveOutbound each refuse a collision, because a rule
	// naming a tag that is both would be ambiguous in the panel and rendered
	// with the wrong key in the core.
	Tag string `gorm:"uniqueIndex;size:64" json:"tag"`
	// Members are Outbound tags. Stored as tags rather than ids so the set
	// survives an outbound being recreated, and so the rendered selector is a
	// direct copy of what the operator sees.
	Members stringList `gorm:"type:text" json:"members"`
	// Strategy is how the balancer picks among the members that are up:
	// leastPing, leastLoad, roundRobin or random. Empty takes the renderer's
	// default.
	Strategy string `gorm:"size:32" json:"strategy"`
	// ProbeURL and ProbeInterval are the health check that decides which members
	// are up. The core keeps ONE observatory for the whole config, so two groups
	// that disagree about these are refused at render time rather than one of
	// them silently losing.
	ProbeURL      string `gorm:"size:255" json:"probe_url"`
	ProbeInterval string `gorm:"size:32" json:"probe_interval"`
	// AllDownPolicy is where traffic goes when EVERY member is down: an outbound
	// tag, or one of the built-ins.
	//
	// It defaults to "block", and that default is the point. Measured on Xray
	// 26.2.6 with two unreachable members: a balancer with NO fallback sent the
	// connection out direct — the access log reads "[in >> direct]" — out of the
	// server's real address, past the relays the group existed to hide behind.
	// With a fallback set, the traffic was dropped instead. So an operator who
	// leaves this blank would get a leak at exactly the moment their exits fail,
	// which is the moment they are least likely to be watching.
	AllDownPolicy string `gorm:"size:64" json:"all_down_policy"`
	Enabled       bool   `json:"enabled"`
	// Note is the operator's own reminder of what this group is for.
	Note      string    `gorm:"size:255" json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (OutboundGroup) TableName() string { return "outbound_groups" }

// GroupStrategies are the balancing strategies the core understands. A value
// outside this set renders a config the core refuses, which takes every inbound
// on the box down — so it is caught on the way in.
var GroupStrategies = []string{"leastPing", "leastLoad", "roundRobin", "random"}

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
	// Outbounds and groups share one tag namespace, because rules point into
	// both. A tag that named each of them would be rendered as an outbound by
	// one code path and a balancer by another.
	var groups int64
	if err := s.db.Model(&OutboundGroup{}).Where("tag = ?", o.Tag).Count(&groups).Error; err != nil {
		return err
	}
	if groups > 0 {
		return fmt.Errorf("%q is already a failover group; rules point at outbounds and groups by the same name", o.Tag)
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
	// A group holds its members by TAG, and this is worse than the rule case
	// above rather than the same. A balancer whose selector matches no outbound
	// does not fail: measured on Xray 26.2.6, the config validates, the core
	// starts, and the traffic the group was carrying goes out DIRECT — from the
	// server's own address, past the relays, with fallbackTag ignored. One
	// delete turns a relayed rule into a leak that logs nothing.
	groups, err := s.ListOutboundGroups()
	if err != nil {
		return err
	}
	var inGroups []string
	for _, g := range groups {
		for _, m := range g.Members {
			if m == o.Tag {
				inGroups = append(inGroups, g.Tag)
				break
			}
		}
		if g.AllDownPolicy == o.Tag {
			inGroups = append(inGroups, g.Tag+" (all-down policy)")
		}
	}
	if len(inGroups) > 0 {
		return fmt.Errorf("%q is still a member of %d failover group(s): %s",
			o.Tag, len(inGroups), strings.Join(inGroups, ", "))
	}
	return s.db.Delete(&Outbound{}, id).Error
}

// --- failover group queries -------------------------------------------------

// ListOutboundGroups returns every failover group, oldest first.
func (s *Store) ListOutboundGroups() ([]OutboundGroup, error) {
	var out []OutboundGroup
	if err := s.db.Order("id asc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list outbound groups: %w", err)
	}
	return out, nil
}

// OutboundGroupByID loads one group.
func (s *Store) OutboundGroupByID(id uint) (*OutboundGroup, error) {
	var g OutboundGroup
	if err := s.db.First(&g, id).Error; err != nil {
		return nil, err
	}
	return &g, nil
}

// SaveOutboundGroup creates or updates a failover group.
//
// The checks below guard two different failures, and the quiet one is the worse
// of them. An unknown strategy or an empty member list is refused by the core,
// which refuses the WHOLE config and takes every inbound on the box offline. A
// member naming an outbound that does not exist is accepted by the core and then
// sends that traffic out direct, past the relays, from the server's own address.
// The first is an outage; the second is a leak nobody is told about.
func (s *Store) SaveOutboundGroup(g *OutboundGroup) error {
	g.Tag = strings.TrimSpace(g.Tag)
	if g.Tag == "" {
		return fmt.Errorf("a failover group needs a tag: rules refer to it by name")
	}
	if g.Tag == OutboundDirect || g.Tag == OutboundBlock || g.Tag == "api" {
		return fmt.Errorf("%q is a built-in outbound tag and cannot be reused", g.Tag)
	}
	if strings.HasPrefix(g.Tag, "egress-") {
		return fmt.Errorf("tags starting with %q are reserved for per-inbound relay chains", "egress-")
	}
	var n int64
	if err := s.db.Model(&Outbound{}).Where("tag = ?", g.Tag).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%q is already an outbound; rules point at outbounds and groups by the same name", g.Tag)
	}
	if g.Strategy != "" {
		ok := false
		for _, v := range GroupStrategies {
			if v == g.Strategy {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%q is not a balancing strategy the core understands (%s)",
				g.Strategy, strings.Join(GroupStrategies, ", "))
		}
	}

	if len(g.Members) == 0 {
		// The core refuses a balancer with an empty selector, and it refuses the
		// whole config for it — so storing one would take every inbound on the
		// box offline at the next reload.
		return fmt.Errorf("a failover group needs at least one member; the core refuses a balancer with an empty selector, and refuses the whole config with it")
	}
	byTag, err := s.outboundTags()
	if err != nil {
		return err
	}
	groupTags, err := s.groupTags()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	members := make(stringList, 0, len(g.Members))
	for _, m := range g.Members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if seen[m] {
			continue // a member listed twice is still one exit
		}
		if groupTags[m] {
			// The core has no nested balancers: a selector is matched against
			// OUTBOUND tags, so a group naming a group selects nothing and the
			// operator gets a balancer that silently has no members.
			return fmt.Errorf("%q is a failover group; a group's members must be outbounds", m)
		}
		if !byTag[m] {
			// A member the config does not define selects nothing, and a
			// balancer that selects nothing sends its traffic out direct rather
			// than failing — so a typo here is a silent leak, not an error.
			//
			// Built-ins are refused here too, on purpose: "direct" and "block"
			// are always reachable, so either of them inside a group wins every
			// health probe and the real exits never see traffic. Where traffic
			// should go when the exits are all down is what AllDownPolicy says.
			return fmt.Errorf("no outbound is named %q", m)
		}
		seen[m] = true
		members = append(members, m)
	}
	if len(members) == 0 {
		return fmt.Errorf("a failover group needs at least one member")
	}
	g.Members = members

	g.AllDownPolicy = strings.TrimSpace(g.AllDownPolicy)
	if g.AllDownPolicy == "" {
		g.AllDownPolicy = OutboundBlock
	}
	if g.AllDownPolicy != OutboundDirect && g.AllDownPolicy != OutboundBlock && !byTag[g.AllDownPolicy] {
		return fmt.Errorf("no outbound is named %q for the all-down policy", g.AllDownPolicy)
	}
	return s.db.Save(g).Error
}

// DeleteOutboundGroup removes a group, refusing while a rule still points at it.
func (s *Store) DeleteOutboundGroup(id uint) error {
	g, err := s.OutboundGroupByID(id)
	if err != nil {
		return err
	}
	rules, err := s.ListRoutingRules()
	if err != nil {
		return err
	}
	var refs []string
	for _, r := range rules {
		if r.OutboundTag == g.Tag {
			refs = append(refs, r.Name)
		}
	}
	if len(refs) > 0 {
		// The rule would keep naming a balancer the config no longer defines.
		// The core accepts that and drops every connection the rule matches, so
		// the group disappears and the rule stops carrying traffic with nothing
		// in the panel to connect the two events.
		return fmt.Errorf("%q is still used by %d rule(s): %s", g.Tag, len(refs), strings.Join(refs, ", "))
	}
	return s.db.Delete(&OutboundGroup{}, id).Error
}

func (s *Store) outboundTags() (map[string]bool, error) {
	obs, err := s.ListOutbounds()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(obs))
	for _, o := range obs {
		out[o.Tag] = true
	}
	return out, nil
}

func (s *Store) groupTags() (map[string]bool, error) {
	gs, err := s.ListOutboundGroups()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(gs))
	for _, g := range gs {
		out[g.Tag] = true
	}
	return out, nil
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
			// A rule may also target a failover GROUP. Counting only outbounds
			// made every group unreachable from the UI: the group existed, the
			// balancer rendered, and no rule could ever be saved to point at it.
			if err := s.db.Model(&OutboundGroup{}).Where("tag = ?", r.OutboundTag).Count(&n).Error; err != nil {
				return err
			}
		}
		if n == 0 {
			// The core refuses a config whose rule names an undefined outbound,
			// which takes down every inbound. Catching it here means the rule is
			// rejected instead of the whole panel.
			return fmt.Errorf("no outbound or failover group is named %q", r.OutboundTag)
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
