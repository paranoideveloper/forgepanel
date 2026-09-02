package store

// Per-inbound public endpoints ("hosts").
//
// One inbound listens once, but it is reachable by several routes that need
// DIFFERENT client-facing settings: straight to the server's IP, through a CDN
// edge that terminates TLS for a domain, or domain-fronted behind an SNI that
// is not the Host header. Until now a subscription could only fan out along two
// fixed axes — one entry per REALITY SNI, or one per clean edge IP — with
// everything else copied from the inbound. There was no way to say "this
// endpoint is the CDN one: port 8443, this SNI, this Host, ALPN h2, and
// allowInsecure because the edge presents its own certificate".
//
// So an operator running a direct route and a CDN route for the same inbound
// had to create the inbound twice, which means two listeners, two sets of
// credentials to keep in step, and two rows to remember to change together.

import (
	"strings"
	"time"
)

// InboundHost is one public-facing endpoint for an inbound.
//
// Every field is an OVERRIDE: empty means "use the inbound's own value". That
// is what makes a host cheap to add — a CDN endpoint that differs only in port
// and Host header says exactly that, and keeps following the inbound for
// everything else, including credentials.
type InboundHost struct {
	Base
	InboundID uint `gorm:"index;not null" json:"inbound_id"`

	// Remark is the config's name in the client. Supports the same {FLAG},
	// {NAME}, {NET} tokens as the subscription naming template; empty falls back
	// to the inbound's remark with the host's label appended.
	Remark string `json:"remark"`
	// Label is a short operator-facing name ("CDN", "direct", "fronted").
	Label string `json:"label"`

	// Address and Port are what the client dials. Address empty means the
	// inbound's own address.
	Address string `json:"address"`
	Port    int    `json:"port"`

	// Security overrides the TLS mode: "", "none", "tls", "reality".
	//
	// A CDN endpoint in front of a plaintext-WS inbound is the case this exists
	// for: the inbound itself terminates no TLS, and the client must still speak
	// TLS to the edge.
	Security string `json:"security"`
	// SNI is the TLS server name the client presents.
	SNI string `json:"sni"`
	// HostHeader is the HTTP Host / gRPC authority. Splitting it from SNI is the
	// whole of domain fronting: they are the same string in the ordinary case
	// and deliberately different in the interesting one.
	HostHeader string `json:"host_header"`
	// Path overrides the ws/httpupgrade/xhttp path or the gRPC service name.
	Path string `json:"path"`
	// ALPN is comma-separated ("h2,http/1.1"). A CDN that only speaks h2 needs
	// this and the inbound does not.
	ALPN string `json:"alpn"`
	// Fingerprint is the uTLS profile.
	Fingerprint string `json:"fingerprint"`
	// AllowInsecure skips certificate verification for THIS endpoint. Needed
	// when an edge presents a certificate for a name the client is not using —
	// domain fronting, or a self-signed origin behind a CDN.
	AllowInsecure bool `json:"allow_insecure"`

	// Enabled lets an endpoint be parked without deleting it, which matters
	// when a CDN route stops working and the operator wants it back later.
	Enabled bool `json:"enabled" gorm:"default:true"`
	// Priority orders the entries in the subscription, ascending.
	Priority int `json:"priority"`

	CreatedAt time.Time `json:"created_at"`
}

// ALPNList splits the stored ALPN string.
func (h *InboundHost) ALPNList() []string {
	if strings.TrimSpace(h.ALPN) == "" {
		return nil
	}
	parts := strings.Split(h.ALPN, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// HostsForInbound returns an inbound's endpoints in subscription order.
func (s *Store) HostsForInbound(inboundID uint) ([]InboundHost, error) {
	var out []InboundHost
	err := s.db.Where("inbound_id = ?", inboundID).
		Order("priority asc, id asc").Find(&out).Error
	return out, err
}

// HostsForInbounds returns endpoints for many inbounds at once, keyed by
// inbound id.
//
// One query rather than one per inbound: subscription generation runs on every
// client refresh, and a panel with 200 inbounds would otherwise issue 200
// queries per fetch.
func (s *Store) HostsForInbounds(ids []uint) (map[uint][]InboundHost, error) {
	out := map[uint][]InboundHost{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []InboundHost
	if err := s.db.Where("inbound_id IN ?", ids).
		Order("priority asc, id asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.InboundID] = append(out[r.InboundID], r)
	}
	return out, nil
}

// CreateHost persists a new endpoint.
func (s *Store) CreateHost(h *InboundHost) error {
	// GORM omits zero values on INSERT when a column declares a default, so a
	// host created with Enabled:false would be stored ENABLED — the same trap
	// that once put a live listener on a port nobody agreed to open. Capture the
	// intent and write it back explicitly.
	wantEnabled := h.Enabled
	if err := s.db.Create(h).Error; err != nil {
		return err
	}
	if !wantEnabled {
		return s.db.Model(h).UpdateColumn("enabled", false).Error
	}
	return nil
}

// SaveHost updates an endpoint.
func (s *Store) SaveHost(h *InboundHost) error {
	return s.db.Model(h).Select("*").Omit("created_at").Updates(h).Error
}

// HostByID loads one endpoint.
func (s *Store) HostByID(id uint) (*InboundHost, error) {
	var h InboundHost
	if err := s.db.First(&h, id).Error; err != nil {
		return nil, err
	}
	return &h, nil
}

// DeleteHost removes an endpoint.
func (s *Store) DeleteHost(id uint) error {
	return s.db.Delete(&InboundHost{}, id).Error
}

// DeleteHostsForInbound removes every endpoint belonging to an inbound.
//
// Called when the inbound goes away: an orphaned host row would keep appearing
// in nothing and confuse the next person to read the table.
func (s *Store) DeleteHostsForInbound(inboundID uint) error {
	return s.db.Where("inbound_id = ?", inboundID).Delete(&InboundHost{}).Error
}
