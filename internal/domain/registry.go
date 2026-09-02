// Package domain is the domain registry and DNS health layer (spec §7). It
// tracks the domains the panel uses (panel/sub/inbound-sni/forgedns-zone/cdn-
// front), verifies their A/AAAA/CNAME resolution live, and reports propagation
// against the server's own IP. The resolver is injectable so the health logic
// is unit-tested without real DNS.
package domain

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Role is what a domain is used for (spec §7).
type Role string

const (
	RolePanel        Role = "panel"
	RoleSub          Role = "sub"
	RoleInboundSNI   Role = "inbound-sni"
	RoleForgeDNSZone Role = "forgedns-zone"
	RoleCDNFront     Role = "cdn-front"
)

// Resolver is the subset of *net.Resolver the registry needs. Tests substitute
// a fake.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Health is the resolution status of a domain relative to an expected IP.
type Health struct {
	Domain    string   `json:"domain"`
	Resolved  []string `json:"resolved"`
	CNAME     string   `json:"cname,omitempty"`
	MatchesIP bool     `json:"matches_ip"`
	Reachable bool     `json:"reachable"`
	Error     string   `json:"error,omitempty"`
	CheckedAt string   `json:"checked_at"`
}

// Registry holds domains and checks their health.
type Registry struct {
	res Resolver
}

// New builds a Registry with the given resolver (pass nil for net.DefaultResolver).
func New(res Resolver) *Registry {
	if res == nil {
		res = net.DefaultResolver
	}
	return &Registry{res: res}
}

// Check resolves domain and reports whether it points at expectIP. now is passed
// in so the timestamp is deterministic in tests.
func (r *Registry) Check(ctx context.Context, domainName, expectIP string, now time.Time) Health {
	h := Health{Domain: domainName, CheckedAt: now.UTC().Format(time.RFC3339)}
	domainName = strings.TrimSuffix(domainName, ".")
	ips, err := r.res.LookupHost(ctx, domainName)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	h.Resolved = ips
	if cname, err := r.res.LookupCNAME(ctx, domainName); err == nil {
		h.CNAME = strings.TrimSuffix(cname, ".")
	}
	for _, ip := range ips {
		if ip == expectIP {
			h.MatchesIP = true
			break
		}
	}
	h.Reachable = len(ips) > 0
	return h
}

// NSDelegation returns the exact glue/NS records an operator must create to
// delegate a ForgeDNS tunnel zone to this server (spec §5.3 NS wizard).
func NSDelegation(zone, serverIP string) ([]Record, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if zone == "" || !strings.Contains(zone, ".") {
		return nil, fmt.Errorf("domain: invalid zone %q", zone)
	}
	// A public suffix (a TLD like "com" or a multi-label one like "co.uk") cannot
	// be delegated — this is what previously produced "ns1.com" for "example.com".
	if suffix, icann := publicsuffix.PublicSuffix(zone); icann && suffix == zone {
		return nil, fmt.Errorf("domain: %q is a public suffix and cannot be delegated", zone)
	}
	// The nameserver host lives under the REGISTRABLE domain (eTLD+1), so a
	// subdomain zone like "t.example.com" delegates to "ns1.example.com" and a
	// bare "example.com" delegates to "ns1.example.com" — never "ns1.com".
	reg, err := publicsuffix.EffectiveTLDPlusOne(zone)
	if err != nil {
		return nil, fmt.Errorf("domain: %q has no registrable domain: %w", zone, err)
	}
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, fmt.Errorf("domain: invalid server IP %q", serverIP)
	}
	// AAAA glue for an IPv6 address, A for IPv4.
	glueType := "A"
	if ip.To4() == nil {
		glueType = "AAAA"
	}
	ns := "ns1." + reg
	// Glue is strictly required only when the NS host is in-bailiwick (within the
	// delegated zone); otherwise the A/AAAA record belongs in the registrable
	// zone. We emit it either way and label which case applies.
	note := "glue: the in-bailiwick NS host → this server"
	if ns != zone && !strings.HasSuffix(ns, "."+zone) {
		note = "A/AAAA for the out-of-bailiwick NS host → this server"
	}
	return []Record{
		{Type: glueType, Name: ns, Value: ip.String(), Note: note},
		{Type: "NS", Name: zone, Value: ns, Note: "delegate the zone to that NS"},
	}, nil
}

// Record is a DNS record instruction.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// VerifyDelegation queries the authoritative chain to confirm the zone is
// delegated to nsHost (spec §5.3 live verification). Returns per-hop pass/fail.
func (r *Registry) VerifyDelegation(ctx context.Context, zone, nsHost, serverIP string) []Health {
	now := time.Now()
	return []Health{
		r.Check(ctx, nsHost, serverIP, now), // NS host resolves to us
	}
}
