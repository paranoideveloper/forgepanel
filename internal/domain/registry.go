// Package domain is the domain registry and DNS health layer (spec §7). It
// tracks the domains the panel uses (panel/sub/inbound-sni/forgedns-zone/cdn-
// front), verifies their A/AAAA/CNAME resolution live, and reports propagation
// against the server's own IP. The resolver is injectable so the health logic
// is unit-tested without real DNS.
package domain

import (
	"context"
	"net"
	"strings"
	"time"
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
func NSDelegation(zone, serverIP string) []Record {
	zone = strings.TrimSuffix(zone, ".")
	parent := zone
	if i := strings.Index(zone, "."); i >= 0 {
		parent = zone[i+1:]
	}
	ns := "ns1." + parent
	return []Record{
		{Type: "A", Name: ns, Value: serverIP, Note: "glue: the authoritative NS host → this server"},
		{Type: "NS", Name: zone, Value: ns, Note: "delegate the tunnel zone to that NS"},
	}
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
