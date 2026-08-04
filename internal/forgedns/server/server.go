// Package server is the ForgeDNS authoritative listener (spec §5.2): a miekg/dns
// UDP server that routes a query by its QNAME suffix to the zone's adapter,
// drives the session manager, and answers with tunnel data. It is NOT a
// recursive resolver: queries for zones it does not own get NXDOMAIN, ANY
// queries are dropped, and per-source rate limits apply (spec §5.4).
package server

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// Zone binds a tunnel domain to an adapter and a session manager.
type Zone struct {
	Name     string
	Adapter  adapter.Adapter
	Sessions *session.Manager
}

// Server is the authoritative DNS tunnel listener.
type Server struct {
	mu    sync.RWMutex
	zones []*Zone
	udp   *dns.Server
}

// New builds an empty server.
func New() *Server { return &Server{} }

// AddZone registers a tunnel zone.
func (s *Server) AddZone(z *Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z.Name = strings.ToLower(strings.TrimSuffix(z.Name, "."))
	if z.Sessions == nil {
		z.Sessions = session.NewManager(60 * time.Second)
	}
	s.zones = append(s.zones, z)
}

// matchZone finds the zone owning a QNAME (longest suffix wins).
func (s *Server) matchZone(qname string) *Zone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	var best *Zone
	for _, z := range s.zones {
		if q == z.Name || strings.HasSuffix(q, "."+z.Name) {
			if best == nil || len(z.Name) > len(best.Name) {
				best = z
			}
		}
	}
	return best
}

// Handle processes a query and returns the response message, or nil to drop.
// Exposed directly so it is unit-testable without a socket.
func (s *Server) Handle(m *dns.Msg) *dns.Msg {
	if len(m.Question) == 0 {
		return nil
	}
	q := m.Question[0]
	// Never behave as an open resolver; drop ANY queries (§5.4).
	if q.Qtype == dns.TypeANY {
		return refuse(m)
	}
	z := s.matchZone(q.Name)
	if z == nil {
		return nxdomain(m) // not our zone
	}
	if !z.Adapter.Match(z.Name, m) {
		return nxdomain(m)
	}
	frame, err := z.Adapter.Decode(z.Name, m)
	if err != nil {
		return nxdomain(m)
	}
	resp := z.Sessions.Ingest(frame)
	out, err := z.Adapter.Encode(z.Name, m, resp)
	if err != nil {
		return servfail(m)
	}
	return out
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	resp := s.Handle(m)
	if resp == nil {
		return
	}
	_ = w.WriteMsg(resp)
}

// ListenAndServe starts the UDP listener on addr (e.g. ":53").
func (s *Server) ListenAndServe(addr string) error {
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s}
	return s.udp.ListenAndServe()
}

// Shutdown stops the listener.
func (s *Server) Shutdown() error {
	if s.udp != nil {
		return s.udp.Shutdown()
	}
	return nil
}

// Zones returns a snapshot of registered zone names.
func (s *Server) Zones() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.zones))
	for _, z := range s.zones {
		out = append(out, z.Name)
	}
	return out
}

func nxdomain(m *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeNameError)
	r.Authoritative = true
	return r
}

func servfail(m *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeServerFailure)
	return r
}

func refuse(m *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeRefused)
	return r
}
