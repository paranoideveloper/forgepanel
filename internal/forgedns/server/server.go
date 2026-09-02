// Package server is the ForgeDNS authoritative listener (spec §5.2): a miekg/dns
// UDP server that routes a query by its QNAME suffix to the zone's adapter,
// drives the session manager, and answers with tunnel data.
//
// It serves two kinds of question for the zones it owns:
//
//   - names carrying an encoded payload, which are tunnel traffic and go to the
//     adapter and session manager;
//   - the zone apex and everything else, which are ordinary DNS and are answered
//     from the zone's authoritative data (SOA, NS, A, AAAA). This is what makes
//     NS delegation and monitoring work: a parent zone's delegation check and any
//     resolver's SOA lookup are plain apex queries, and answering them NXDOMAIN
//     — as this server used to — makes the zone undelegatable.
//
// It is NOT a recursive resolver and must not become an amplifier: it refuses
// names outside its zones, never sets RA, returns a minimal RFC 8482 answer for
// ANY, caps the EDNS0 buffer it advertises, truncates rather than emitting large
// UDP datagrams, and rate limits responses per client prefix (spec §5.4).
package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// maxAdvertisedUDP caps the EDNS0 buffer size the server advertises. A large
// advertised buffer is precisely what makes a DNS server useful as a reflector,
// so we never echo the client's 4096 back at it.
const maxAdvertisedUDP = 1232

// defaultTTL is the TTL on synthesised authoritative records.
const defaultTTL = 300

// Zone binds a tunnel domain to an adapter and a session manager, plus the
// authoritative data used to answer ordinary queries for the zone.
type Zone struct {
	Name     string
	Adapter  adapter.Adapter
	Sessions *session.Manager

	// Egress carries a session's reassembled bytes to their destination and the
	// replies back. Without it the zone answers DNS, creates sessions and counts
	// traffic while moving nothing — which is what the native path did.
	//
	// nil is a legitimate configuration: a zone served by an upstream binary
	// adapter tunnels in that process, not this one.
	Egress SessionBridge

	// NS are the zone's nameserver hostnames, answered at the apex and used in
	// the authority section. Defaults to ns1.<zone>.
	NS []string
	// Addrs are the apex A/AAAA addresses (usually this server's public IP).
	Addrs []net.IP
	// Mbox is the SOA responsible-party mailbox. Defaults to hostmaster.<zone>.
	Mbox string
	// Serial is the SOA serial. Defaults to 1.
	Serial uint32
	// TTL applies to synthesised records. Defaults to defaultTTL.
	TTL uint32
}

// SessionBridge is the egress side of a tunnel zone. It is an interface so this
// package does not depend on the bridge implementation, and so a zone can be
// tested without opening sockets.
type SessionBridge interface {
	// Deliver moves whatever the session has reassembled to its destination.
	// It is called with the id of the session the frame belongs to.
	Deliver(ctx context.Context, sessionID uint64)
}

// RateLimit bounds responses per client prefix. Identical and error traffic get
// separate budgets because they are abused differently: repeated identical
// answers are the amplification lever, while a flood of NXDOMAIN/REFUSED is the
// classic way to turn an authoritative server into a reflector.
type RateLimit struct {
	Identical int           // identical (name, type, rcode) responses per window
	Errors    int           // NXDOMAIN / REFUSED / SERVFAIL responses per window
	Window    time.Duration // budget window
}

// Counters are the server's observability counters.
type Counters struct {
	RateLimited uint64 `json:"rate_limited"`
	Truncated   uint64 `json:"truncated"`
	Refused     uint64 `json:"refused"`
	Malformed   uint64 `json:"malformed"`
}

// Server is the authoritative DNS tunnel listener.
type Server struct {
	mu    sync.RWMutex
	zones []*Zone
	udp   *dns.Server
	// shutdown records that Shutdown has been called, so a ListenAndServe that
	// loses the race does not bind a listener nothing holds a reference to.
	shutdown bool
	rrl      *rrl
	counters Counters
}

// New builds an empty server with default response-rate limits.
func New() *Server {
	return &Server{rrl: newRRL(RateLimit{Identical: 15, Errors: 5, Window: time.Second})}
}

// SetRateLimit replaces the response-rate limits.
func (s *Server) SetRateLimit(l RateLimit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rrl = newRRL(l)
}

// Counters snapshots the server's counters.
func (s *Server) Counters() Counters {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counters
}

// AddZone registers a tunnel zone, filling in authoritative defaults so a zone
// is delegatable even when the operator supplied only a name.
func (s *Server) AddZone(z *Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z.Name = strings.ToLower(strings.TrimSuffix(z.Name, "."))
	if z.Sessions == nil {
		z.Sessions = session.NewManager(60 * time.Second)
	}
	if len(z.NS) == 0 {
		z.NS = []string{defaultNS(z.Name)}
	}
	if z.Mbox == "" {
		z.Mbox = "hostmaster." + z.Name
	}
	if z.Serial == 0 {
		z.Serial = 1
	}
	if z.TTL == 0 {
		z.TTL = defaultTTL
	}
	s.zones = append(s.zones, z)
}

// defaultNS derives the zone's nameserver hostname the same way the delegation
// wizard does (internal/domain.NSDelegation): under the REGISTRABLE domain, so a
// zone "t.example.com" advertises "ns1.example.com" and never "ns1.com". The two
// must agree — the panel tells the operator to point that exact host at this
// server, and answering NS with a different name makes the delegation
// inconsistent.
func defaultNS(zone string) string {
	if reg, err := publicsuffix.EffectiveTLDPlusOne(zone); err == nil && reg != "" {
		return "ns1." + reg
	}
	return "ns1." + zone
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
// Exposed directly so it is unit-testable without a socket. Rate limiting is
// keyed on the client address, so this form (no address) is never limited.
func (s *Server) Handle(m *dns.Msg) *dns.Msg { return s.HandleFrom(nil, m) }

// HandleFrom is Handle with the client address, which response-rate limiting
// needs.
func (s *Server) HandleFrom(src net.Addr, m *dns.Msg) *dns.Msg {
	if len(m.Question) == 0 {
		return nil
	}
	q := m.Question[0]
	z := s.matchZone(q.Name)
	if z == nil {
		// Not our zone. REFUSED, not NXDOMAIN: we have no authority to say the
		// name does not exist, and it is the smaller answer.
		s.bump(&s.counters.Refused)
		return s.finish(src, m, refuse(m))
	}

	// ANY must not expand into every record we hold (RFC 8482).
	if q.Qtype == dns.TypeANY {
		return s.finish(src, m, z.minimalANY(m))
	}

	// Tunnel traffic: a name under the zone carrying an encoded payload.
	if z.Adapter != nil && z.Adapter.Match(z.Name, m) {
		frame, err := z.Adapter.Decode(z.Name, m)
		if err != nil {
			// A name under the zone whose encoded label is not a valid frame.
			// That name genuinely does not exist, so NXDOMAIN is correct — and
			// no session is created for it.
			if !errors.Is(err, adapter.ErrNoPayload) {
				s.bump(&s.counters.Malformed)
			}
			return s.finish(src, m, z.nxdomain(m))
		}
		resp := z.Sessions.Ingest(frame)
		// Forward whatever that frame completed. A DNS tunnel has no clock other
		// than the client's next query, so this is the only moment reassembled
		// bytes can move.
		//
		// The reply the destination sends back rides the NEXT answer, not this
		// one. That is deliberate: Ingest has already committed this response's
		// in-flight chunk and request sequence, and re-running it to fold in
		// late-arriving bytes would corrupt the replay buffer the stop-and-wait
		// delivery depends on — trading a lost round trip for a lost byte. The
		// client polls continuously, so the round trip is what it already costs.
		if z.Egress != nil {
			if id, ok := sessionIDOf(frame, resp); ok {
				z.Egress.Deliver(context.Background(), id)
			}
		}
		out, err := z.Adapter.Encode(z.Name, m, resp)
		if err != nil {
			return s.finish(src, m, servfail(m))
		}
		out.Authoritative = true
		return s.finish(src, m, out)
	}

	// Ordinary authoritative DNS for the zone.
	if strings.EqualFold(strings.TrimSuffix(q.Name, "."), z.Name) {
		return s.finish(src, m, z.apex(m))
	}
	return s.finish(src, m, z.nxdomain(m))
}

// sessionIDOf resolves the 64-bit session id a frame belongs to.
//
// v2 sessions carry a full 64-bit CSPRNG id in the extension; v1 sessions have
// only the 16-bit header field. On the handshake the client sends no id at all
// and the server mints one, so the answer is the only place it appears.
func sessionIDOf(req, resp codec.Frame) (uint64, bool) {
	if req.Has(codec.FlagEXT) {
		if req.Ext != nil && req.Ext.SessionID != 0 {
			return req.Ext.SessionID, true
		}
		if resp.Ext != nil && resp.Ext.SessionID != 0 {
			return resp.Ext.SessionID, true
		}
		return 0, false
	}
	if resp.Flags == 0 && resp.Ext == nil && len(resp.Payload) == 0 {
		return 0, false // the frame was rejected; no session exists for it
	}
	return uint64(req.SessionID), true
}

func (s *Server) bump(p *uint64) {
	s.mu.Lock()
	*p++
	s.mu.Unlock()
}

// finish applies the policies that every response must obey regardless of which
// path produced it: no recursion, a capped EDNS0 buffer, response-rate limiting,
// and truncation instead of oversized UDP.
func (s *Server) finish(src net.Addr, q, resp *dns.Msg) *dns.Msg {
	if resp == nil {
		return nil
	}
	// Never advertise recursion: this is an authoritative server, and RA is what
	// marks a host as an open resolver worth abusing.
	resp.RecursionAvailable = false

	budget := dns.MinMsgSize // 512
	if opt := q.IsEdns0(); opt != nil {
		if sz := int(opt.UDPSize()); sz > budget {
			budget = sz
		}
		if budget > maxAdvertisedUDP {
			budget = maxAdvertisedUDP
		}
		resp.SetEdns0(uint16(budget), false)
	}

	s.mu.RLock()
	limiter := s.rrl
	s.mu.RUnlock()
	if !limiter.allow(src, q.Question[0], resp.Rcode) {
		s.bump(&s.counters.RateLimited)
		return nil // drop: a rate-limited response is not sent at all
	}

	if resp.Len() > budget {
		resp.Truncated = true
		resp.Answer = nil
		resp.Ns = nil
		resp.Extra = nil
		if opt := q.IsEdns0(); opt != nil {
			resp.SetEdns0(uint16(budget), false)
		}
		s.bump(&s.counters.Truncated)
	}
	return resp
}

// --- authoritative zone data ---------------------------------------------

func (z *Zone) fqdn() string { return dns.Fqdn(z.Name) }

func (z *Zone) soa() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: z.fqdn(), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTL},
		Ns:  dns.Fqdn(z.NS[0]), Mbox: dns.Fqdn(z.Mbox), Serial: z.Serial,
		Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 60,
	}
}

// apex answers an ordinary query for the zone name itself.
func (z *Zone) apex(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Authoritative = true

	switch q.Question[0].Qtype {
	case dns.TypeSOA:
		r.Answer = append(r.Answer, z.soa())
	case dns.TypeNS:
		for _, ns := range z.NS {
			r.Answer = append(r.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: z.fqdn(), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: z.TTL},
				Ns:  dns.Fqdn(ns),
			})
		}
	case dns.TypeA:
		for _, ip := range z.Addrs {
			if v4 := ip.To4(); v4 != nil {
				r.Answer = append(r.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: z.fqdn(), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: z.TTL},
					A:   v4,
				})
			}
		}
	case dns.TypeAAAA:
		for _, ip := range z.Addrs {
			if ip.To4() == nil && ip.To16() != nil {
				r.Answer = append(r.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: z.fqdn(), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: z.TTL},
					AAAA: ip.To16(),
				})
			}
		}
	}

	if len(r.Answer) == 0 {
		// The name exists, we just hold no data of this type: NOERROR/NODATA
		// with the SOA in authority, never NXDOMAIN.
		r.Ns = append(r.Ns, z.soa())
	}
	return r
}

// minimalANY implements RFC 8482: answer ANY with one synthesised HINFO rather
// than expanding the zone, which would be an amplification gift.
func (z *Zone) minimalANY(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Authoritative = true
	r.Answer = append(r.Answer, &dns.HINFO{
		Hdr: dns.RR_Header{
			Name: q.Question[0].Name, Rrtype: dns.TypeHINFO,
			Class: dns.ClassINET, Ttl: z.TTL,
		},
		Cpu: "RFC8482", Os: "",
	})
	return r
}

// nxdomain answers for a name under the zone that genuinely does not exist,
// carrying the SOA so resolvers can cache the negative answer.
func (z *Zone) nxdomain(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, dns.RcodeNameError)
	r.Authoritative = true
	r.Ns = append(r.Ns, z.soa())
	return r
}

// --- response rate limiting ----------------------------------------------

// maxRRLEntries bounds the limiter's own memory: an attacker rotating source
// addresses must not be able to grow the table without limit.
const maxRRLEntries = 8192

type rrl struct {
	mu    sync.Mutex
	limit RateLimit
	start time.Time
	ident map[string]int
	errs  map[string]int
	now   func() time.Time
}

func newRRL(l RateLimit) *rrl {
	if l.Window <= 0 {
		l.Window = time.Second
	}
	return &rrl{
		limit: l, ident: map[string]int{}, errs: map[string]int{},
		now: time.Now, start: time.Now(),
	}
}

// allow reports whether a response to src may be sent. A nil src (the in-process
// Handle form used by tests and internal callers) is never limited.
func (r *rrl) allow(src net.Addr, q dns.Question, rcode int) bool {
	if r == nil || src == nil {
		return true
	}
	prefix := clientPrefix(src)
	if prefix == "" {
		return true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.start) >= r.limit.Window || len(r.ident)+len(r.errs) > maxRRLEntries {
		r.start = now
		r.ident = map[string]int{}
		r.errs = map[string]int{}
	}

	if rcode != dns.RcodeSuccess {
		r.errs[prefix]++
		return r.limit.Errors <= 0 || r.errs[prefix] <= r.limit.Errors
	}
	key := prefix + "|" + strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype]
	r.ident[key]++
	return r.limit.Identical <= 0 || r.ident[key] <= r.limit.Identical
}

// clientPrefix buckets a client by network rather than by exact address, so
// rotating the low bits of a source address does not buy a fresh budget.
func clientPrefix(src net.Addr) string {
	var ip net.IP
	switch a := src.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(src.String())
		if err != nil {
			return ""
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// --- listener -------------------------------------------------------------

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	resp := s.HandleFrom(w.RemoteAddr(), m)
	if resp == nil {
		return
	}
	_ = w.WriteMsg(resp)
}

// ListenAndServe starts the UDP listener on addr (e.g. ":53").
//
// ListenAndServe is called on its own goroutine and Shutdown from whoever is
// stopping the controller, so the handle they share is written under the lock.
// Without that the two race on s.udp — and worse, Shutdown could read a nil
// handle a nanosecond before ListenAndServe set it, return nil, and leave a
// listener bound to :53 that nothing has a reference to any more. The next
// start then fails with "address already in use" from a process that believes
// it released the port.
func (s *Server) ListenAndServe(addr string) error {
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: s}
	s.mu.Lock()
	if s.shutdown {
		// Shutdown won the race. Do not bind: nothing will ever stop it.
		s.mu.Unlock()
		return nil
	}
	s.udp = srv
	s.mu.Unlock()
	return srv.ListenAndServe()
}

// Shutdown stops the listener. Safe to call before ListenAndServe, and more than
// once.
func (s *Server) Shutdown() error {
	s.mu.Lock()
	s.shutdown = true
	srv := s.udp
	s.udp = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown()
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
