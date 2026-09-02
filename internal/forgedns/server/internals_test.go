package server

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// --- malformed input ------------------------------------------------------

// TestQuestionlessQueryIsDropped: a DNS message with an empty question section
// is not a question we can answer, and answering it would make the server a
// one-packet-in/one-packet-out reflector for the cheapest possible query.
func TestQuestionlessQueryIsDropped(t *testing.T) {
	srv, _ := apexServer(t)
	if r := srv.Handle(new(dns.Msg)); r != nil {
		t.Fatalf("questionless query produced %v, want a drop", r)
	}
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.40"), Port: 53}
	if r := srv.HandleFrom(src, new(dns.Msg)); r != nil {
		t.Fatalf("questionless query from %v produced %v, want a drop", src, r)
	}
}

// TestFinishDropsANilResponse: finish is the single choke point every answer
// passes through, and it dereferences the response for EDNS0, truncation and
// rate limiting. It must stay total for a handler that decides to answer
// nothing, so a future adapter returning no message drops the query instead of
// panicking the listener.
func TestFinishDropsANilResponse(t *testing.T) {
	srv, _ := apexServer(t)
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)

	if got := srv.finish(nil, q, nil); got != nil {
		t.Fatalf("finish(nil response) = %v, want nil", got)
	}
}

// --- SERVFAIL ------------------------------------------------------------

// brokenEncoder decodes tunnel queries like the native adapter but always fails
// to build the answer, which is the only condition that makes the server emit
// SERVFAIL.
type brokenEncoder struct{ adapter.Forge }

func (brokenEncoder) Encode(string, *dns.Msg, codec.Frame) (*dns.Msg, error) {
	return nil, errors.New("adapter: cannot encode answer")
}

// TestAdapterEncodeFailureIsServfail: a frame the server understood but cannot
// answer is a server-side failure, so it must be SERVFAIL — not NXDOMAIN, which
// would poison resolver caches for a name that does exist, and not a silent
// drop, which would leave the client retrying blind.
func TestAdapterEncodeFailureIsServfail(t *testing.T) {
	sess := session.NewManager(time.Minute)
	srv := New()
	srv.AddZone(&Zone{Name: apexZone, Adapter: brokenEncoder{}, Sessions: sess})

	q, err := adapter.EncodeQuery(apexZone, codec.Frame{
		SessionID: 0x0777, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("payload"),
	})
	if err != nil {
		t.Fatalf("encode tunnel query: %v", err)
	}

	r := srv.Handle(q)
	if r == nil {
		t.Fatal("encode failure produced no response")
	}
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("encode failure got %s, want SERVFAIL", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("SERVFAIL carried %d answer records", len(r.Answer))
	}
}

// --- zone defaults --------------------------------------------------------

// TestDefaultNSUsesTheRegistrableDomain pins the rule the delegation wizard
// depends on: the advertised nameserver lives under the registrable domain, so
// a zone "tunnel.example.com" advertises "ns1.example.com" and never "ns1.com",
// which the operator could not create a glue record for.
func TestDefaultNSUsesTheRegistrableDomain(t *testing.T) {
	for _, tc := range []struct{ zone, want string }{
		{"tunnel.example.com", "ns1.example.com"},
		{"a.b.c.example.co.uk", "ns1.example.co.uk"},
		// No registrable domain can be derived from a single label, so the
		// zone name itself is the only honest answer.
		{"internal", "ns1.internal"},
	} {
		if got := defaultNS(tc.zone); got != tc.want {
			t.Fatalf("defaultNS(%q) = %q, want %q", tc.zone, got, tc.want)
		}
	}
}

// TestAddZoneFillsAuthoritativeDefaults: a zone registered with nothing but a
// name must still be delegatable and answerable, or the operator gets a zone
// that fails every SOA and NS probe.
func TestAddZoneFillsAuthoritativeDefaults(t *testing.T) {
	srv := New()
	z := &Zone{Name: "Bare.Example.COM."}
	srv.AddZone(z)

	if z.Name != "bare.example.com" {
		t.Fatalf("zone name %q was not normalised", z.Name)
	}
	if z.Sessions == nil {
		t.Fatal("zone got no session manager")
	}
	if len(z.NS) != 1 || z.NS[0] != "ns1.example.com" {
		t.Fatalf("zone NS = %v, want [ns1.example.com]", z.NS)
	}
	if z.Mbox != "hostmaster.bare.example.com" {
		t.Fatalf("zone Mbox = %q", z.Mbox)
	}
	if z.Serial != 1 || z.TTL != defaultTTL {
		t.Fatalf("zone serial/TTL = %d/%d, want 1/%d", z.Serial, z.TTL, defaultTTL)
	}

	// The defaults must actually answer: SOA at the apex, with the derived NS.
	r := ask(srv, z.Name, dns.TypeSOA)
	if r == nil || len(r.Answer) == 0 {
		t.Fatalf("defaulted zone did not answer its apex SOA: %v", r)
	}
	soa, ok := r.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("apex answer is %T, want *dns.SOA", r.Answer[0])
	}
	if soa.Ns != "ns1.example.com." {
		t.Fatalf("SOA MNAME = %q, want the derived nameserver", soa.Ns)
	}
}

// --- client prefix bucketing ---------------------------------------------

// textAddr is a net.Addr that is neither *net.UDPAddr nor *net.TCPAddr, which
// is what a decorated or proxied listener hands the handler.
type textAddr string

func (a textAddr) Network() string { return "test" }
func (a textAddr) String() string  { return string(a) }

// TestClientPrefixBucketsByNetwork: the limiter must key on the client's network
// rather than its exact address, or an attacker rotating the low bits of a
// spoofed source buys a fresh budget with every packet.
func TestClientPrefixBucketsByNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  net.Addr
		want string
	}{
		{"udp v4", &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53}, "198.51.100.0/24"},
		{"udp v4 other host", &net.UDPAddr{IP: net.ParseIP("198.51.100.200"), Port: 9}, "198.51.100.0/24"},
		{"tcp v4", &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 53}, "203.0.113.0/24"},
		{"udp v6", &net.UDPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 53}, "2001:db8:1:2::/64"},
		{"tcp v6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}, "2001:db8::/64"},
		{"opaque addr v4", textAddr("203.0.113.5:1234"), "203.0.113.0/24"},
		{"opaque addr v6", textAddr("[2001:db8::9]:1234"), "2001:db8::/64"},
		// Anything we cannot turn into an IP yields no bucket at all, which
		// allow() treats as "do not limit" rather than lumping every such
		// client into one shared budget.
		{"opaque addr without a port", textAddr("not-a-host-port"), ""},
		{"opaque addr that is not an IP", textAddr("example.com:53"), ""},
		{"udp with no ip", &net.UDPAddr{Port: 53}, ""},
	} {
		if got := clientPrefix(tc.src); got != tc.want {
			t.Fatalf("%s: clientPrefix(%v) = %q, want %q", tc.name, tc.src, got, tc.want)
		}
	}
}

// TestNeighboursInOnePrefixShareABudget is the property clientPrefix exists for:
// two addresses in the same /24 must not get independent budgets.
func TestNeighboursInOnePrefixShareABudget(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 4, Errors: 4, Window: time.Minute})

	dropped := 0
	for i := 0; i < 40; i++ {
		src := &net.UDPAddr{IP: net.IPv4(198, 51, 100, byte(i)), Port: 53}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
		if r := srv.HandleFrom(src, m); r == nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("rotating the low octet of the source address defeated rate limiting")
	}
}

// TestUnattributableClientIsNotLimited: when we cannot derive a prefix there is
// nothing to key a budget on, and sharing one bucket across every such client
// would let one of them silence the rest.
func TestUnattributableClientIsNotLimited(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 1, Errors: 1, Window: time.Minute})

	for i := 0; i < 20; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
		if r := srv.HandleFrom(textAddr("no-port-here"), m); r == nil {
			t.Fatalf("query %d from an unattributable client was dropped", i)
		}
	}
}

// --- response rate limiting ----------------------------------------------

// fixedClockRRL builds a limiter whose clock the test drives, so the window
// boundary is exercised exactly rather than by sleeping.
func fixedClockRRL(l RateLimit) (*rrl, func(time.Duration)) {
	r := newRRL(l)
	now := time.Unix(1700000000, 0).UTC()
	r.start = now
	r.now = func() time.Time { return now }
	return r, func(d time.Duration) { now = now.Add(d) }
}

func rrlQuestion() dns.Question {
	return dns.Question{Name: "a." + apexZone + ".", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
}

// TestRRLWindowRestoresBudget: the budget is per window, so a client that went
// quiet for a window must be served again. A limiter that never refilled would
// blackhole a legitimate resolver permanently after one burst.
func TestRRLWindowRestoresBudget(t *testing.T) {
	r, advance := fixedClockRRL(RateLimit{Identical: 2, Errors: 2, Window: time.Second})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53}
	q := rrlQuestion()

	for i := 0; i < 2; i++ {
		if !r.allow(src, q, dns.RcodeSuccess) {
			t.Fatalf("identical response %d was limited inside the budget", i)
		}
	}
	if r.allow(src, q, dns.RcodeSuccess) {
		t.Fatal("identical response over the budget was allowed")
	}

	advance(time.Second)
	if !r.allow(src, q, dns.RcodeSuccess) {
		t.Fatal("budget was not restored at the window boundary")
	}
}

// TestRRLErrorBudgetIsSeparate: NXDOMAIN/REFUSED floods are the classic
// reflection lever, so spending the error budget must not touch the budget for
// real answers, and vice versa.
func TestRRLErrorBudgetIsSeparate(t *testing.T) {
	r, _ := fixedClockRRL(RateLimit{Identical: 100, Errors: 2, Window: time.Minute})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.8"), Port: 53}
	q := rrlQuestion()

	for i := 0; i < 2; i++ {
		if !r.allow(src, q, dns.RcodeNameError) {
			t.Fatalf("error response %d was limited inside the budget", i)
		}
	}
	if r.allow(src, q, dns.RcodeRefused) {
		t.Fatal("error response over the budget was allowed")
	}
	// The success budget is untouched.
	if !r.allow(src, q, dns.RcodeSuccess) {
		t.Fatal("a real answer was refused because the error budget was spent")
	}
}

// TestRRLZeroBudgetDisablesLimiting documents the escape hatch: a non-positive
// budget means "unlimited", not "drop everything", so a misconfigured zero does
// not silently take the server off the air.
func TestRRLZeroBudgetDisablesLimiting(t *testing.T) {
	r, _ := fixedClockRRL(RateLimit{Identical: 0, Errors: 0, Window: time.Minute})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.11"), Port: 53}
	q := rrlQuestion()

	for i := 0; i < 100; i++ {
		if !r.allow(src, q, dns.RcodeSuccess) {
			t.Fatalf("success response %d dropped under an unlimited budget", i)
		}
		if !r.allow(src, q, dns.RcodeNameError) {
			t.Fatalf("error response %d dropped under an unlimited budget", i)
		}
	}
}

// TestNewRRLDefaultsTheWindow: a zero window would make every comparison against
// it trivially true, so it is normalised to one second.
func TestNewRRLDefaultsTheWindow(t *testing.T) {
	if got := newRRL(RateLimit{Identical: 5, Errors: 5}).limit.Window; got != time.Second {
		t.Fatalf("newRRL window = %v, want 1s", got)
	}
	if got := newRRL(RateLimit{Window: -time.Second}).limit.Window; got != time.Second {
		t.Fatalf("newRRL window for a negative input = %v, want 1s", got)
	}
	if got := newRRL(RateLimit{Window: time.Minute}).limit.Window; got != time.Minute {
		t.Fatalf("newRRL overrode an explicit window: %v", got)
	}
}

// TestRRLTableIsBounded: the limiter's own state must not be a memory-growth
// lever. An attacker rotating source prefixes faster than the window expires
// would otherwise grow the table without limit.
func TestRRLTableIsBounded(t *testing.T) {
	// A window long enough that only the size guard can reset the table.
	r, _ := fixedClockRRL(RateLimit{Identical: 1000, Errors: 1000, Window: time.Hour})
	q := rrlQuestion()

	for i := 0; i < maxRRLEntries+64; i++ {
		src := &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 53}
		r.allow(src, q, dns.RcodeSuccess)
	}

	r.mu.Lock()
	entries := len(r.ident) + len(r.errs)
	r.mu.Unlock()
	if entries > maxRRLEntries {
		t.Fatalf("limiter holds %d entries, above the %d cap", entries, maxRRLEntries)
	}
	if entries == 0 {
		t.Fatal("limiter reset its table and then tracked nothing")
	}
}

// TestNilLimiterAllows: SetRateLimit always installs a limiter, but allow is the
// gate every response passes through and must not panic on a zero-valued
// server.
func TestNilLimiterAllows(t *testing.T) {
	var r *rrl
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.12"), Port: 53}
	if !r.allow(src, rrlQuestion(), dns.RcodeSuccess) {
		t.Fatal("nil limiter denied a response")
	}
}

// --- zone matching --------------------------------------------------------

// TestLongestZoneSuffixWins: with nested zones registered, a name must be
// handled by the most specific one, or traffic for a delegated sub-zone is
// answered with the parent's adapter and session state.
func TestLongestZoneSuffixWins(t *testing.T) {
	srv := New()
	srv.AddZone(&Zone{Name: "example.com", Adapter: adapter.Forge{}})
	srv.AddZone(&Zone{Name: "deep.sub.example.com", Adapter: adapter.Forge{}})
	srv.AddZone(&Zone{Name: "sub.example.com", Adapter: adapter.Forge{}})

	for _, tc := range []struct{ qname, want string }{
		{"example.com.", "example.com"},
		{"host.example.com.", "example.com"},
		{"sub.example.com.", "sub.example.com"},
		{"x.deep.sub.example.com.", "deep.sub.example.com"},
		{"DEEP.SUB.EXAMPLE.COM.", "deep.sub.example.com"},
	} {
		z := srv.matchZone(tc.qname)
		if z == nil {
			t.Fatalf("%s matched no zone", tc.qname)
		}
		if z.Name != tc.want {
			t.Fatalf("%s matched zone %q, want %q", tc.qname, z.Name, tc.want)
		}
	}
	if z := srv.matchZone("notexample.com."); z != nil {
		t.Fatalf("notexample.com matched zone %q: suffix check is not label-aligned", z.Name)
	}
}

// TestZoneWithoutAdapterAnswersOrdinaryDNS: a zone registered for delegation
// only (no tunnel adapter) must still answer its apex and NXDOMAIN below it,
// rather than taking the tunnel path on a nil adapter.
func TestZoneWithoutAdapterAnswersOrdinaryDNS(t *testing.T) {
	srv := New()
	srv.AddZone(&Zone{Name: apexZone, Addrs: []net.IP{net.ParseIP("203.0.113.10")}})

	if r := ask(srv, apexZone, dns.TypeA); r == nil || len(r.Answer) == 0 {
		t.Fatalf("adapterless zone did not answer its apex A: %v", r)
	}
	r := ask(srv, fmt.Sprintf("anything.%s", apexZone), dns.TypeTXT)
	if r == nil || r.Rcode != dns.RcodeNameError {
		t.Fatalf("name under an adapterless zone got %v, want NXDOMAIN", r)
	}
	if len(r.Ns) == 0 {
		t.Fatal("NXDOMAIN must carry a SOA so resolvers can cache the negative answer")
	}
}
