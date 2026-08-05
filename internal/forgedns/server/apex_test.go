package server

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

const apexZone = "tunnel.example.com"

func apexServer(t *testing.T) (*Server, *session.Manager) {
	t.Helper()
	sess := session.NewManager(0)
	srv := New()
	srv.AddZone(&Zone{
		Name: apexZone, Adapter: adapter.Forge{}, Sessions: sess,
		NS:    []string{"ns1." + apexZone, "ns2." + apexZone},
		Addrs: []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")},
	})
	return srv, sess
}

func ask(srv *Server, name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	return srv.Handle(m)
}

// --- 3. apex queries are authoritative DNS, not malformed frames ----------

// TestApexQueriesAreAnswered is the headline regression: a query for the zone
// apex carries no encoded payload, so it must never reach the frame decoder.
// Before the fix every one of these returned NXDOMAIN, which is why NS
// delegation and ordinary monitoring of the zone could not work.
func TestApexQueriesAreAnswered(t *testing.T) {
	srv, _ := apexServer(t)

	for _, tc := range []struct {
		qt   uint16
		want string
	}{
		{dns.TypeSOA, "SOA"},
		{dns.TypeNS, "NS"},
		{dns.TypeA, "A"},
		{dns.TypeAAAA, "AAAA"},
	} {
		r := ask(srv, apexZone, tc.qt)
		if r == nil {
			t.Fatalf("%s: nil response", tc.want)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: rcode %s, want NOERROR", tc.want, dns.RcodeToString[r.Rcode])
		}
		if len(r.Answer) == 0 {
			t.Fatalf("%s: no answer records", tc.want)
		}
		if !r.Authoritative {
			t.Fatalf("%s: AA bit not set", tc.want)
		}
	}
}

// TestApexUnsupportedTypeIsNoDataNotNXDOMAIN: the name exists, so a type we do
// not serve must be NOERROR with an empty answer and a SOA in authority.
func TestApexUnsupportedTypeIsNoDataNotNXDOMAIN(t *testing.T) {
	srv, _ := apexServer(t)
	r := ask(srv, apexZone, dns.TypeMX)
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("MX at apex: want NOERROR/NODATA, got %v", r)
	}
	if len(r.Answer) != 0 {
		t.Fatalf("MX at apex must have no answers, got %d", len(r.Answer))
	}
	if len(r.Ns) == 0 {
		t.Fatal("NODATA response must carry a SOA in the authority section")
	}
	if _, ok := r.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("authority record is %T, want *dns.SOA", r.Ns[0])
	}
}

// TestApexCaseAndTrailingDotNormalised covers resolvers that randomise case.
func TestApexCaseAndTrailingDotNormalised(t *testing.T) {
	srv, _ := apexServer(t)
	for _, name := range []string{
		apexZone, strings.ToUpper(apexZone), "TuNneL.ExAmPle.CoM", apexZone + ".",
	} {
		r := ask(srv, name, dns.TypeSOA)
		if r == nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
			t.Fatalf("%q: apex SOA not answered: %v", name, r)
		}
	}
}

// TestApexQueryCreatesNoSession: monitoring traffic must not allocate tunnel
// state, or a health check would be indistinguishable from a client.
func TestApexQueryCreatesNoSession(t *testing.T) {
	srv, sess := apexServer(t)
	for _, qt := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
		ask(srv, apexZone, qt)
	}
	if n := sess.Count(); n != 0 {
		t.Fatalf("apex queries created %d session(s)", n)
	}
}

// TestApexNeverReturnsTunnelData: an ordinary apex answer must not carry
// transport bytes.
func TestApexNeverReturnsTunnelData(t *testing.T) {
	srv, sess := apexServer(t)
	sess.QueueOutbound(0, []byte("downstream tunnel bytes"))
	r := ask(srv, apexZone, dns.TypeTXT)
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			joined := strings.Join(txt.Txt, "")
			if raw, err := codec.Base64Decode(joined); err == nil && len(raw) >= codec.FrameHeaderSize {
				t.Fatalf("apex TXT answer carried a tunnel frame: %q", joined)
			}
		}
	}
}

// --- tunnel path still works and still rejects bad frames ----------------

// TestEncodedSubdomainStillDecodes ensures the split did not break the tunnel.
func TestEncodedSubdomainStillDecodes(t *testing.T) {
	srv, sess := apexServer(t)
	f := codec.Frame{SessionID: 0x2222, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("tunnelled")}
	q, err := adapter.EncodeQuery(apexZone, f)
	if err != nil {
		t.Fatal(err)
	}
	r := srv.Handle(q)
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("encoded subdomain not answered: %v", r)
	}
	if _, err := adapter.DecodeAnswer(r); err != nil {
		t.Fatalf("answer is not a tunnel frame: %v", err)
	}
	if got := sess.TakeInbound(0x2222); string(got) != "tunnelled" {
		t.Fatalf("payload not reassembled: %q", got)
	}
}

// TestInvalidEncodedSubdomainIsProtocolError: garbage under the zone is a
// controlled error, not an apex answer and not a panic.
func TestInvalidEncodedSubdomainIsProtocolError(t *testing.T) {
	srv, sess := apexServer(t)
	for _, label := range []string{
		"!!!not-base32!!!",  // invalid alphabet
		"aaaa",              // valid base32, decodes shorter than a frame header
		"zzzzzzzzzzzzzzzzz", // valid alphabet, still too short a frame
	} {
		r := ask(srv, label+"."+apexZone, dns.TypeTXT)
		if r == nil {
			t.Fatalf("%q: nil response", label)
		}
		if r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
			t.Fatalf("%q: malformed frame produced a success answer", label)
		}
	}
	if n := sess.Count(); n != 0 {
		t.Fatalf("malformed frames created %d session(s)", n)
	}
}

// --- authoritative-server hardening --------------------------------------

// TestForeignZoneIsRefused: we are not authoritative for it, so claiming the
// name does not exist would be a lie — and REFUSED is the smaller answer.
func TestForeignZoneIsRefused(t *testing.T) {
	srv, _ := apexServer(t)
	r := ask(srv, "google.com", dns.TypeTXT)
	if r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone: want REFUSED, got %v", r)
	}
}

// TestNoRecursionOffered: RD must never produce RA, or the server advertises
// itself as an open resolver.
func TestNoRecursionOffered(t *testing.T) {
	srv, _ := apexServer(t)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(apexZone), dns.TypeA)
	m.RecursionDesired = true
	r := srv.Handle(m)
	if r == nil {
		t.Fatal("nil response")
	}
	if r.RecursionAvailable {
		t.Fatal("RA set: server advertises recursion")
	}
	if !r.Authoritative || len(r.Answer) == 0 {
		t.Fatal("RD query must still get the authoritative answer")
	}
}

// TestANYIsMinimalPerRFC8482: ANY must not expand into every record.
func TestANYIsMinimalPerRFC8482(t *testing.T) {
	srv, _ := apexServer(t)
	r := ask(srv, apexZone, dns.TypeANY)
	if r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("ANY: want NOERROR minimal response, got %v", r)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("ANY must return exactly one synthesised record, got %d", len(r.Answer))
	}
	if _, ok := r.Answer[0].(*dns.HINFO); !ok {
		t.Fatalf("ANY answer is %T, want *dns.HINFO per RFC 8482", r.Answer[0])
	}
}

// TestIdenticalQueriesAreRateLimited: response-rate limiting per client prefix.
func TestIdenticalQueriesAreRateLimited(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 5, Errors: 5, Window: time.Minute})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 5353}

	dropped := 0
	for i := 0; i < 50; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
		if r := srv.HandleFrom(src, m); r == nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("identical queries from one prefix were never rate limited")
	}
	if c := srv.Counters(); c.RateLimited == 0 {
		t.Fatal("rate-limited queries not counted")
	}
}

// TestErrorResponsesHaveTheirOwnBudget: NXDOMAIN/REFUSED floods are the classic
// reflection lever and must be limited separately from valid traffic.
func TestErrorResponsesHaveTheirOwnBudget(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 1000, Errors: 3, Window: time.Minute})
	src := &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5353}

	dropped := 0
	for i := 0; i < 30; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("nope.google.com"), dns.TypeA)
		if r := srv.HandleFrom(src, m); r == nil {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("error responses were never rate limited")
	}
}

// TestDifferentPrefixesHaveSeparateBudgets guards against one noisy client
// silencing the server for everyone.
func TestDifferentPrefixesHaveSeparateBudgets(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 3, Errors: 3, Window: time.Minute})

	noisy := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 53}
	for i := 0; i < 20; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
		srv.HandleFrom(noisy, m)
	}
	quiet := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 53}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
	if r := srv.HandleFrom(quiet, m); r == nil {
		t.Fatal("an unrelated client was starved by another prefix's budget")
	}
}

// TestOversizedAnswerTruncatesRatherThanAmplifying: a response that will not fit
// the client's UDP budget must set TC so the client retries over TCP, rather
// than being emitted as a large UDP datagram a spoofed source could aim at a
// victim.
func TestOversizedAnswerTruncatesRatherThanAmplifying(t *testing.T) {
	// A zone with many nameservers produces an NS answer well over 512 bytes.
	var ns []string
	for i := 0; i < 40; i++ {
		ns = append(ns, fmt.Sprintf("ns%02d.a-rather-long-nameserver-name.%s", i, apexZone))
	}
	srv := New()
	srv.AddZone(&Zone{Name: apexZone, Adapter: adapter.Forge{}, NS: ns})

	big := new(dns.Msg)
	big.SetQuestion(dns.Fqdn(apexZone), dns.TypeNS)
	big.SetEdns0(512, false) // client advertises a small buffer
	r := srv.Handle(big)
	if r == nil {
		t.Fatal("nil response")
	}
	if !r.Truncated {
		t.Fatalf("response of %d bytes was not truncated for a 512-byte client", r.Len())
	}
	if len(r.Answer) != 0 {
		t.Fatal("a truncated response must not still carry the oversized answer")
	}
	if r.Len() > 512 {
		t.Fatalf("truncated response is still %d bytes", r.Len())
	}
	if c := srv.Counters(); c.Truncated == 0 {
		t.Fatal("truncated responses not counted")
	}
}

// TestAdvertisedUDPSizeIsCapped: we must not echo a huge EDNS0 buffer back, as
// that is what makes an amplifier.
func TestAdvertisedUDPSizeIsCapped(t *testing.T) {
	srv, _ := apexServer(t)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
	m.SetEdns0(4096, false)
	r := srv.Handle(m)
	if r == nil {
		t.Fatal("nil response")
	}
	if opt := r.IsEdns0(); opt != nil && opt.UDPSize() > maxAdvertisedUDP {
		t.Fatalf("advertised UDP size %d exceeds the %d cap", opt.UDPSize(), maxAdvertisedUDP)
	}
}
