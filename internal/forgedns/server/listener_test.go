package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// captureWriter is a dns.ResponseWriter that records what the handler wrote, so
// ServeDNS can be exercised without a socket — including the case where the
// handler deliberately writes nothing.
type captureWriter struct {
	remote net.Addr

	mu   sync.Mutex
	msgs []*dns.Msg
}

func (w *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (w *captureWriter) RemoteAddr() net.Addr { return w.remote }

func (w *captureWriter) WriteMsg(m *dns.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, m)
	return nil
}

func (w *captureWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *captureWriter) Close() error                { return nil }
func (w *captureWriter) TsigStatus() error           { return nil }
func (w *captureWriter) TsigTimersOnly(bool)         {}
func (w *captureWriter) Hijack()                     {}

func (w *captureWriter) written() []*dns.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*dns.Msg, len(w.msgs))
	copy(out, w.msgs)
	return out
}

// --- ServeDNS -------------------------------------------------------------

// TestServeDNSWritesTheAnswer covers the dns.Handler entry point: it must pass
// the client address through (so rate limiting can key on it) and write the
// message Handle produced.
func TestServeDNSWritesTheAnswer(t *testing.T) {
	srv, _ := apexServer(t)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.30"), Port: 40000}}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
	srv.ServeDNS(w, m)

	got := w.written()
	if len(got) != 1 {
		t.Fatalf("ServeDNS wrote %d messages, want 1", len(got))
	}
	if got[0].Rcode != dns.RcodeSuccess || len(got[0].Answer) == 0 {
		t.Fatalf("ServeDNS wrote %v, want an authoritative SOA answer", got[0])
	}
	if _, ok := got[0].Answer[0].(*dns.SOA); !ok {
		t.Fatalf("answer is %T, want *dns.SOA", got[0].Answer[0])
	}
	if got[0].RecursionAvailable {
		t.Fatal("RA set on a socket-path answer: server advertises recursion")
	}
}

// TestServeDNSWritesNothingWhenRateLimited: a rate-limited response must not be
// emitted at all. Writing an empty or SERVFAIL message instead would still hand
// a spoofed source a packet aimed at its victim, which is the whole point of
// dropping it.
func TestServeDNSWritesNothingWhenRateLimited(t *testing.T) {
	srv, _ := apexServer(t)
	srv.SetRateLimit(RateLimit{Identical: 2, Errors: 2, Window: time.Minute})
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.31"), Port: 40000}}

	const asked = 10
	for i := 0; i < asked; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(apexZone), dns.TypeSOA)
		srv.ServeDNS(w, m)
	}

	got := w.written()
	if len(got) == 0 {
		t.Fatal("no response was ever written")
	}
	if len(got) >= asked {
		t.Fatalf("wrote %d of %d responses: rate limiting never dropped one", len(got), asked)
	}
	if c := srv.Counters(); c.RateLimited == 0 {
		t.Fatal("dropped responses were not counted")
	}
}

// TestServeDNSWritesNothingForAQuestionlessQuery guards the malformed-input path
// through the socket entry point: a query with no question section yields no
// response rather than a panic.
func TestServeDNSWritesNothingForAQuestionlessQuery(t *testing.T) {
	srv, _ := apexServer(t)
	w := &captureWriter{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.32"), Port: 40000}}

	srv.ServeDNS(w, new(dns.Msg))

	if got := w.written(); len(got) != 0 {
		t.Fatalf("questionless query produced %d responses, want 0", len(got))
	}
}

// --- Zones ----------------------------------------------------------------

// TestZonesSnapshot: the snapshot must report the normalised names AddZone
// stored, since that is what the panel shows and what matchZone compares.
func TestZonesSnapshot(t *testing.T) {
	srv := New()
	if got := srv.Zones(); len(got) != 0 {
		t.Fatalf("fresh server reports zones %v, want none", got)
	}

	srv.AddZone(&Zone{Name: "Tunnel.Example.COM.", Adapter: adapter.Forge{}})
	srv.AddZone(&Zone{Name: "b.example.net"})

	got := srv.Zones()
	if len(got) != 2 {
		t.Fatalf("Zones() = %v, want 2 entries", got)
	}
	if got[0] != "tunnel.example.com" {
		t.Fatalf("Zones()[0] = %q, want the lowercased, dot-stripped name", got[0])
	}
	if got[1] != "b.example.net" {
		t.Fatalf("Zones()[1] = %q", got[1])
	}
}

// --- listener lifecycle ---------------------------------------------------

// TestShutdownWithoutListenerIsNoError: Shutdown is called from the daemon's
// teardown path whether or not the listener ever started, so it must be safe on
// a server that never bound a socket.
func TestShutdownWithoutListenerIsNoError(t *testing.T) {
	if err := New().Shutdown(); err != nil {
		t.Fatalf("Shutdown on an unstarted server: %v", err)
	}
}

// TestListenAndServeReportsBindFailure: a bad bind must surface as an error to
// the caller rather than being swallowed, and the subsequent Shutdown must not
// panic on the half-built listener.
func TestListenAndServeReportsBindFailure(t *testing.T) {
	srv := New()
	srv.AddZone(&Zone{Name: apexZone, Adapter: adapter.Forge{}})

	if err := srv.ListenAndServe("127.0.0.1:99999"); err == nil {
		t.Fatal("ListenAndServe on an invalid port returned nil error")
	}
	// The dns.Server exists but never started; Shutdown reports that rather
	// than dereferencing a nil listener.
	if err := srv.Shutdown(); err == nil {
		t.Fatal("Shutdown of a listener that never started returned nil error")
	}
}

// freeUDPAddr reserves an ephemeral UDP port on the loopback interface and
// releases it, so the listener under test binds a port the OS just handed out
// rather than a hard-coded one.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback UDP port: %v", err)
	}
	addr := pc.LocalAddr().String()
	if err := pc.Close(); err != nil {
		t.Fatalf("release loopback UDP port: %v", err)
	}
	return addr
}

// TestListenAndServeUDPRoundTrip is the socket-level lifecycle test: bind a real
// UDP listener on loopback, push a genuine tunnel frame through it, confirm the
// answer decodes and the session manager reassembled the bytes, then shut the
// listener down and confirm ListenAndServe returns.
func TestListenAndServeUDPRoundTrip(t *testing.T) {
	sess := session.NewManager(time.Minute)
	srv := New()
	srv.AddZone(&Zone{
		Name: apexZone, Adapter: adapter.Forge{}, Sessions: sess,
		Addrs: []net.IP{net.ParseIP("203.0.113.10")},
	})

	addr := freeUDPAddr(t)
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe(addr) }()

	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}

	const sid = 0x4242
	const payload = "bytes that crossed a real socket"
	query, err := adapter.EncodeQuery(apexZone, codec.Frame{
		SessionID: sid, Seq: 0, Flags: codec.FlagDATA, Payload: []byte(payload),
	})
	if err != nil {
		t.Fatalf("encode tunnel query: %v", err)
	}

	// Poll until the listener is up rather than sleeping a guessed interval.
	var resp *dns.Msg
	deadline := time.Now().Add(10 * time.Second)
	for resp == nil {
		select {
		case err := <-served:
			t.Fatalf("ListenAndServe(%s) returned before serving: %v", addr, err)
		default:
		}
		r, _, err := client.Exchange(query, addr)
		if err == nil {
			resp = r
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener on %s never answered: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative {
		t.Fatalf("tunnel query over UDP got %v, want an authoritative NOERROR", resp)
	}
	frame, err := adapter.DecodeAnswer(resp)
	if err != nil {
		t.Fatalf("answer over UDP is not a tunnel frame: %v", err)
	}
	if frame.SessionID != sid {
		t.Fatalf("answer frame session %#x, want %#x", frame.SessionID, sid)
	}
	if got := string(sess.TakeInbound(sid)); got != payload {
		t.Fatalf("upstream bytes over UDP: got %q, want %q", got, payload)
	}

	// A name we hold no authority over is REFUSED over the wire too. Reading
	// Counters afterwards is also what orders this goroutine behind the
	// handler goroutine that bumped it, and therefore behind the listener
	// goroutine that published the dns.Server that Shutdown below reads.
	foreign := new(dns.Msg)
	foreign.SetQuestion("example.net.", dns.TypeA)
	fr, _, err := client.Exchange(foreign, addr)
	if err != nil {
		t.Fatalf("foreign-zone query over UDP: %v", err)
	}
	if fr.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone over UDP got %s, want REFUSED", dns.RcodeToString[fr.Rcode])
	}
	if c := srv.Counters(); c.Refused == 0 {
		t.Fatal("REFUSED responses served over the socket were not counted")
	}

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v after Shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}
