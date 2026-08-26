package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/egress"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// TestNativeTunnelActuallyCarriesTraffic is the test this whole row exists for.
//
// The native path answered DNS, created sessions, counted traffic and produced a
// client config while moving nothing: the session manager reassembled upstream
// bytes into a buffer nothing drained, and nothing ever queued a downstream
// byte. TakeInbound and QueueOutbound — the two methods that exist for exactly
// this — had no callers outside their own tests. So the tunnel connected and
// then sat there, and only the upstream-BINARY adapters ever tunnelled.
//
// This drives real DNS queries end to end and asserts bytes reach a real socket
// and come back, which is the only claim that distinguishes a working tunnel
// from a well-tested one.
func TestNativeTunnelActuallyCarriesTraffic(t *testing.T) {
	// A destination that upper-cases whatever it is sent, so the reply is
	// distinguishable from an echo of the request.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var upstreamGot []byte
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				mu.Lock()
				upstreamGot = append(upstreamGot, buf[:n]...)
				mu.Unlock()
				out := make([]byte, n)
				for i := 0; i < n; i++ {
					ch := buf[i]
					if ch >= 'a' && ch <= 'z' {
						ch -= 32
					}
					out[i] = ch
				}
				c.Write(out)
			}
			if err != nil {
				return
			}
		}
	}()

	const zone = "t.example.com"
	const sid = 0x4242
	sess := session.NewManager(time.Minute)
	bridge := egress.New(sess, egress.TCPDialer(ln.Addr().String()), egress.Options{})
	defer bridge.Shutdown()

	srv := New()
	srv.AddZone(&Zone{Name: zone, Adapter: adapter.Forge{}, Sessions: sess, Egress: bridge})

	ask := func(f codec.Frame) *dns.Msg {
		t.Helper()
		q, err := adapter.EncodeQuery(zone, f)
		if err != nil {
			t.Fatal(err)
		}
		r := srv.Handle(q)
		if r == nil || r.Rcode != dns.RcodeSuccess {
			t.Fatalf("query not answered: %+v", r)
		}
		return r
	}

	ask(codec.Frame{SessionID: sid, Seq: 0, Flags: codec.FlagSYN})

	payload := []byte("hello through dns")
	// DATA starts at seq 0: the SYN resets nextSeqIn to 0, so a first DATA frame
	// numbered 1 sits in the reorder buffer waiting for a seq 0 that never comes.
	var seq uint16
	for off := 0; off < len(payload); off += 20 {
		end := min(off+20, len(payload))
		ask(codec.Frame{SessionID: sid, Seq: seq, Flags: codec.FlagDATA, Payload: payload[off:end]})
		seq++
	}

	// The bytes must reach the real socket.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := string(upstreamGot)
		mu.Unlock()
		if got == string(payload) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	got := string(upstreamGot)
	mu.Unlock()
	if got != string(payload) {
		t.Fatalf("the destination received %q, want %q — the tunnel is not carrying traffic upstream", got, payload)
	}

	// And the reply must come back through DNS answers.
	var down []byte
	want := "HELLO THROUGH DNS"
	deadline = time.Now().Add(5 * time.Second)
	for len(down) < len(want) && time.Now().Before(deadline) {
		seq++
		r := ask(codec.Frame{SessionID: sid, Seq: seq, Flags: codec.FlagKA})
		f, err := adapter.DecodeAnswer(r)
		if err == nil && len(f.Payload) > 0 {
			down = append(down, f.Payload...)
			continue
		}
		time.Sleep(5 * time.Millisecond)
	}
	if string(down) != want {
		t.Fatalf("the client received %q, want %q — downstream bytes are not reaching the client", down, want)
	}
}

func TestAZoneWithNoEgressStillAnswersDNS(t *testing.T) {
	// nil Egress is a legitimate configuration: a zone served by an upstream
	// binary adapter tunnels in that process. It must not panic here.
	const zone = "t.example.com"
	sess := session.NewManager(time.Minute)
	srv := New()
	srv.AddZone(&Zone{Name: zone, Adapter: adapter.Forge{}, Sessions: sess})

	q, err := adapter.EncodeQuery(zone, codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagSYN})
	if err != nil {
		t.Fatal(err)
	}
	if r := srv.Handle(q); r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("a zone without egress stopped answering: %+v", r)
	}
}

// countingBridge records which session ids were delivered.
type countingBridge struct {
	mu  sync.Mutex
	ids []uint64
}

func (c *countingBridge) Deliver(_ context.Context, id uint64) {
	c.mu.Lock()
	c.ids = append(c.ids, id)
	c.mu.Unlock()
}

func (c *countingBridge) seen() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.ids...)
}

func TestARejectedFrameDeliversNothing(t *testing.T) {
	// A frame the session manager refuses (a v2 frame that fails its MAC, say)
	// must not reach the egress side. Delivering for it would let anyone who can
	// send a UDP packet open an upstream connection for a session id they do not
	// hold the key for.
	const zone = "t.example.com"
	// WithLegacy, not the struct field: Options.AllowLegacy has an unexported
	// "was it set" flag, so a plain `AllowLegacy: false` is indistinguishable
	// from the zero value and withDefaults turns it back ON. Setting the field
	// directly would have left legacy enabled and made this test assert nothing.
	sess := session.NewManagerWithOptions(session.Options{IdleTTL: time.Minute}.WithLegacy(false))
	cb := &countingBridge{}
	srv := New()
	srv.AddZone(&Zone{Name: zone, Adapter: adapter.Forge{}, Sessions: sess, Egress: cb})

	// A v1 frame, with legacy sessions turned off: Ingest returns a zero Frame.
	q, err := adapter.EncodeQuery(zone, codec.Frame{SessionID: 9, Seq: 1, Flags: codec.FlagDATA, Payload: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	srv.Handle(q)
	if got := cb.seen(); len(got) != 0 {
		t.Fatalf("a rejected frame was delivered for session(s) %v", got)
	}
}
