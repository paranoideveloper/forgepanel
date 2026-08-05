package server

import (
	"bytes"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// TestForgeDNSTunnelEndToEnd is the §5 integration test: a synthetic client
// tunnels real bytes upstream through the DNS server (SYN + DATA frames encoded
// as base32 QNAMEs), the server reassembles them in order, and queued downstream
// bytes come back in the TXT answers — with correct per-session accounting.
func TestForgeDNSTunnelEndToEnd(t *testing.T) {
	zone := "t.example.com"
	sess := session.NewManager(time.Minute)
	srv := New()
	srv.AddZone(&Zone{Name: zone, Adapter: adapter.Forge{}, Sessions: sess})

	const sid = 0x1234
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" +
		"…arbitrary tunneled application bytes, long enough to span several DNS queries…")

	// Client sends SYN then DATA frames of <=30 bytes each (base32 blows up ~1.6x,
	// still well within one QNAME).
	syn := codec.Frame{SessionID: sid, Seq: 0, Flags: codec.FlagSYN}
	qm, err := adapter.EncodeQuery(zone, syn)
	if err != nil {
		t.Fatal(err)
	}
	if r := srv.Handle(qm); r == nil || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("SYN not answered: %+v", r)
	}

	var seq uint16 = 0
	for off := 0; off < len(payload); off += 30 {
		end := off + 30
		if end > len(payload) {
			end = len(payload)
		}
		f := codec.Frame{SessionID: sid, Seq: seq, Flags: codec.FlagDATA, Payload: payload[off:end]}
		q, err := adapter.EncodeQuery(zone, f)
		if err != nil {
			t.Fatal(err)
		}
		resp := srv.Handle(q)
		if resp == nil || resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("DATA seq %d not answered", seq)
		}
		if _, err := adapter.DecodeAnswer(resp); err != nil {
			t.Fatalf("cannot decode answer frame: %v", err)
		}
		seq++
	}

	// Server must have reassembled the exact upstream bytes, in order.
	got := sess.TakeInbound(sid)
	if !bytes.Equal(got, payload) {
		t.Fatalf("upstream reassembly mismatch:\n got %q\nwant %q", got, payload)
	}

	// Now queue downstream bytes and confirm they come back via a poll (KA frame).
	down := []byte("HTTP/1.1 200 OK\r\n\r\nhello from the origin")
	sess.QueueOutbound(sid, down)
	var recv []byte
	for i := 0; i < 20 && len(recv) < len(down); i++ {
		ka := codec.Frame{SessionID: sid, Seq: seq, Flags: codec.FlagKA}
		seq++
		q, _ := adapter.EncodeQuery(zone, ka)
		resp := srv.Handle(q)
		fr, err := adapter.DecodeAnswer(resp)
		if err != nil {
			t.Fatal(err)
		}
		recv = append(recv, fr.Payload...)
	}
	if !bytes.Equal(recv, down) {
		t.Fatalf("downstream mismatch:\n got %q\nwant %q", recv, down)
	}

	// Accounting must reflect the transfer.
	m := sess.Snapshot()
	if len(m) != 1 || m[0].UpBytes != int64(len(payload)) || m[0].DownBytes != int64(len(down)) {
		t.Fatalf("bad accounting: %+v", m)
	}
	t.Logf("tunneled %d up / %d down bytes through DNS, reassembled correctly", m[0].UpBytes, m[0].DownBytes)
}

func TestServerRefusesForeignZoneAndANY(t *testing.T) {
	srv := New()
	srv.AddZone(&Zone{Name: "t.example.com", Adapter: adapter.Forge{}})

	// A name outside our zones gets REFUSED rather than NXDOMAIN: we hold no
	// authority over it, so claiming it does not exist would be a lie, and
	// REFUSED is the smaller answer for an unsolicited spoofed query.
	foreign := new(dns.Msg)
	foreign.SetQuestion("google.com.", dns.TypeTXT)
	if r := srv.Handle(foreign); r == nil || r.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone must get REFUSED, got %+v", r)
	}
	// ANY is answered minimally per RFC 8482 instead of being expanded, which is
	// what stops it being an amplification lever.
	any := new(dns.Msg)
	any.SetQuestion("t.example.com.", dns.TypeANY)
	r := srv.Handle(any)
	if r == nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("ANY query must get a minimal RFC 8482 answer, got %+v", r)
	}
	if _, ok := r.Answer[0].(*dns.HINFO); !ok {
		t.Fatalf("ANY answer is %T, want *dns.HINFO", r.Answer[0])
	}
}

func TestEvictIdle(t *testing.T) {
	sess := session.NewManager(time.Millisecond)
	sess.QueueOutbound(1, []byte("x"))
	time.Sleep(5 * time.Millisecond)
	if n := sess.EvictIdle(); n != 1 {
		t.Fatalf("expected 1 eviction, got %d", n)
	}
}
