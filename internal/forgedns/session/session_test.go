package session

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
)

// poll builds a legacy (non-extended) client poll frame.
func poll(sid uint16, seq uint16) codec.Frame {
	return codec.Frame{SessionID: sid, Seq: seq, Flags: codec.FlagKA}
}

// --- 1. downstream retransmission must not lose data ----------------------

// TestDroppedResponseIsRetransmitted is the headline regression: DNS over UDP is
// unreliable, so when a downstream answer is lost the client repeats the exact
// same query. The server must replay the same unacknowledged chunk instead of
// moving on to the next one, which would drop bytes on the floor permanently.
func TestDroppedResponseIsRetransmitted(t *testing.T) {
	m := NewManager(time.Minute)
	want := []byte("HTTP/1.1 200 OK\r\n\r\nthe body the client must not lose")
	m.QueueOutbound(1, want)

	q := poll(1, 7)
	first := m.Ingest(q) // this answer is "dropped" in transit
	if len(first.Payload) == 0 {
		t.Fatal("first poll returned no downstream data")
	}
	again := m.Ingest(q) // client repeats the identical query

	if !bytes.Equal(first.Payload, again.Payload) {
		t.Fatalf("retransmission lost data:\n first %q\n again %q", first.Payload, again.Payload)
	}
	if first.Seq != again.Seq {
		t.Fatalf("retransmission changed seq: %d then %d", first.Seq, again.Seq)
	}
}

// TestNoByteIsLostAcrossAChunkedStreamWithLoss drives a multi-chunk stream where
// every other response is dropped, and requires byte-perfect reconstruction.
func TestNoByteIsLostAcrossAChunkedStreamWithLoss(t *testing.T) {
	m := NewManager(time.Minute)
	var want []byte
	for i := 0; i < 4000; i++ {
		want = append(want, byte('a'+i%26))
	}
	m.QueueOutbound(1, want)

	var got []byte
	var seq uint16
	drop := true
	for i := 0; i < 500 && len(got) < len(want); i++ {
		r := m.Ingest(poll(1, seq))
		if len(r.Payload) == 0 {
			break
		}
		if drop {
			// Response lost: do not consume it and do not advance the request
			// seq, so the next poll is a genuine retransmission request.
			drop = false
			continue
		}
		got = append(got, r.Payload...)
		drop = true
		seq++ // client moved on, which implicitly acknowledges the chunk
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("stream corrupted under loss: got %d bytes, want %d", len(got), len(want))
	}
}

// TestAcknowledgedChunkAdvancesExactlyOnce ensures a committed chunk is not
// re-sent and not skipped.
func TestAcknowledgedChunkAdvancesExactlyOnce(t *testing.T) {
	m := NewManager(time.Minute)
	m.QueueOutbound(1, bytes.Repeat([]byte("A"), 220))
	m.QueueOutbound(1, bytes.Repeat([]byte("B"), 220))

	first := m.Ingest(poll(1, 0))
	if !bytes.Equal(first.Payload, bytes.Repeat([]byte("A"), 220)) {
		t.Fatalf("unexpected first chunk %q", first.Payload)
	}
	second := m.Ingest(poll(1, 1)) // new request seq acknowledges the first chunk
	if !bytes.Equal(second.Payload, bytes.Repeat([]byte("B"), 220)) {
		t.Fatalf("second chunk wrong: %q", second.Payload)
	}
	third := m.Ingest(poll(1, 2))
	if len(third.Payload) != 0 {
		t.Fatalf("expected no more data, got %q", third.Payload)
	}
}

// TestDownBytesCountedOnce guards against double accounting: a replayed
// chunk must not be billed twice.
func TestDownBytesCountedOnce(t *testing.T) {
	m := NewManager(time.Minute)
	m.QueueOutbound(1, bytes.Repeat([]byte("x"), 100))

	m.Ingest(poll(1, 0))
	m.Ingest(poll(1, 0)) // retransmit
	m.Ingest(poll(1, 0)) // retransmit
	m.Ingest(poll(1, 1)) // ack

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 session, got %d", len(snap))
	}
	if snap[0].DownBytes != 100 {
		t.Fatalf("DownBytes double-counted: got %d want 100", snap[0].DownBytes)
	}
}

// TestConcurrentDuplicatesDoNotDoubleAdvance runs the same retransmission
// concurrently; exactly one chunk may be in flight and no bytes may vanish.
func TestConcurrentDuplicatesDoNotDoubleAdvance(t *testing.T) {
	m := NewManager(time.Minute)
	m.QueueOutbound(1, bytes.Repeat([]byte("z"), 2200))

	var wg sync.WaitGroup
	seen := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := m.Ingest(poll(1, 0))
			seen[i] = append([]byte(nil), r.Payload...)
		}(i)
	}
	wg.Wait()
	for i, s := range seen {
		if !bytes.Equal(s, seen[0]) {
			t.Fatalf("concurrent duplicates diverged at %d: %q vs %q", i, s, seen[0])
		}
	}
}

// --- upstream de-duplication ---------------------------------------------

// TestDuplicateUpstreamFrameNotDoubleCounted: a retransmitted client DATA frame
// must not be counted twice nor re-injected into the reassembly stream.
func TestDuplicateUpstreamFrameNotDoubleCounted(t *testing.T) {
	m := NewManager(time.Minute)
	f := codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("hello")}
	m.Ingest(f)
	m.Ingest(f) // duplicate

	if got := m.TakeInbound(1); !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("duplicate upstream frame corrupted reassembly: %q", got)
	}
	if snap := m.Snapshot(); snap[0].UpBytes != 5 {
		t.Fatalf("UpBytes double-counted: %d want 5", snap[0].UpBytes)
	}
}

// TestStaleUpstreamSeqDoesNotLeak: a frame whose sequence was already consumed
// must be dropped, not parked in the reorder buffer forever.
func TestStaleUpstreamSeqDoesNotLeak(t *testing.T) {
	m := NewManager(time.Minute)
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("a")})
	m.Ingest(codec.Frame{SessionID: 1, Seq: 1, Flags: codec.FlagDATA, Payload: []byte("b")})
	m.TakeInbound(1)
	// Replay of an already-consumed sequence.
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("a")})

	if n := m.PendingReorder(1); n != 0 {
		t.Fatalf("stale seq leaked into reorder buffer: %d entries", n)
	}
	if got := m.TakeInbound(1); len(got) != 0 {
		t.Fatalf("stale seq re-injected %q into the stream", got)
	}
}

// --- 2. session integrity -------------------------------------------------

// TestExtendedSessionRequiresValidMAC: over an unauthenticated, source-spoofable
// transport, a third party must not be able to fetch another session's buffered
// chunk by guessing its id.
func TestExtendedSessionRequiresValidMAC(t *testing.T) {
	m := NewManager(time.Minute)

	// Handshake: client asks for an authenticated session.
	synResp := m.Ingest(codec.Frame{Flags: codec.FlagSYN | codec.FlagEXT, Ext: &codec.FrameExt{}})
	id, key, err := codec.ParseHandshake(synResp)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if id < 1<<16 {
		t.Fatalf("session id %d has too little entropy / collides with legacy space", id)
	}

	secret := []byte("downstream bytes for the legitimate client only")
	m.QueueOutbound(id, secret)

	// Attacker knows the id (or guessed it) but not the key.
	forged := codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: 1,
		Ext: &codec.FrameExt{SessionID: id}}
	if r := m.Ingest(forged); len(r.Payload) > 0 {
		t.Fatalf("unauthenticated frame retrieved buffered data: %q", r.Payload)
	}

	// The real client, holding the key, gets it.
	good := codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: 1,
		Ext: &codec.FrameExt{SessionID: id}}
	codec.SignFrame(&good, key)
	if r := m.Ingest(good); !bytes.Equal(r.Payload, secret) {
		t.Fatalf("authenticated client did not get its data: %q", r.Payload)
	}
}

// TestForgedAckCannotDiscardAnotherSessionsChunk: an unauthenticated ack must not
// advance (and therefore destroy) a chunk the real client has not received.
func TestForgedAckCannotDiscardAnotherSessionsChunk(t *testing.T) {
	m := NewManager(time.Minute)
	synResp := m.Ingest(codec.Frame{Flags: codec.FlagSYN | codec.FlagEXT, Ext: &codec.FrameExt{}})
	id, key, _ := codec.ParseHandshake(synResp)

	want := []byte("chunk that must survive a forged ack")
	m.QueueOutbound(id, want)

	first := codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: 1, Ext: &codec.FrameExt{SessionID: id}}
	codec.SignFrame(&first, key)
	got := m.Ingest(first)
	if !bytes.Equal(got.Payload, want) {
		t.Fatalf("setup: client did not receive chunk")
	}

	// Attacker forges an ack for that sequence without the key.
	forgedAck := codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: 2,
		Ext: &codec.FrameExt{SessionID: id, AckSeq: got.Seq, HasAck: true}}
	m.Ingest(forgedAck)

	// The real client retransmits; it must still get its chunk.
	retry := codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: 1, Ext: &codec.FrameExt{SessionID: id}}
	codec.SignFrame(&retry, key)
	if r := m.Ingest(retry); !bytes.Equal(r.Payload, want) {
		t.Fatalf("forged ack destroyed the in-flight chunk: %q", r.Payload)
	}
}

// TestAuthFailureDoesNotCreateSessionState: rejected frames must be dropped
// before any session is allocated, so forged ids cannot fill the session table.
func TestAuthFailureDoesNotCreateSessionState(t *testing.T) {
	m := NewManager(time.Minute)
	for i := 0; i < 500; i++ {
		m.Ingest(codec.Frame{Flags: codec.FlagKA | codec.FlagEXT, Seq: uint16(i),
			Ext: &codec.FrameExt{SessionID: uint64(1<<16 + i)}})
	}
	if n := m.Count(); n != 0 {
		t.Fatalf("forged frames created %d sessions", n)
	}
	if c := m.Counters(); c.AuthFailures == 0 {
		t.Fatal("auth failures not counted")
	}
}

// TestSessionTableIsBounded: a flood of unknown legacy ids must not grow the
// table without limit.
func TestSessionTableIsBounded(t *testing.T) {
	m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxSessions: 64})
	for i := 0; i < 5000; i++ {
		m.Ingest(poll(uint16(i), 0))
	}
	if n := m.Count(); n > 64 {
		t.Fatalf("session table unbounded: %d sessions (cap 64)", n)
	}
	if c := m.Counters(); c.SessionsRejected == 0 {
		t.Fatal("session-table pressure not counted")
	}
}

// TestPerSessionOutboundIsBounded: queued downstream bytes must be capped so a
// stalled client cannot pin unbounded memory.
func TestPerSessionOutboundIsBounded(t *testing.T) {
	m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxOutboundBytes: 1024})
	for i := 0; i < 100; i++ {
		m.QueueOutbound(1, bytes.Repeat([]byte("q"), 256))
	}
	if p := m.PendingOutbound(1); p > 1024 {
		t.Fatalf("outbound buffer unbounded: %d bytes (cap 1024)", p)
	}
	if c := m.Counters(); c.OutboundDropped == 0 {
		t.Fatal("dropped outbound bytes not counted")
	}
}

// TestInFlightExpires: an abandoned in-flight chunk must not pin memory forever.
func TestInFlightExpires(t *testing.T) {
	now := time.Now()
	m := NewManagerWithOptions(Options{IdleTTL: time.Hour, InFlightTTL: time.Second})
	m.SetClock(func() time.Time { return now })
	m.QueueOutbound(1, []byte("payload"))
	m.Ingest(poll(1, 0))

	now = now.Add(2 * time.Second)
	if n := m.ExpireInFlight(); n != 1 {
		t.Fatalf("expected 1 expired in-flight chunk, got %d", n)
	}
	if c := m.Counters(); c.ExpiredFrames == 0 {
		t.Fatal("expired frames not counted")
	}
}

// TestRetransmitAndDuplicateCounters checks the observability the fix is
// supposed to add.
func TestRetransmitAndDuplicateCounters(t *testing.T) {
	m := NewManager(time.Minute)
	m.QueueOutbound(1, bytes.Repeat([]byte("m"), 50))
	m.Ingest(poll(1, 0))
	m.Ingest(poll(1, 0))
	m.Ingest(poll(1, 0))

	c := m.Counters()
	if c.Retransmits < 2 {
		t.Fatalf("retransmits not counted: %d", c.Retransmits)
	}
	if c.DuplicateQueries < 2 {
		t.Fatalf("duplicate queries not counted: %d", c.DuplicateQueries)
	}
}
