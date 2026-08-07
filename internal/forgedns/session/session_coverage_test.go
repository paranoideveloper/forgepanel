package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
)

// handshake performs the v2 SYN exchange and returns the minted id and key.
func handshake(t *testing.T, m *Manager) (uint64, []byte) {
	t.Helper()
	resp := m.Ingest(codec.Frame{Flags: codec.FlagSYN | codec.FlagEXT, Ext: &codec.FrameExt{}})
	id, key, err := codec.ParseHandshake(resp)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	return id, key
}

// signed builds an authenticated v2 frame for a session.
func signed(id uint64, key []byte, seq uint16, flags uint8, ext codec.FrameExt) codec.Frame {
	ext.SessionID = id
	f := codec.Frame{Seq: seq, Flags: flags | codec.FlagEXT, Ext: &ext}
	codec.SignFrame(&f, key)
	return f
}

// TestAIMDWindow covers both directions of the congestion window, including the
// lower clamp that OnLoss must not undershoot.
func TestAIMDWindow(t *testing.T) {
	a := AIMD{Window: 4, Min: 1, Max: 6}
	a.OnACK()
	a.OnACK()
	if a.Window != 6 {
		t.Fatalf("window = %d, want 6", a.Window)
	}
	a.OnACK() // already at Max: must not grow past it
	if a.Window != 6 {
		t.Fatalf("window grew past Max: %d", a.Window)
	}
	a.OnLoss() // 3
	a.OnLoss() // 1
	if a.Window != 1 {
		t.Fatalf("window = %d, want 1 after two halvings", a.Window)
	}
	a.OnLoss() // 0 -> clamped back to Min
	if a.Window != 1 {
		t.Fatalf("OnLoss undershot Min: %d", a.Window)
	}

	// A Min above zero is honoured even from a small starting window.
	b := AIMD{Window: 3, Min: 2, Max: 8}
	b.OnLoss()
	if b.Window != 2 {
		t.Fatalf("window = %d, want the Min of 2", b.Window)
	}
}

// TestOptionsWithLegacy covers WithLegacy and proves the flag actually reaches
// the manager: the zero Options value accepts v1 frames, WithLegacy(false)
// rejects them and counts the rejection.
func TestOptionsWithLegacy(t *testing.T) {
	permissive := Options{}
	if permissive.legacySet {
		t.Fatal("the zero Options must not look explicitly set")
	}
	strict := permissive.WithLegacy(false)
	if strict.AllowLegacy || !strict.legacySet {
		t.Fatalf("WithLegacy(false) produced %+v", strict)
	}
	if permissive.legacySet {
		t.Fatal("WithLegacy must not mutate its receiver")
	}
	if on := permissive.WithLegacy(true); !on.AllowLegacy || !on.legacySet {
		t.Fatalf("WithLegacy(true) produced %+v", on)
	}

	// A default manager still serves v1 clients.
	def := NewManagerWithOptions(Options{IdleTTL: time.Minute})
	def.QueueOutbound(1, []byte("v1 payload"))
	if r := def.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA}); len(r.Payload) == 0 {
		t.Fatal("the default manager must still accept legacy frames")
	}

	// With legacy disabled the frame is dropped without creating any state.
	m := NewManagerWithOptions(Options{IdleTTL: time.Minute}.WithLegacy(false))
	got := m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
	if got.Flags != 0 || got.Payload != nil {
		t.Fatalf("a rejected legacy frame must yield an empty response, got %+v", got)
	}
	if n := m.Count(); n != 0 {
		t.Fatalf("a rejected legacy frame created %d sessions", n)
	}
	if c := m.Counters(); c.LegacyRejected != 1 {
		t.Fatalf("LegacyRejected = %d, want 1", c.LegacyRejected)
	}
	// Authenticated v2 frames still work on the same manager.
	id, key := handshake(t, m)
	m.QueueOutbound(id, []byte("v2 payload"))
	r := m.Ingest(signed(id, key, 1, codec.FlagKA, codec.FrameExt{}))
	if !bytes.Equal(r.Payload, []byte("v2 payload")) {
		t.Fatalf("v2 client was denied its data: %q", r.Payload)
	}
}

// TestIngestExtWithoutExtBlock covers the ext==nil rejection: FlagEXT is set but
// no extension block is present, which is a malformed frame.
func TestIngestExtWithoutExtBlock(t *testing.T) {
	m := NewManager(time.Minute)
	got := m.Ingest(codec.Frame{Flags: codec.FlagEXT | codec.FlagKA, Seq: 3})
	if got.Flags != 0 || got.Payload != nil {
		t.Fatalf("malformed extended frame must yield an empty response, got %+v", got)
	}
	if m.Count() != 0 {
		t.Fatal("a malformed frame must not create session state")
	}
	if c := m.Counters(); c.AuthFailures != 1 {
		t.Fatalf("AuthFailures = %d, want 1", c.AuthFailures)
	}
}

// TestHandshakeRejectedWhenTableFull covers the create-returned-nil branch of the
// handshake path: a full session table must refuse to mint a new session rather
// than exceeding its cap.
func TestHandshakeRejectedWhenTableFull(t *testing.T) {
	m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxSessions: 1})
	// Fill the single slot with a legacy session.
	m.Ingest(codec.Frame{SessionID: 7, Seq: 0, Flags: codec.FlagKA})
	if m.Count() != 1 {
		t.Fatalf("setup: want 1 session, got %d", m.Count())
	}

	resp := m.Ingest(codec.Frame{Flags: codec.FlagSYN | codec.FlagEXT, Ext: &codec.FrameExt{}})
	if resp.Flags != 0 || resp.Payload != nil {
		t.Fatalf("handshake must be refused when the table is full, got %+v", resp)
	}
	if n := m.Count(); n != 1 {
		t.Fatalf("session table grew past its cap: %d", n)
	}
	if c := m.Counters(); c.SessionsRejected == 0 {
		t.Fatal("the refused handshake was not counted")
	}
}

// TestExplicitAckWithWrongSequence covers the InvalidSequence branch: an
// authenticated client that acknowledges a sequence other than the one in flight
// must not commit the chunk.
func TestExplicitAckWithWrongSequence(t *testing.T) {
	m := NewManager(time.Minute)
	id, key := handshake(t, m)
	want := []byte("chunk awaiting the right acknowledgement")
	m.QueueOutbound(id, want)

	first := m.Ingest(signed(id, key, 1, codec.FlagKA, codec.FrameExt{}))
	if !bytes.Equal(first.Payload, want) {
		t.Fatalf("setup: client did not receive the chunk, got %q", first.Payload)
	}

	// The client acknowledges a sequence that is not in flight.
	bad := m.Ingest(signed(id, key, 2, codec.FlagKA, codec.FrameExt{AckSeq: first.Seq + 99, HasAck: true}))
	if !bytes.Equal(bad.Payload, want) {
		t.Fatalf("a mis-sequenced ack committed the chunk; got %q", bad.Payload)
	}
	if bad.Seq != first.Seq {
		t.Fatalf("sequence advanced on a bad ack: %d then %d", first.Seq, bad.Seq)
	}
	if c := m.Counters(); c.InvalidSequence == 0 {
		t.Fatal("the mis-sequenced ack was not counted")
	}

	// The correct ack does commit it.
	done := m.Ingest(signed(id, key, 3, codec.FlagKA, codec.FrameExt{AckSeq: first.Seq, HasAck: true}))
	if len(done.Payload) != 0 {
		t.Fatalf("a correct ack should drain the queue, got %q", done.Payload)
	}
	if p := m.PendingOutbound(id); p != 0 {
		t.Fatalf("queue still holds %d bytes after a valid ack", p)
	}
}

// TestReorderBufferIsBounded covers the MaxReorderFrames guard: out-of-order
// upstream frames beyond the cap are rejected instead of growing the buffer,
// yet the in-order head is always accepted so a full buffer cannot deadlock the
// stream on its own missing head.
func TestReorderBufferIsBounded(t *testing.T) {
	m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxReorderFrames: 2})
	// Sequence 0 is never sent, so nothing can be reassembled and the first two
	// frames park in the reorder buffer; the rest are refused by the cap.
	for seq := uint16(1); seq <= 5; seq++ {
		m.Ingest(codec.Frame{SessionID: 1, Seq: seq, Flags: codec.FlagDATA, Payload: []byte{byte(seq)}})
	}
	if n := m.PendingReorder(1); n != 2 {
		t.Fatalf("reorder buffer holds %d frames, want the cap of 2", n)
	}
	if c := m.Counters(); c.InvalidSequence == 0 {
		t.Fatal("frames rejected by the reorder cap were not counted")
	}
	if got := m.TakeInbound(1); got != nil {
		t.Fatalf("nothing should be reassembled yet, got %q", got)
	}

	// The missing HEAD (seq 0) must be accepted even though the buffer is full:
	// it drains immediately, shrinking the buffer rather than growing it. If the
	// cap rejected it, the session would stall forever on a head that can never
	// arrive because the frames behind it hold the buffer full. Regression guard
	// for the head-of-line-blocking bug fixed in session.go's DATA switch.
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte{0}})
	if got := m.TakeInbound(1); !bytes.Equal(got, []byte{0, 1, 2}) {
		t.Fatalf("full buffer must still accept the head and drain it, got %v", got)
	}
	if n := m.PendingReorder(1); n != 0 {
		t.Fatalf("head should have drained the buffer, %d entries remain", n)
	}

	// With room to spare, the arriving head likewise unblocks everything behind it.
	roomy := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxReorderFrames: 4})
	for seq := uint16(1); seq <= 2; seq++ {
		roomy.Ingest(codec.Frame{SessionID: 1, Seq: seq, Flags: codec.FlagDATA, Payload: []byte{byte(seq)}})
	}
	roomy.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte{0}})
	if got := roomy.TakeInbound(1); !bytes.Equal(got, []byte{0, 1, 2}) {
		t.Fatalf("reassembled %v, want [0 1 2]", got)
	}
	if n := roomy.PendingReorder(1); n != 0 {
		t.Fatalf("reorder buffer should be drained, %d entries remain", n)
	}
}

// TestDuplicateOutOfOrderFrameIsDropped covers the "already parked in the reorder
// buffer" branch, which is distinct from the already-consumed one.
func TestDuplicateOutOfOrderFrameIsDropped(t *testing.T) {
	m := NewManager(time.Minute)
	f := codec.Frame{SessionID: 1, Seq: 5, Flags: codec.FlagDATA, Payload: []byte("late")}
	m.Ingest(f)
	m.Ingest(f) // exact duplicate, still out of order

	if n := m.PendingReorder(1); n != 1 {
		t.Fatalf("duplicate parked twice: %d entries", n)
	}
	snap := m.Snapshot()
	if len(snap) != 1 || snap[0].UpBytes != 4 {
		t.Fatalf("duplicate out-of-order frame double-counted: %+v", snap)
	}
	if c := m.Counters(); c.StaleUpstream == 0 {
		t.Fatal("the duplicate was not counted as stale upstream")
	}
}

// TestKeepaliveResponseWhenIdle covers the keepalive branch of the response
// builder: with nothing queued, a KA poll is answered with a KA ack.
func TestKeepaliveResponseWhenIdle(t *testing.T) {
	m := NewManager(time.Minute)
	r := m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
	if !r.Has(codec.FlagKA) || !r.Has(codec.FlagACK) {
		t.Fatalf("idle keepalive answered with flags %#02x", r.Flags)
	}
	if r.Has(codec.FlagDATA) || len(r.Payload) != 0 {
		t.Fatalf("idle keepalive must carry no data, got %q", r.Payload)
	}
	if r.SessionID != 1 {
		t.Fatalf("legacy response must echo the 16-bit session id, got %d", r.SessionID)
	}

	// A non-keepalive poll with nothing queued gets a bare ack.
	plain := m.Ingest(codec.Frame{SessionID: 1, Seq: 1, Flags: 0})
	if plain.Has(codec.FlagKA) || plain.Has(codec.FlagDATA) {
		t.Fatalf("a plain poll must get a bare ack, got flags %#02x", plain.Flags)
	}
	if !plain.Has(codec.FlagACK) {
		t.Fatal("every response must carry an ack")
	}
}

// TestAuthenticatedResponseIsSigned proves v2 responses carry the extension block
// and a MAC the client can verify, while v1 responses carry neither.
func TestAuthenticatedResponseIsSigned(t *testing.T) {
	m := NewManager(time.Minute)
	id, key := handshake(t, m)
	r := m.Ingest(signed(id, key, 1, codec.FlagKA, codec.FrameExt{}))
	if r.Ext == nil || !r.Has(codec.FlagEXT) {
		t.Fatalf("authenticated response is missing its extension block: %+v", r)
	}
	if r.Ext.SessionID != id {
		t.Fatalf("response session id = %d, want %d", r.Ext.SessionID, id)
	}
	if !codec.VerifyFrame(r, key) {
		t.Fatal("the client cannot verify the server's response")
	}

	legacy := m.Ingest(codec.Frame{SessionID: 9, Seq: 0, Flags: codec.FlagKA})
	if legacy.Ext != nil || legacy.Has(codec.FlagEXT) {
		t.Fatalf("a legacy response must not carry an extension block: %+v", legacy)
	}
}

// TestSYNResetsReassembly covers the reassembly-reset branch: a client that
// re-SYNs mid-stream restarts its upstream sequence at zero.
func TestSYNResetsReassembly(t *testing.T) {
	m := NewManager(time.Minute)
	// Park an out-of-order frame.
	m.Ingest(codec.Frame{SessionID: 1, Seq: 4, Flags: codec.FlagDATA, Payload: []byte("orphan")})
	if m.PendingReorder(1) != 1 {
		t.Fatal("setup: frame was not parked")
	}
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagSYN})
	if n := m.PendingReorder(1); n != 0 {
		t.Fatalf("SYN did not clear the reorder buffer: %d entries", n)
	}
	// Sequence numbering restarts, so seq 0 is accepted again.
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("fresh")})
	if got := m.TakeInbound(1); !bytes.Equal(got, []byte("fresh")) {
		t.Fatalf("reassembly after SYN produced %q", got)
	}
}

// TestQueueOutboundBoundaries covers the queue-full branch, the partial-truncation
// branch and the create-failed branch of QueueOutbound.
func TestQueueOutboundBoundaries(t *testing.T) {
	t.Run("partial then full", func(t *testing.T) {
		m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxOutboundBytes: 10})
		m.QueueOutbound(1, []byte("1234"))
		if p := m.PendingOutbound(1); p != 4 {
			t.Fatalf("pending = %d, want 4", p)
		}
		// Only the first 6 bytes fit; the rest are dropped and counted.
		m.QueueOutbound(1, []byte("ABCDEFGHIJ"))
		if p := m.PendingOutbound(1); p != 10 {
			t.Fatalf("pending = %d, want the cap of 10", p)
		}
		if c := m.Counters(); c.OutboundDropped != 4 {
			t.Fatalf("OutboundDropped = %d, want 4", c.OutboundDropped)
		}
		// The queue is now exactly full: everything further is dropped whole.
		m.QueueOutbound(1, []byte("XYZ"))
		if p := m.PendingOutbound(1); p != 10 {
			t.Fatalf("pending grew past the cap: %d", p)
		}
		if c := m.Counters(); c.OutboundDropped != 7 {
			t.Fatalf("OutboundDropped = %d, want 7", c.OutboundDropped)
		}
		// And the bytes that did fit are the ones delivered, in order.
		r := m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
		if !bytes.Equal(r.Payload, []byte("1234ABCDEF")) {
			t.Fatalf("delivered %q, want %q", r.Payload, "1234ABCDEF")
		}
	})

	t.Run("session table full", func(t *testing.T) {
		m := NewManagerWithOptions(Options{IdleTTL: time.Minute, MaxSessions: 1})
		m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
		m.QueueOutbound(999, []byte("nowhere to go"))
		if n := m.Count(); n != 1 {
			t.Fatalf("QueueOutbound created a session past the cap: %d", n)
		}
		if c := m.Counters(); c.OutboundDropped != uint64(len("nowhere to go")) {
			t.Fatalf("OutboundDropped = %d, want %d", c.OutboundDropped, len("nowhere to go"))
		}
	})

	t.Run("creates a session on demand", func(t *testing.T) {
		m := NewManager(time.Minute)
		m.QueueOutbound(42, []byte("early"))
		if m.Count() != 1 {
			t.Fatalf("QueueOutbound should have created the session, got %d", m.Count())
		}
		if p := m.PendingOutbound(42); p != 5 {
			t.Fatalf("pending = %d, want 5", p)
		}
	})
}

// TestAccessorsOnUnknownSession covers the not-found returns of the read-only
// accessors.
func TestAccessorsOnUnknownSession(t *testing.T) {
	m := NewManager(time.Minute)
	if got := m.PendingOutbound(1234); got != 0 {
		t.Fatalf("PendingOutbound on an unknown session = %d", got)
	}
	if got := m.PendingReorder(1234); got != 0 {
		t.Fatalf("PendingReorder on an unknown session = %d", got)
	}
	if got := m.TakeInbound(1234); got != nil {
		t.Fatalf("TakeInbound on an unknown session = %q", got)
	}
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot of an empty manager = %+v", got)
	}
	if n := m.ExpireInFlight(); n != 0 {
		t.Fatalf("ExpireInFlight on an empty manager = %d", n)
	}
	if n := m.EvictIdle(); n != 0 {
		t.Fatalf("EvictIdle on an empty manager = %d", n)
	}

	// A live session with nothing reassembled also returns nil rather than an
	// empty non-nil slice.
	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
	if got := m.TakeInbound(1); got != nil {
		t.Fatalf("TakeInbound with nothing buffered = %q", got)
	}
}

// TestEvictIdle covers idle eviction, which had no test at all.
func TestEvictIdle(t *testing.T) {
	now := time.Now()
	m := NewManagerWithOptions(Options{IdleTTL: 30 * time.Second, InFlightTTL: time.Hour})
	m.SetClock(func() time.Time { return now })

	m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
	now = now.Add(20 * time.Second)
	m.Ingest(codec.Frame{SessionID: 2, Seq: 0, Flags: codec.FlagKA})
	if m.Count() != 2 {
		t.Fatalf("setup: want 2 sessions, got %d", m.Count())
	}

	// Nothing is old enough yet.
	if n := m.EvictIdle(); n != 0 {
		t.Fatalf("evicted %d sessions too early", n)
	}

	// Session 1 is now 40s idle, session 2 only 20s.
	now = now.Add(20 * time.Second)
	if n := m.EvictIdle(); n != 1 {
		t.Fatalf("evicted %d sessions, want 1", n)
	}
	if m.Count() != 1 {
		t.Fatalf("want 1 surviving session, got %d", m.Count())
	}
	if got := m.Snapshot(); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("the wrong session survived: %+v", got)
	}

	// Push past the TTL again and the last one goes too.
	now = now.Add(time.Minute)
	if n := m.EvictIdle(); n != 1 {
		t.Fatalf("evicted %d sessions, want 1", n)
	}
	if m.Count() != 0 {
		t.Fatalf("manager should be empty, got %d", m.Count())
	}
}

// TestSnapshotIsSortedAndPopulated covers the sort comparator (which needs at
// least two sessions) and every reported field.
func TestSnapshotIsSortedAndPopulated(t *testing.T) {
	now := time.Now()
	m := NewManagerWithOptions(Options{IdleTTL: time.Hour, InFlightTTL: time.Hour, ChunkSize: 8})
	m.SetClock(func() time.Time { return now })

	// Three legacy sessions created out of id order.
	for _, id := range []uint16{30, 10, 20} {
		m.Ingest(codec.Frame{SessionID: id, Seq: 0, Flags: codec.FlagDATA, Payload: []byte("up")})
	}
	m.QueueOutbound(10, []byte("downstream bytes"))
	now = now.Add(5 * time.Second)
	m.Ingest(codec.Frame{SessionID: 10, Seq: 1, Flags: codec.FlagKA})
	now = now.Add(2 * time.Second)

	snap := m.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("want 3 sessions, got %d", len(snap))
	}
	for i := 1; i < len(snap); i++ {
		if snap[i-1].ID >= snap[i].ID {
			t.Fatalf("snapshot is not sorted by id: %+v", snap)
		}
	}
	s := snap[0]
	if s.ID != 10 {
		t.Fatalf("first session id = %d, want 10", s.ID)
	}
	if s.UpBytes != 2 {
		t.Fatalf("UpBytes = %d, want 2", s.UpBytes)
	}
	if s.DownBytes != 8 {
		t.Fatalf("DownBytes = %d, want the 8-byte chunk size", s.DownBytes)
	}
	if s.InFlight != 8 {
		t.Fatalf("InFlight = %d, want 8", s.InFlight)
	}
	if s.Pending != len("downstream bytes") {
		t.Fatalf("Pending = %d, want %d (unacknowledged bytes stay queued)", s.Pending, len("downstream bytes"))
	}
	if s.Auth {
		t.Fatal("a legacy session must not report itself as authenticated")
	}
	if s.AgeMs != 7000 {
		t.Fatalf("AgeMs = %d, want 7000", s.AgeMs)
	}
	if s.IdleMs != 2000 {
		t.Fatalf("IdleMs = %d, want 2000", s.IdleMs)
	}
	if s.Window <= 0 {
		t.Fatalf("Window = %d, want a positive congestion window", s.Window)
	}

	// An authenticated session reports Auth.
	id, key := handshake(t, m)
	m.Ingest(signed(id, key, 1, codec.FlagKA, codec.FrameExt{}))
	for _, got := range m.Snapshot() {
		if got.ID == id && !got.Auth {
			t.Fatal("an authenticated session must report Auth")
		}
	}
}

// TestExpireInFlightHalvesWindowAndReplays proves an expired chunk is re-sent
// rather than lost, and that the congestion window reacts to the loss.
func TestExpireInFlightHalvesWindowAndReplays(t *testing.T) {
	now := time.Now()
	m := NewManagerWithOptions(Options{IdleTTL: time.Hour, InFlightTTL: time.Second})
	m.SetClock(func() time.Time { return now })

	want := []byte("bytes that must survive an expiry")
	m.QueueOutbound(1, want)
	first := m.Ingest(codec.Frame{SessionID: 1, Seq: 0, Flags: codec.FlagKA})
	if !bytes.Equal(first.Payload, want) {
		t.Fatalf("setup: got %q", first.Payload)
	}
	before := m.Snapshot()[0].Window

	now = now.Add(2 * time.Second)
	if n := m.ExpireInFlight(); n != 1 {
		t.Fatalf("expired %d chunks, want 1", n)
	}
	// Expiring twice must not double count: nothing is in flight any more.
	if n := m.ExpireInFlight(); n != 0 {
		t.Fatalf("expired %d chunks on the second pass, want 0", n)
	}
	after := m.Snapshot()[0].Window
	if after >= before {
		t.Fatalf("window did not shrink on loss: %d then %d", before, after)
	}
	if p := m.PendingOutbound(1); p != len(want) {
		t.Fatalf("expiry dropped queued bytes: %d of %d remain", p, len(want))
	}
	// The very next poll re-sends the same bytes.
	again := m.Ingest(codec.Frame{SessionID: 1, Seq: 1, Flags: codec.FlagKA})
	if !bytes.Equal(again.Payload, want) {
		t.Fatalf("expired chunk was not re-sent: %q", again.Payload)
	}
	if c := m.Counters(); c.ExpiredFrames != 1 {
		t.Fatalf("ExpiredFrames = %d, want 1", c.ExpiredFrames)
	}
}

// TestOptionsDefaults pins every default the zero Options value fills in.
func TestOptionsDefaults(t *testing.T) {
	o := Options{}
	o.withDefaults()
	if o.IdleTTL != 60*time.Second || o.InFlightTTL != 30*time.Second {
		t.Fatalf("TTL defaults wrong: %+v", o)
	}
	if o.MaxSessions != 4096 || o.MaxOutboundBytes != 1<<20 || o.MaxReorderFrames != 256 {
		t.Fatalf("bound defaults wrong: %+v", o)
	}
	if o.ChunkSize != 220 {
		t.Fatalf("ChunkSize default = %d, want 220", o.ChunkSize)
	}
	if !o.AllowLegacy {
		t.Fatal("the zero Options value must accept legacy frames")
	}

	// Negative values are treated as unset, explicit ones survive.
	neg := Options{IdleTTL: -1, InFlightTTL: -1, MaxSessions: -1, MaxOutboundBytes: -1, MaxReorderFrames: -1, ChunkSize: -1}
	neg.withDefaults()
	if neg.ChunkSize != 220 || neg.MaxSessions != 4096 {
		t.Fatalf("negative values were not defaulted: %+v", neg)
	}
	set := Options{IdleTTL: time.Second, InFlightTTL: 2 * time.Second, MaxSessions: 7,
		MaxOutboundBytes: 8, MaxReorderFrames: 9, ChunkSize: 10}.WithLegacy(false)
	set.withDefaults()
	if set.IdleTTL != time.Second || set.MaxSessions != 7 || set.ChunkSize != 10 || set.AllowLegacy {
		t.Fatalf("explicit options were overwritten: %+v", set)
	}
}

// TestSeqBefore pins the wrap-around-safe sequence comparison, which is what
// keeps a 16-bit counter usable across a long-lived tunnel.
func TestSeqBefore(t *testing.T) {
	cases := []struct {
		a, b uint16
		want bool
	}{
		{0, 1, true},
		{1, 0, false},
		{0, 0, false},
		{65535, 0, true},   // wraps forward
		{0, 65535, false},  // that is behind, not ahead
		{100, 32000, true}, // just inside half the space
		{100, 40000, false},
	}
	for _, c := range cases {
		if got := seqBefore(c.a, c.b); got != c.want {
			t.Fatalf("seqBefore(%d, %d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
