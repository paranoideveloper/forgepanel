package codec

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// --- ChunkQName / SplitQName edge cases ------------------------------------

func TestChunkQNameClampsMaxLabel(t *testing.T) {
	enc := Base32Encode(bytes.Repeat([]byte{0x11}, 60))
	zone := "t.example.com"
	want, err := ChunkQName(enc, zone, MaxLabel)
	if err != nil {
		t.Fatalf("baseline chunk: %v", err)
	}
	// Both an out-of-range and a non-positive maxLabel clamp to MaxLabel.
	for _, maxLabel := range []int{0, -1, MaxLabel + 1, 1000} {
		got, err := ChunkQName(enc, zone, maxLabel)
		if err != nil {
			t.Fatalf("maxLabel=%d: %v", maxLabel, err)
		}
		if got != want {
			t.Errorf("maxLabel=%d: clamp mismatch: %q vs %q", maxLabel, got, want)
		}
	}
}

func TestChunkQNameRejectsEmptyZone(t *testing.T) {
	for _, zone := range []string{"", "."} {
		if name, err := ChunkQName("abcdef", zone, 63); err == nil {
			t.Errorf("zone %q: expected empty-zone error, got %q", zone, name)
		}
	}
}

func TestChunkQNameNormalisesZoneDots(t *testing.T) {
	enc := Base32Encode([]byte("dots"))
	want, err := ChunkQName(enc, "t.example.com", 63)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{".t.example.com", "t.example.com.", ".t.example.com."} {
		got, err := ChunkQName(enc, zone, 63)
		if err != nil {
			t.Fatalf("zone %q: %v", zone, err)
		}
		if got != want {
			t.Errorf("zone %q: got %q want %q", zone, got, want)
		}
	}
}

func TestChunkQNameEmptyPayloadIsZoneApex(t *testing.T) {
	zone := "t.example.com"
	name, err := ChunkQName("", zone, 63)
	if err != nil {
		t.Fatal(err)
	}
	if name != zone {
		t.Fatalf("empty payload should yield the bare zone: got %q", name)
	}
	payload, hasPayload, err := SplitQName(name, zone)
	if err != nil {
		t.Fatal(err)
	}
	if hasPayload || payload != "" {
		t.Fatalf("zone apex must report no payload: %q %v", payload, hasPayload)
	}
}

func TestChunkQNameMultipleLabels(t *testing.T) {
	zone := "t.io"
	raw := bytes.Repeat([]byte{0xC3, 0x5A}, 20) // 40 bytes -> 64 base32 chars
	enc := Base32Encode(raw)
	for _, maxLabel := range []int{1, 4, 10, 63} {
		name, err := ChunkQName(enc, zone, maxLabel)
		if err != nil {
			t.Fatalf("maxLabel=%d: %v", maxLabel, err)
		}
		labels := strings.Split(strings.TrimSuffix(name, "."+zone), ".")
		wantLabels := (len(enc) + maxLabel - 1) / maxLabel
		if len(labels) != wantLabels {
			t.Errorf("maxLabel=%d: got %d labels, want %d", maxLabel, len(labels), wantLabels)
		}
		for _, l := range labels {
			if len(l) == 0 || len(l) > maxLabel {
				t.Fatalf("maxLabel=%d: bad label %q", maxLabel, l)
			}
		}
		recovered, hasPayload, err := SplitQName(name, zone)
		if err != nil || !hasPayload {
			t.Fatalf("maxLabel=%d: split: %v %v", maxLabel, err, hasPayload)
		}
		back, err := Base32Decode(recovered)
		if err != nil {
			t.Fatalf("maxLabel=%d: decode: %v", maxLabel, err)
		}
		if !bytes.Equal(back, raw) {
			t.Errorf("maxLabel=%d: payload mismatch", maxLabel)
		}
	}
}

func TestChunkQNameOverlongFromLabelOverhead(t *testing.T) {
	// A payload that fits comfortably at maxLabel=63 must be rejected once the
	// per-label length octets are multiplied by tiny labels.
	enc := Base32Encode(bytes.Repeat([]byte{0x7E}, 100))
	if _, err := ChunkQName(enc, "t.example.com", 63); err != nil {
		t.Fatalf("baseline should fit: %v", err)
	}
	if name, err := ChunkQName(enc, "t.example.com", 1); err == nil {
		t.Fatalf("1-octet labels should blow the QNAME budget, got %q", name)
	}
	// A zone that alone nearly fills the budget (253 of 255 octets) leaves no
	// room for even a two-character payload label.
	longZone := strings.Repeat("label.", 40) + "example.com"
	if got, want := wireLen(longZone), MaxQName; got > want {
		t.Fatalf("test zone is %d octets, expected it to fit within %d on its own", got, want)
	}
	if name, err := ChunkQName(Base32Encode([]byte("x")), longZone, 63); err == nil {
		t.Fatalf("overlong zone should be rejected, got %q", name)
	}
}

func TestSplitQNameZoneApexAndErrors(t *testing.T) {
	zone := "t.example.com"

	// Exact apex, with the trailing-dot / case / whitespace normalisations.
	for _, qname := range []string{zone, zone + ".", " " + strings.ToUpper(zone) + ". "} {
		payload, hasPayload, err := SplitQName(qname, zone)
		if err != nil {
			t.Fatalf("apex %q: %v", qname, err)
		}
		if hasPayload || payload != "" {
			t.Errorf("apex %q: want no payload, got %q %v", qname, payload, hasPayload)
		}
	}

	// A name whose only label content is the zone preceded by a bare dot has an
	// empty prefix and likewise carries nothing.
	payload, hasPayload, err := SplitQName("."+zone, zone)
	if err != nil {
		t.Fatalf("dotted apex: %v", err)
	}
	if hasPayload || payload != "" {
		t.Errorf("dotted apex: want no payload, got %q %v", payload, hasPayload)
	}

	// Names outside the zone are an error.
	for _, qname := range []string{
		"abc.other.example.com",
		"example.com",
		"",
		"nott.example.com.evil.test",
		"xt.example.com", // suffix match without the label boundary
	} {
		if _, _, err := SplitQName(qname, zone); err == nil {
			t.Errorf("qname %q: expected out-of-zone error", qname)
		}
	}
}

func TestSplitQNameNormalisesCaseAndDots(t *testing.T) {
	got, hasPayload, err := SplitQName("  AB.CD.T.EXAMPLE.COM. ", ".T.Example.Com.")
	if err != nil {
		t.Fatal(err)
	}
	if !hasPayload {
		t.Fatal("expected a payload")
	}
	if got != "abcd" {
		t.Fatalf("got %q, want %q", got, "abcd")
	}
}

// --- wireLen / MaxPayloadPerQuery ------------------------------------------

func TestWireLen(t *testing.T) {
	cases := map[string]int{
		"":              1, // root only
		".":             1,
		"a":             3, // 1 len + 1 byte + root
		"a.":            3,
		"t.example.com": 1 + 2 + 8 + 4, // 1+1, 1+7, 1+3, root
	}
	for name, want := range cases {
		if got := wireLen(name); got != want {
			t.Errorf("wireLen(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestMaxPayloadPerQueryClampsMaxLabel(t *testing.T) {
	want := MaxPayloadPerQuery("t.example.com", MaxLabel)
	for _, maxLabel := range []int{0, -5, MaxLabel + 1, 4096} {
		if got := MaxPayloadPerQuery("t.example.com", maxLabel); got != want {
			t.Errorf("maxLabel=%d: got %d, want clamped %d", maxLabel, got, want)
		}
	}
}

func TestMaxPayloadPerQueryEmptyAndOversizeZone(t *testing.T) {
	// An empty zone is the largest possible budget and must not panic.
	if got := MaxPayloadPerQuery("", 63); got <= 0 {
		t.Fatalf("empty zone budget must be positive, got %d", got)
	}
	if got := MaxPayloadPerQuery(".", 63); got <= 0 {
		t.Fatalf("root zone budget must be positive, got %d", got)
	}
	// A zone that overruns the QNAME budget leaves no room at all.
	for _, zone := range []string{
		strings.Repeat("a", MaxQName),
		strings.Repeat("label.", 60) + "example.com",
	} {
		if got := MaxPayloadPerQuery(zone, 63); got != 0 {
			t.Errorf("oversize zone: got %d, want 0", got)
		}
	}
}

func TestMaxPayloadPerQueryBudgetActuallyFits(t *testing.T) {
	for _, zone := range []string{"a.io", "t.example.com", "tunnel.sub.example.org"} {
		for _, maxLabel := range []int{16, 32, 63} {
			budget := MaxPayloadPerQuery(zone, maxLabel)
			if budget <= 0 {
				t.Fatalf("zone %q maxLabel %d: non-positive budget", zone, maxLabel)
			}
			enc := Base32Encode(bytes.Repeat([]byte{0x5A}, budget))
			if _, err := ChunkQName(enc, zone, maxLabel); err != nil {
				t.Errorf("zone %q maxLabel %d: advertised %d did not fit: %v",
					zone, maxLabel, budget, err)
			}
		}
	}
}

// --- framing ---------------------------------------------------------------

func TestHeaderLen(t *testing.T) {
	if got := (Frame{Flags: FlagDATA}).HeaderLen(); got != FrameHeaderSize {
		t.Errorf("plain HeaderLen = %d, want %d", got, FrameHeaderSize)
	}
	if got := (Frame{Flags: FlagEXT}).HeaderLen(); got != FrameHeaderSize+ExtSize {
		t.Errorf("ext HeaderLen = %d, want %d", got, FrameHeaderSize+ExtSize)
	}
	if got := (Frame{Flags: FlagDATA | FlagEXT, Ext: &FrameExt{}}).HeaderLen(); got != FrameHeaderSize+ExtSize {
		t.Errorf("ext+data HeaderLen = %d, want %d", got, FrameHeaderSize+ExtSize)
	}
}

func TestExtFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{
			SessionID: 0xABCD, Seq: 7, Flags: FlagEXT | FlagDATA,
			Ext:     &FrameExt{SessionID: 0x0102030405060708, AckSeq: 0x1234, HasAck: true, MAC: [MACSize]byte{1, 2, 3, 4, 5, 6, 7, 8}},
			Payload: []byte("extended payload"),
		},
		{
			// HasAck false and an empty payload exercise the other branches.
			SessionID: 0, Seq: 0, Flags: FlagEXT,
			Ext: &FrameExt{SessionID: 1 << 16, AckSeq: 0},
		},
		{
			SessionID: 0xFFFF, Seq: 0xFFFF, Flags: FlagEXT | FlagFIN | FlagACK,
			Ext:     &FrameExt{SessionID: ^uint64(0), AckSeq: 0xFFFF, HasAck: true, MAC: [MACSize]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
			Payload: bytes.Repeat([]byte{0x5A}, 300),
		},
	}
	for i, f := range cases {
		raw := f.Marshal()
		if len(raw) != FrameHeaderSize+ExtSize+len(f.Payload) {
			t.Fatalf("case %d: marshalled %d octets, want %d",
				i, len(raw), FrameHeaderSize+ExtSize+len(f.Payload))
		}
		got, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got.SessionID != f.SessionID || got.Seq != f.Seq || got.Flags != f.Flags {
			t.Errorf("case %d: header mismatch: %+v vs %+v", i, got, f)
		}
		if got.Ext == nil {
			t.Fatalf("case %d: extension block lost", i)
		}
		if *got.Ext != *f.Ext {
			t.Errorf("case %d: ext mismatch: %+v vs %+v", i, *got.Ext, *f.Ext)
		}
		if !bytes.Equal(got.Payload, f.Payload) {
			t.Errorf("case %d: payload mismatch", i)
		}
	}
}

func TestMarshalExtWithNilExt(t *testing.T) {
	// FlagEXT with a nil Ext must still emit a well-formed zero extension block
	// rather than panicking or truncating.
	f := Frame{SessionID: 5, Seq: 6, Flags: FlagEXT, Payload: []byte("hi")}
	raw := f.Marshal()
	if len(raw) != FrameHeaderSize+ExtSize+2 {
		t.Fatalf("marshalled %d octets, want %d", len(raw), FrameHeaderSize+ExtSize+2)
	}
	if !bytes.Equal(raw[5:24], make([]byte, ExtSize)) {
		t.Errorf("nil Ext should serialise as zeros, got %x", raw[5:24])
	}
	got, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ext == nil || *got.Ext != (FrameExt{}) {
		t.Errorf("round-tripped ext = %+v, want zero value", got.Ext)
	}
}

func TestParseFrameErrors(t *testing.T) {
	// Truncated base header.
	for n := 0; n < FrameHeaderSize; n++ {
		if _, err := ParseFrame(make([]byte, n)); err == nil {
			t.Errorf("len %d: expected too-short error", n)
		}
	}
	if _, err := ParseFrame(nil); err == nil {
		t.Error("nil buffer: expected too-short error")
	}
	// Truncated extension block: header says FlagEXT but the block is short.
	full := Frame{SessionID: 1, Seq: 2, Flags: FlagEXT, Ext: &FrameExt{SessionID: 9}}.Marshal()
	for n := FrameHeaderSize; n < FrameHeaderSize+ExtSize; n++ {
		if _, err := ParseFrame(full[:n]); err == nil {
			t.Errorf("ext len %d: expected too-short error", n)
		}
	}
	// Exactly the header lengths parse with a nil payload.
	plain, err := ParseFrame(make([]byte, FrameHeaderSize))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Payload != nil {
		t.Errorf("headerless frame should have nil payload, got %x", plain.Payload)
	}
	ext, err := ParseFrame(full)
	if err != nil {
		t.Fatal(err)
	}
	if ext.Payload != nil {
		t.Errorf("headerless ext frame should have nil payload, got %x", ext.Payload)
	}
}

func TestParseFrameCopiesPayload(t *testing.T) {
	raw := Frame{SessionID: 1, Seq: 1, Flags: FlagDATA, Payload: []byte("mutable")}.Marshal()
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	if string(f.Payload) != "mutable" {
		t.Fatalf("payload aliased the input buffer: %q", f.Payload)
	}
}

func TestFrameHasEveryFlag(t *testing.T) {
	all := []uint8{FlagSYN, FlagACK, FlagDATA, FlagFIN, FlagKA, FlagEXT}
	for _, flag := range all {
		f := Frame{Flags: flag}
		if !f.Has(flag) {
			t.Errorf("flag %#x not reported set", flag)
		}
		for _, other := range all {
			if other != flag && f.Has(other) {
				t.Errorf("flag %#x wrongly reported for frame with %#x", other, flag)
			}
		}
	}
	if (Frame{}).Has(FlagDATA) {
		t.Error("zero frame must have no flags")
	}
}

// --- authentication --------------------------------------------------------

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	return key
}

func TestMacInputNilExtMatchesZeroExt(t *testing.T) {
	// macInput must treat a nil extension exactly like a zero-valued one, so a
	// signature computed either way agrees.
	f := Frame{SessionID: 3, Seq: 11, Flags: FlagEXT | FlagDATA, Payload: []byte("body")}
	withNil := macInput(f)
	f.Ext = &FrameExt{}
	withZero := macInput(f)
	if !bytes.Equal(withNil, withZero) {
		t.Fatalf("nil ext MAC input %x != zero ext %x", withNil, withZero)
	}
	// The MAC field itself is deliberately excluded from the input.
	f.Ext.MAC = [MACSize]byte{9, 9, 9, 9, 9, 9, 9, 9}
	if !bytes.Equal(macInput(f), withZero) {
		t.Error("MAC field must not feed back into its own input")
	}
}

func TestMacInputDistinguishesEveryField(t *testing.T) {
	base := Frame{
		Seq: 1, Flags: FlagEXT,
		Ext:     &FrameExt{SessionID: 1 << 20, AckSeq: 2},
		Payload: []byte("p"),
	}
	baseline := macInput(base)

	variants := map[string]func(f *Frame){
		"seq":       func(f *Frame) { f.Seq = 2 },
		"flags":     func(f *Frame) { f.Flags |= FlagDATA },
		"extID":     func(f *Frame) { f.Ext.SessionID = 1 << 21 },
		"ackSeq":    func(f *Frame) { f.Ext.AckSeq = 3 },
		"hasAck":    func(f *Frame) { f.Ext.HasAck = true },
		"payload":   func(f *Frame) { f.Payload = []byte("q") },
		"payloadLn": func(f *Frame) { f.Payload = []byte("pp") },
	}
	for name, mutate := range variants {
		v := base
		ext := *base.Ext
		v.Ext = &ext
		mutate(&v)
		if bytes.Equal(macInput(v), baseline) {
			t.Errorf("%s: distinct frames share a MAC input", name)
		}
	}
}

func TestSignVerifyFrame(t *testing.T) {
	key := testKey(t)
	f := Frame{
		SessionID: 0x1111, Seq: 42, Flags: FlagDATA,
		Ext:     &FrameExt{SessionID: 1 << 33, AckSeq: 17, HasAck: true},
		Payload: []byte("authenticated bytes"),
	}
	SignFrame(&f, key)
	if !f.Has(FlagEXT) {
		t.Fatal("SignFrame must set FlagEXT")
	}
	if f.Ext.MAC == ([MACSize]byte{}) {
		t.Fatal("SignFrame left a zero MAC")
	}
	if !VerifyFrame(f, key) {
		t.Fatal("freshly signed frame failed verification")
	}
	// Signing is deterministic.
	again := f
	ext := *f.Ext
	again.Ext = &ext
	SignFrame(&again, key)
	if again.Ext.MAC != f.Ext.MAC {
		t.Error("SignFrame is not deterministic")
	}
	// The signature survives a marshal/parse round trip.
	parsed, err := ParseFrame(f.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyFrame(parsed, key) {
		t.Fatal("signature lost across marshal/parse")
	}
}

func TestSignFrameCreatesMissingExt(t *testing.T) {
	key := testKey(t)
	f := Frame{SessionID: 2, Seq: 3, Flags: FlagDATA, Payload: []byte("no ext yet")}
	SignFrame(&f, key)
	if f.Ext == nil {
		t.Fatal("SignFrame must allocate a missing extension block")
	}
	if !f.Has(FlagEXT) {
		t.Fatal("SignFrame must set FlagEXT")
	}
	if !VerifyFrame(f, key) {
		t.Fatal("frame signed from a nil Ext failed verification")
	}
}

func TestVerifyFrameRejectsTampering(t *testing.T) {
	key := testKey(t)
	signed := Frame{
		SessionID: 0x2222, Seq: 5, Flags: FlagDATA,
		Ext:     &FrameExt{SessionID: 1 << 40, AckSeq: 9, HasAck: true},
		Payload: []byte("original payload"),
	}
	SignFrame(&signed, key)

	tampers := map[string]func(f *Frame){
		"seq":         func(f *Frame) { f.Seq++ },
		"flags":       func(f *Frame) { f.Flags |= FlagFIN },
		"extSession":  func(f *Frame) { f.Ext.SessionID++ },
		"ackSeq":      func(f *Frame) { f.Ext.AckSeq++ },
		"hasAck":      func(f *Frame) { f.Ext.HasAck = !f.Ext.HasAck },
		"payloadByte": func(f *Frame) { f.Payload = []byte("0riginal payload") },
		"payloadCut":  func(f *Frame) { f.Payload = f.Payload[:len(f.Payload)-1] },
		"payloadGrow": func(f *Frame) { f.Payload = append(append([]byte{}, f.Payload...), 'x') },
		"mac":         func(f *Frame) { f.Ext.MAC[0] ^= 0xFF },
		"macLast":     func(f *Frame) { f.Ext.MAC[MACSize-1] ^= 0x01 },
	}
	for name, tamper := range tampers {
		bad := signed
		ext := *signed.Ext
		bad.Ext = &ext
		bad.Payload = append([]byte{}, signed.Payload...)
		tamper(&bad)
		if VerifyFrame(bad, key) {
			t.Errorf("%s: tampered frame verified", name)
		}
		// The same tampering also fails after a wire round trip.
		parsed, err := ParseFrame(bad.Marshal())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if VerifyFrame(parsed, key) {
			t.Errorf("%s: tampered frame verified after round trip", name)
		}
	}

	// The untampered frame still verifies, and only under the right key.
	if !VerifyFrame(signed, key) {
		t.Fatal("control frame failed verification")
	}
	wrong := testKey(t)
	wrong[0] ^= 0xFF
	if VerifyFrame(signed, wrong) {
		t.Error("frame verified under the wrong key")
	}
}

func TestVerifyFrameRejectsMissingExtOrKey(t *testing.T) {
	key := testKey(t)
	if VerifyFrame(Frame{Flags: FlagEXT}, key) {
		t.Error("frame without an extension block must not verify")
	}
	if VerifyFrame(Frame{SessionID: 1, Flags: FlagDATA, Payload: []byte("x")}, key) {
		t.Error("legacy frame must not verify")
	}
	signed := Frame{Seq: 1, Ext: &FrameExt{SessionID: 1 << 17}}
	SignFrame(&signed, key)
	if VerifyFrame(signed, nil) {
		t.Error("nil key must not verify")
	}
	if VerifyFrame(signed, []byte{}) {
		t.Error("empty key must not verify")
	}
}

// --- handshake -------------------------------------------------------------

func TestHandshakeRoundTrip(t *testing.T) {
	key := testKey(t)
	for _, id := range []uint64{0, 1, 1 << 16, 1<<63 + 12345, ^uint64(0)} {
		payload := MakeHandshake(id, key)
		if len(payload) != 8+KeySize {
			t.Fatalf("id %d: handshake is %d octets, want %d", id, len(payload), 8+KeySize)
		}
		f := Frame{SessionID: 1, Flags: FlagSYN | FlagACK, Payload: payload}
		gotID, gotKey, err := ParseHandshake(f)
		if err != nil {
			t.Fatalf("id %d: %v", id, err)
		}
		if gotID != id {
			t.Errorf("id %d: parsed %d", id, gotID)
		}
		if !bytes.Equal(gotKey, key) {
			t.Errorf("id %d: key mismatch", id)
		}
		// The returned key must be a copy, not a view into the frame payload.
		gotKey[0] ^= 0xFF
		if bytes.Equal(gotKey, f.Payload[8:]) {
			t.Errorf("id %d: ParseHandshake aliased the payload", id)
		}
	}
}

func TestMakeHandshakeTruncatesAndPadsKey(t *testing.T) {
	// A short key leaves the tail zeroed; an over-long key is truncated. Either
	// way the output is exactly handshakeLen.
	short := MakeHandshake(7, []byte{1, 2, 3})
	if len(short) != 8+KeySize {
		t.Fatalf("short key: %d octets", len(short))
	}
	if !bytes.Equal(short[8:11], []byte{1, 2, 3}) || !bytes.Equal(short[11:], make([]byte, KeySize-3)) {
		t.Errorf("short key not zero-padded: %x", short[8:])
	}
	long := MakeHandshake(7, bytes.Repeat([]byte{0xAA}, KeySize*2))
	if len(long) != 8+KeySize {
		t.Fatalf("long key: %d octets", len(long))
	}
}

func TestParseHandshakeErrors(t *testing.T) {
	good := MakeHandshake(1<<20, testKey(t))

	// Wrong flags.
	for name, flags := range map[string]uint8{
		"none":     0,
		"syn only": FlagSYN,
		"ack only": FlagACK,
		"data":     FlagDATA,
		"fin+ack":  FlagFIN | FlagACK,
		"syn+data": FlagSYN | FlagDATA,
	} {
		if _, _, err := ParseHandshake(Frame{Flags: flags, Payload: good}); err == nil {
			t.Errorf("flags %s: expected not-a-handshake error", name)
		}
	}

	// Right flags, short payload.
	for _, n := range []int{0, 1, 8, len(good) - 1} {
		f := Frame{Flags: FlagSYN | FlagACK, Payload: good[:n]}
		if _, _, err := ParseHandshake(f); err == nil {
			t.Errorf("payload len %d: expected short-handshake error", n)
		}
	}
	if _, _, err := ParseHandshake(Frame{Flags: FlagSYN | FlagACK}); err == nil {
		t.Error("nil payload: expected short-handshake error")
	}

	// A longer-than-required payload is accepted; the tail is ignored.
	id, key, err := ParseHandshake(Frame{
		Flags:   FlagSYN | FlagACK,
		Payload: append(append([]byte{}, good...), 'j', 'u', 'n', 'k'),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != 1<<20 || !bytes.Equal(key, testKey(t)) {
		t.Errorf("trailing bytes changed the parse: id=%d", id)
	}
}

// --- session secrets -------------------------------------------------------

func TestNewSessionSecret(t *testing.T) {
	id, key, err := NewSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	if id < 1<<16 {
		t.Fatalf("id %d collides with the legacy 16-bit space", id)
	}
	if len(key) != KeySize {
		t.Fatalf("key is %d octets, want %d", len(key), KeySize)
	}
	if bytes.Equal(key, make([]byte, KeySize)) {
		t.Fatal("key is all zeros")
	}
	id2, key2, err := NewSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	if id2 == id || bytes.Equal(key2, key) {
		t.Fatal("two secrets collided")
	}
	// The minted secret is usable end to end.
	f := Frame{Seq: 1, Ext: &FrameExt{SessionID: id}, Payload: []byte("live")}
	SignFrame(&f, key)
	if !VerifyFrame(f, key) {
		t.Fatal("minted key failed to authenticate a frame")
	}
	if VerifyFrame(f, key2) {
		t.Fatal("frame verified under a different session's key")
	}
}

// scriptedRand is a deterministic stand-in for crypto/rand.Reader. It serves
// scripted bytes first and then a constant filler, so it can never short-read
// (crypto/rand.Read treats a reader error as a fatal, unrecoverable condition).
type scriptedRand struct {
	script []byte
	pos    int
}

func (r *scriptedRand) Read(p []byte) (int, error) {
	for i := range p {
		if r.pos < len(r.script) {
			p[i] = r.script[r.pos]
		} else {
			p[i] = 0xA5
		}
		r.pos++
	}
	return len(p), nil
}

var _ io.Reader = (*scriptedRand)(nil)

func TestNewSessionSecretRejectsLegacyIDSpace(t *testing.T) {
	// Drive the id draw so the first two candidates land in the reserved 16-bit
	// space (including the 1<<16-1 boundary) and must be discarded.
	var script []byte
	for _, candidate := range []uint64{0, 1<<16 - 1, 1 << 16} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], candidate)
		script = append(script, b[:]...)
	}
	wantKey := make([]byte, KeySize)
	for i := range wantKey {
		wantKey[i] = byte(0xF0 ^ i)
	}
	script = append(script, wantKey...)

	orig := rand.Reader
	rand.Reader = &scriptedRand{script: script}
	defer func() { rand.Reader = orig }()

	id, key, err := NewSessionSecret()
	if err != nil {
		t.Fatal(err)
	}
	if id != 1<<16 {
		t.Fatalf("id = %d, want the first candidate outside the legacy space (%d)", id, 1<<16)
	}
	if !bytes.Equal(key, wantKey) {
		t.Fatalf("key = %x, want %x", key, wantKey)
	}
}
