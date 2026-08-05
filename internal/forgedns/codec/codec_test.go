package codec

import (
	"bytes"
	"strings"
	"testing"
)

func TestBase32RoundTrip(t *testing.T) {
	cases := [][]byte{
		nil, {0}, {0xff}, []byte("hello world"),
		[]byte("The quick brown fox jumps over 13 lazy dogs — تست"),
		bytes.Repeat([]byte{0xAB, 0x00, 0x7F}, 40),
	}
	for i, in := range cases {
		enc := Base32Encode(in)
		if enc != strings.ToLower(enc) {
			t.Errorf("case %d: base32 must be lowercase", i)
		}
		// Simulate a resolver upcasing the QNAME in transit.
		got, err := Base32Decode(strings.ToUpper(enc))
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("case %d: round-trip mismatch: %x vs %x", i, got, in)
		}
	}
}

func TestBase64AndNull(t *testing.T) {
	in := []byte{0, 1, 2, 3, 250, 251, 252}
	if got, err := Base64Decode(Base64Encode(in)); err != nil || !bytes.Equal(got, in) {
		t.Fatalf("base64 round-trip: %v %x", err, got)
	}
	if !bytes.Equal(NullDecode(NullEncode(in)), in) {
		t.Fatal("null passthrough must be identity")
	}
}

func TestChunkQNameRoundTrip(t *testing.T) {
	zone := "t.example.com"
	payload := []byte("session-3 tunneled tcp bytes here, arbitrary length data 0123456789")
	enc := Base32Encode(payload)
	name, err := ChunkQName(enc, zone, 63)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, "."+zone) {
		t.Fatalf("qname %q not under zone", name)
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."+zone), ".") {
		if len(label) > MaxLabel {
			t.Fatalf("label %q exceeds %d", label, MaxLabel)
		}
	}
	recovered, hasPayload, err := SplitQName(name, zone)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPayload {
		t.Fatalf("qname %q should carry an encoded payload", name)
	}
	back, err := Base32Decode(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("payload mismatch after chunk+split: %q vs %q", back, payload)
	}
}

func TestChunkQNameRejectsOversize(t *testing.T) {
	// A payload whose encoding cannot fit under 255 octets must be rejected.
	huge := Base32Encode(bytes.Repeat([]byte{0x42}, 400))
	if _, err := ChunkQName(huge, "t.example.com", 63); err == nil {
		t.Fatal("expected oversize QNAME rejection")
	}
}

func TestMaxPayloadPerQuery(t *testing.T) {
	// Sanity bounds: shorter zone => more payload room; result respects that a
	// full round-trip actually fits.
	short := MaxPayloadPerQuery("a.io", 63)
	long := MaxPayloadPerQuery("very.long.tunnel.subdomain.example.com", 63)
	if short <= 0 || long <= 0 {
		t.Fatalf("payload budgets must be positive: %d %d", short, long)
	}
	if long >= short {
		t.Fatalf("longer zone should leave less room: short=%d long=%d", short, long)
	}
	// Whatever the budget says fits, must actually chunk without error.
	zone := "t.example.com"
	budget := MaxPayloadPerQuery(zone, 63)
	enc := Base32Encode(bytes.Repeat([]byte{0x5A}, budget))
	if _, err := ChunkQName(enc, zone, 63); err != nil {
		t.Fatalf("advertised budget %d did not fit: %v", budget, err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{SessionID: 0, Seq: 0, Flags: FlagSYN},
		{SessionID: 0xBEEF, Seq: 42, Flags: FlagDATA | FlagACK, Payload: []byte("payload")},
		{SessionID: 0xFFFF, Seq: 0xFFFF, Flags: FlagFIN, Payload: bytes.Repeat([]byte{1}, 200)},
		{SessionID: 7, Seq: 1, Flags: FlagKA},
	}
	for i, f := range cases {
		got, err := ParseFrame(f.Marshal())
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if got.SessionID != f.SessionID || got.Seq != f.Seq || got.Flags != f.Flags {
			t.Errorf("case %d: header mismatch: %+v vs %+v", i, got, f)
		}
		if !bytes.Equal(got.Payload, f.Payload) {
			t.Errorf("case %d: payload mismatch", i)
		}
	}
	if _, err := ParseFrame([]byte{1, 2}); err == nil {
		t.Fatal("short frame must error")
	}
}

func TestFrameFlags(t *testing.T) {
	f := Frame{Flags: FlagDATA | FlagACK}
	if !f.Has(FlagDATA) || !f.Has(FlagACK) || f.Has(FlagFIN) {
		t.Fatal("flag predicate wrong")
	}
}
