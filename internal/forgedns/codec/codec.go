// Package codec implements the label/QNAME codec layer for ForgeDNS, the
// DNS-tunnelling transport (spec §5.2, §5.3). It is deliberately self-contained
// (stdlib only) so a new tunnel wire format is a new adapter file plus test
// vectors, with no change to this layer.
//
// DNS constraints this layer must respect:
//   - a single label is at most 63 octets,
//   - a full QNAME is at most 255 octets on the wire,
//   - the query side is case-insensitive and case may be normalised in transit,
//     so upstream (client→server) labels must use a case-insensitive alphabet:
//     base32 (RFC 4648, lowercase, no padding) or base16. Base64 is reserved for
//     the downstream side (TXT/NULL answers), which is case-preserving.
package codec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// dnsB32 is RFC 4648 base32 with the standard alphabet, lowercased and unpadded
// for DNS labels. Decoding upper-cases first so a resolver that upcased the
// QNAME still round-trips.
var dnsB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	// MaxLabel is the DNS single-label octet limit.
	MaxLabel = 63
	// MaxQName is the DNS full-name octet limit (including length octets and the
	// trailing root); we budget conservatively against 255.
	MaxQName = 255
)

// Base32Encode encodes raw bytes to a lowercase, unpadded, DNS-safe base32
// string suitable for splitting into query labels.
func Base32Encode(data []byte) string {
	return strings.ToLower(dnsB32.EncodeToString(data))
}

// Base32Decode reverses Base32Encode, tolerating case folding introduced by a
// recursive resolver.
func Base32Decode(s string) ([]byte, error) {
	return dnsB32.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
}

// Base64Encode encodes raw bytes for a case-preserving downstream answer
// (TXT/CNAME), using standard base64.
func Base64Encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// Base64Decode reverses Base64Encode.
func Base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// NullEncode passes raw bytes straight through for a NULL resource record, which
// carries arbitrary octets. It exists so adapters can select an encoding by name
// uniformly.
func NullEncode(data []byte) []byte { return data }

// NullDecode is the identity, for symmetry with NullEncode.
func NullDecode(data []byte) []byte { return data }

// ChunkQName splits already-encoded payload text into dot-separated labels each
// at most maxLabel octets, appends the zone, and errors if the resulting QNAME
// would exceed the DNS limit. zone should be given without a leading dot; it may
// carry a trailing dot which is normalised away.
func ChunkQName(encoded, zone string, maxLabel int) (string, error) {
	if maxLabel <= 0 || maxLabel > MaxLabel {
		maxLabel = MaxLabel
	}
	zone = strings.TrimSuffix(strings.TrimPrefix(zone, "."), ".")
	if zone == "" {
		return "", errors.New("codec: empty zone")
	}
	var labels []string
	for len(encoded) > 0 {
		n := maxLabel
		if n > len(encoded) {
			n = len(encoded)
		}
		labels = append(labels, encoded[:n])
		encoded = encoded[n:]
	}
	name := strings.Join(labels, ".")
	if name != "" {
		name += "."
	}
	name += zone
	if wireLen(name) > MaxQName {
		return "", fmt.Errorf("codec: QNAME %d octets exceeds %d", wireLen(name), MaxQName)
	}
	return name, nil
}

// SplitQName recovers the encoded payload from a QNAME by stripping the zone
// suffix and concatenating the remaining labels. It is the inverse of
// ChunkQName (label boundaries are not significant to the payload).
//
// The second return value reports whether the name actually carried an encoded
// payload. A query for the zone apex ("tunnel.example.com" itself) carries none:
// it is an ordinary DNS question — SOA, NS, a delegation check, a health probe —
// and must be answered as authoritative DNS rather than pushed through the frame
// decoder, where an empty payload would fail the header-length check and be
// mistaken for a malformed frame. Deciding what to do with that answer is the
// adapter's job; this function only reports the fact.
func SplitQName(qname, zone string) (string, bool, error) {
	qname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	zone = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(zone)), "."), ".")
	if qname == zone {
		return "", false, nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(qname, suffix) {
		return "", false, fmt.Errorf("codec: %q is not under zone %q", qname, zone)
	}
	prefix := strings.TrimSuffix(qname, suffix)
	if prefix == "" {
		return "", false, nil
	}
	return strings.ReplaceAll(prefix, ".", ""), true, nil
}

// wireLen returns the on-the-wire octet length of a domain name: each label
// contributes a length octet plus its bytes, plus one for the root label.
func wireLen(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 1
	}
	total := 1 // root
	for _, label := range strings.Split(name, ".") {
		total += 1 + len(label)
	}
	return total
}

// MaxPayloadPerQuery computes how many RAW payload bytes fit in one query for a
// given zone and label size, accounting for the base32 5→8 expansion, the label
// dots, and the zone length. It never returns a negative number.
func MaxPayloadPerQuery(zone string, maxLabel int) int {
	if maxLabel <= 0 || maxLabel > MaxLabel {
		maxLabel = MaxLabel
	}
	zone = strings.TrimSuffix(strings.TrimPrefix(zone, "."), ".")
	// Octets available to the encoded payload = MaxQName budget
	//   minus the zone's wire length, minus a length octet per label.
	zoneWire := wireLen(zone) // includes root
	avail := MaxQName - zoneWire
	if avail <= 0 {
		return 0
	}
	// Each label of maxLabel encoded chars costs 1 length octet; estimate the
	// number of labels the encoded text will span and subtract their overhead.
	// Encoded length E satisfies E + ceil(E/maxLabel) <= avail.
	// Solve conservatively: encodedBudget = avail * maxLabel / (maxLabel+1).
	encodedBudget := avail * maxLabel / (maxLabel + 1)
	// base32 encodes 5 raw bytes into 8 chars, so raw = encoded * 5 / 8.
	raw := encodedBudget * 5 / 8
	if raw < 0 {
		return 0
	}
	return raw
}

// --- framing -------------------------------------------------------------

// FrameHeaderSize is the fixed binary header length: 2 (session) + 2 (seq) +
// 1 (flags).
const FrameHeaderSize = 5

// Flag bits for Frame.Flags.
const (
	FlagSYN  uint8 = 1 << 0 // session establishment
	FlagACK  uint8 = 1 << 1 // acknowledgement
	FlagDATA uint8 = 1 << 2 // carries payload
	FlagFIN  uint8 = 1 << 3 // session teardown
	FlagKA   uint8 = 1 << 4 // keepalive (empty data-pool poll)
	// FlagEXT marks a version-2 frame carrying the extension block described by
	// FrameExt: a wide session id, an explicit downstream acknowledgement, and a
	// per-session authenticator. Frames without it parse exactly as before, so a
	// v1 peer keeps working (see the AllowLegacy note in package session).
	FlagEXT uint8 = 1 << 5
)

// Extension-block layout constants (v2 frames, FlagEXT set). The block sits
// between the 5-byte base header and the payload.
const (
	// ExtSize is the total extension-block length: 8 (session) + 2 (ack seq) +
	// 1 (ext flags) + 8 (MAC).
	ExtSize = 19
	// MACSize is the truncated-HMAC length. 64 bits of forgery resistance, which
	// together with the manager's rate limiting is ample for a transport whose
	// frames are already bounded by the DNS QNAME budget.
	MACSize = 8
	// KeySize is the per-session HMAC key length handed out at handshake.
	KeySize = 32
	// extFlagAck marks FrameExt.AckSeq as meaningful.
	extFlagAck uint8 = 1 << 0
)

// FrameExt is the v2 extension block.
//
// SessionID replaces the 16-bit field for authenticated sessions: 16 bits is
// trivially enumerable, and because the session manager replays a buffered
// chunk to whoever asks for a given (session, sequence), a guessable id is a
// data-disclosure bug on a source-spoofable transport. Authenticated ids are
// always >= 1<<16 so they cannot collide with the legacy id space.
//
// MAC authenticates (SessionID, Seq, Flags, AckSeq, extFlags, Payload) under the
// per-session key established at handshake, so a third party can neither fetch
// another session's buffered chunk nor forge an acknowledgement that discards it.
type FrameExt struct {
	SessionID uint64
	AckSeq    uint16
	HasAck    bool
	MAC       [MACSize]byte
}

// Frame is one unit exchanged over the tunnel: a 5-byte big-endian header,
// optionally a 19-byte extension block, then an opaque payload. Adapters
// translate between Frames and concrete DNS messages; the session manager
// sequences and reorders them.
type Frame struct {
	SessionID uint16
	Seq       uint16
	Flags     uint8
	Payload   []byte

	// Ext is non-nil exactly when Flags has FlagEXT set.
	Ext *FrameExt
}

// HeaderLen returns this frame's total header length including any extension.
func (f Frame) HeaderLen() int {
	if f.Has(FlagEXT) {
		return FrameHeaderSize + ExtSize
	}
	return FrameHeaderSize
}

// Marshal serialises the frame to bytes.
func (f Frame) Marshal() []byte {
	hdr := f.HeaderLen()
	out := make([]byte, hdr+len(f.Payload))
	binary.BigEndian.PutUint16(out[0:2], f.SessionID)
	binary.BigEndian.PutUint16(out[2:4], f.Seq)
	out[4] = f.Flags
	if f.Has(FlagEXT) {
		e := f.Ext
		if e == nil {
			e = &FrameExt{}
		}
		binary.BigEndian.PutUint64(out[5:13], e.SessionID)
		binary.BigEndian.PutUint16(out[13:15], e.AckSeq)
		if e.HasAck {
			out[15] = extFlagAck
		}
		copy(out[16:24], e.MAC[:])
	}
	copy(out[hdr:], f.Payload)
	return out
}

// ParseFrame deserialises a frame, copying the payload so the caller may reuse
// the input buffer.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < FrameHeaderSize {
		return Frame{}, fmt.Errorf("codec: frame too short: %d < %d", len(b), FrameHeaderSize)
	}
	f := Frame{
		SessionID: binary.BigEndian.Uint16(b[0:2]),
		Seq:       binary.BigEndian.Uint16(b[2:4]),
		Flags:     b[4],
	}
	hdr := FrameHeaderSize
	if f.Has(FlagEXT) {
		if len(b) < FrameHeaderSize+ExtSize {
			return Frame{}, fmt.Errorf("codec: extended frame too short: %d < %d",
				len(b), FrameHeaderSize+ExtSize)
		}
		e := &FrameExt{
			SessionID: binary.BigEndian.Uint64(b[5:13]),
			AckSeq:    binary.BigEndian.Uint16(b[13:15]),
			HasAck:    b[15]&extFlagAck != 0,
		}
		copy(e.MAC[:], b[16:24])
		f.Ext = e
		hdr = FrameHeaderSize + ExtSize
	}
	if n := len(b) - hdr; n > 0 {
		f.Payload = make([]byte, n)
		copy(f.Payload, b[hdr:])
	}
	return f, nil
}

// Has reports whether a flag bit is set.
func (f Frame) Has(flag uint8) bool { return f.Flags&flag != 0 }

// --- frame authentication -------------------------------------------------

// macInput builds the canonical authenticated byte string for a frame. The
// length-prefixed layout is unambiguous, so no two distinct frames share an
// input.
func macInput(f Frame) []byte {
	e := f.Ext
	if e == nil {
		e = &FrameExt{}
	}
	buf := make([]byte, 0, 8+2+1+2+1+len(f.Payload))
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], e.SessionID)
	buf = append(buf, scratch[:]...)
	binary.BigEndian.PutUint16(scratch[:2], f.Seq)
	buf = append(buf, scratch[:2]...)
	buf = append(buf, f.Flags)
	binary.BigEndian.PutUint16(scratch[:2], e.AckSeq)
	buf = append(buf, scratch[:2]...)
	var af uint8
	if e.HasAck {
		af = extFlagAck
	}
	buf = append(buf, af)
	return append(buf, f.Payload...)
}

// SignFrame computes and stores the frame's authenticator. The frame must
// already have FlagEXT set and a non-nil Ext.
func SignFrame(f *Frame, key []byte) {
	if f.Ext == nil {
		f.Ext = &FrameExt{}
	}
	f.Flags |= FlagEXT
	mac := hmac.New(sha256.New, key)
	mac.Write(macInput(*f))
	copy(f.Ext.MAC[:], mac.Sum(nil)[:MACSize])
}

// VerifyFrame reports whether the frame carries a valid authenticator for key,
// comparing in constant time.
func VerifyFrame(f Frame, key []byte) bool {
	if f.Ext == nil || len(key) == 0 {
		return false
	}
	probe := f
	probe.Ext = &FrameExt{SessionID: f.Ext.SessionID, AckSeq: f.Ext.AckSeq, HasAck: f.Ext.HasAck}
	mac := hmac.New(sha256.New, key)
	mac.Write(macInput(probe))
	return hmac.Equal(mac.Sum(nil)[:MACSize], f.Ext.MAC[:])
}

// --- handshake ------------------------------------------------------------

// handshakeLen is the SYN response payload: session id followed by the key.
const handshakeLen = 8 + KeySize

// NewSessionSecret mints a session id with at least 64 bits of entropy and its
// per-session key, both from the system CSPRNG. Ids are forced above the legacy
// 16-bit space so authenticated and legacy sessions can never collide.
func NewSessionSecret() (uint64, []byte, error) {
	var idb [8]byte
	key := make([]byte, KeySize)
	for {
		if _, err := rand.Read(idb[:]); err != nil {
			return 0, nil, fmt.Errorf("codec: session id: %w", err)
		}
		id := binary.BigEndian.Uint64(idb[:])
		if id < 1<<16 {
			continue // reserved for legacy sessions
		}
		if _, err := rand.Read(key); err != nil {
			return 0, nil, fmt.Errorf("codec: session key: %w", err)
		}
		return id, key, nil
	}
}

// MakeHandshake builds the SYN response payload carrying the session id and key.
func MakeHandshake(id uint64, key []byte) []byte {
	out := make([]byte, handshakeLen)
	binary.BigEndian.PutUint64(out[0:8], id)
	copy(out[8:], key)
	return out
}

// ParseHandshake is the client side of MakeHandshake: recover the session id and
// key from a SYN response frame.
func ParseHandshake(f Frame) (uint64, []byte, error) {
	if !f.Has(FlagSYN) || !f.Has(FlagACK) {
		return 0, nil, errors.New("codec: not a handshake response")
	}
	if len(f.Payload) < handshakeLen {
		return 0, nil, fmt.Errorf("codec: short handshake: %d < %d", len(f.Payload), handshakeLen)
	}
	id := binary.BigEndian.Uint64(f.Payload[0:8])
	key := make([]byte, KeySize)
	copy(key, f.Payload[8:handshakeLen])
	return id, key, nil
}
