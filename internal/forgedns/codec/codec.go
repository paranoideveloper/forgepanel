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
func SplitQName(qname, zone string) (string, error) {
	qname = strings.TrimSuffix(strings.ToLower(qname), ".")
	zone = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(zone), "."), ".")
	suffix := "." + zone
	if !strings.HasSuffix(qname, suffix) {
		if qname == zone {
			return "", nil
		}
		return "", fmt.Errorf("codec: %q is not under zone %q", qname, zone)
	}
	prefix := strings.TrimSuffix(qname, suffix)
	return strings.ReplaceAll(prefix, ".", ""), nil
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
)

// Frame is one unit exchanged over the tunnel: a 5-byte big-endian header
// followed by an opaque payload. Adapters translate between Frames and concrete
// DNS messages; the session manager sequences and reorders them.
type Frame struct {
	SessionID uint16
	Seq       uint16
	Flags     uint8
	Payload   []byte
}

// Marshal serialises the frame to bytes.
func (f Frame) Marshal() []byte {
	out := make([]byte, FrameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint16(out[0:2], f.SessionID)
	binary.BigEndian.PutUint16(out[2:4], f.Seq)
	out[4] = f.Flags
	copy(out[FrameHeaderSize:], f.Payload)
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
	if n := len(b) - FrameHeaderSize; n > 0 {
		f.Payload = make([]byte, n)
		copy(f.Payload, b[FrameHeaderSize:])
	}
	return f, nil
}

// Has reports whether a flag bit is set.
func (f Frame) Has(flag uint8) bool { return f.Flags&flag != 0 }
