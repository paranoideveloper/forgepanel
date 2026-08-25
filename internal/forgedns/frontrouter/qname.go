// Package frontrouter lets one public port 53 sit in front of many DNS tunnels.
//
// ForgeDNS can already serve several zones, but only through its own in-process
// adapters. An upstream zone — one backed by a real third-party tunnel binary —
// gets its own BindHost:BindPort, and every one of them defaults to :53. Two
// upstream zones therefore contend for the same socket: internal/forgedns/
// upstream/manager.go waits for the port and fails with a "port is held by"
// hint. The operator's only escape is to move the loser to a non-standard port,
// which breaks it entirely, because a resolver following an NS delegation only
// ever asks port 53.
//
// The result is that the panel can configure any number of tunnel zones and
// serve exactly one of them to the public internet.
//
// This package removes that ceiling. It owns the public socket, reads the first
// question of each query, picks the backend whose configured suffix is the
// longest match, and forwards the datagram BYTE FOR BYTE to that backend on a
// private port. It never re-encodes the packet, adds a label, or terminates
// TLS, so the tunnel's usable payload per query — its MTU — is unchanged. A
// router that re-serialised packets would silently shrink every tunnel behind
// it.
//
// The approach, and the longest-suffix route table, follow CottenRouter
// (https://github.com/TaJirax/CottenRouter), MIT licensed, used here with
// attribution under compatible terms. See docs/LICENSING.md.
package frontrouter

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Errors returned while reading the question. They are deliberately specific:
// this parser is the first thing an untrusted packet touches on a public port,
// and "malformed" alone makes an operator guess.
var (
	ErrShortPacket      = errors.New("frontrouter: packet is shorter than a DNS header")
	ErrNotQuery         = errors.New("frontrouter: packet is a response, not a query")
	ErrNoQuestion       = errors.New("frontrouter: packet carries no question")
	ErrCompressedQNAME  = errors.New("frontrouter: compressed QNAME is not accepted in a query")
	ErrInvalidLabel     = errors.New("frontrouter: invalid DNS label")
	ErrUnterminatedName = errors.New("frontrouter: unterminated DNS name")
	ErrNameTooLong      = errors.New("frontrouter: DNS name exceeds the 255-octet limit")
)

// dnsHeaderLen is the fixed 12-byte DNS header.
const dnsHeaderLen = 12

// maxEncodedName is the RFC 1035 §2.3.4 limit: 255 octets in wire form,
// counting each label's length byte and the root terminator.
//
// It is enforced DURING the walk, not after joining, and that matters here.
// This runs on a public port, and the TCP path carries datagrams up to 65535
// bytes, so one query can hold a thousand 63-byte labels. Checking afterwards
// would mean growing the label slice and building a ~64 KB string — twice, once
// to join and once to lower-case — before the router had decided anything at
// all. Rejecting mid-walk costs one integer comparison per label and never
// allocates the string.
const maxEncodedName = 255

// maxLabelLen is the RFC 1035 limit for a single label.
const maxLabelLen = 63

// QuestionName returns the lower-cased QNAME of a query's first question.
//
// Compression pointers are refused rather than followed. A pointer in the first
// question of a query is never legitimate, and following one means handling
// cycles and out-of-range offsets on the hottest untrusted path in the process.
// Refusing is both correct and one less way to be attacked.
func QuestionName(packet []byte) (string, error) {
	if len(packet) < dnsHeaderLen {
		return "", ErrShortPacket
	}
	// QR bit set means this is a response; a front router forwards queries.
	if binary.BigEndian.Uint16(packet[2:4])&0x8000 != 0 {
		return "", ErrNotQuery
	}
	if binary.BigEndian.Uint16(packet[4:6]) == 0 {
		return "", ErrNoQuestion
	}

	labels := make([]string, 0, 8)
	// encoded counts the root terminator up front.
	encoded := 1
	for offset := dnsHeaderLen; ; {
		if offset >= len(packet) {
			return "", ErrUnterminatedName
		}
		length := int(packet[offset])
		offset++

		if length == 0 {
			if len(labels) == 0 {
				return "", ErrInvalidLabel
			}
			return strings.ToLower(strings.Join(labels, ".")), nil
		}
		// The two high bits mark a compression pointer (0xc0) or a reserved
		// label type; neither belongs in a query's first question.
		if length&0xc0 != 0 {
			return "", ErrCompressedQNAME
		}
		if length > maxLabelLen || offset+length > len(packet) {
			return "", ErrInvalidLabel
		}
		encoded += 1 + length
		if encoded > maxEncodedName {
			return "", ErrNameTooLong
		}
		label := packet[offset : offset+length]
		for _, b := range label {
			// A NUL or a dot inside a label would change the meaning of the
			// name once joined, which is how a crafted packet could be made to
			// match a suffix it does not own.
			if b == 0 || b == '.' {
				return "", ErrInvalidLabel
			}
		}
		labels = append(labels, string(label))
		offset += length
	}
}
