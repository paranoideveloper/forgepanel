package frontrouter

import (
	"encoding/binary"
	"errors"
	"strings"
)

// TLS ClientHello parsing, for sharing one public TLS port across tunnels.
//
// The DNS half of this package solved half the problem. An upstream zone can
// also expose DNS-over-TLS and DNS-over-HTTPS, and those ports are not
// negotiable either: a DoT client goes to 853 and a DoH client to 443, so two
// zones that both enable them collide exactly as two zones on 53 collided, and
// the second one loses its listener.
//
// The router answers it the same way and for the same reason: read only what is
// needed to choose a backend, then hand the bytes over untouched. TLS is NOT
// terminated here. That is not a shortcut — terminating would mean this process
// holding every zone's private key, presenting its own certificate, and
// re-encrypting, which changes what the client validates and breaks any backend
// doing certificate pinning or its own ALPN. Passing the stream through leaves
// the backend's certificate, protocol and version exactly as the operator
// configured them, and leaves this router unable to read a byte of the tunnel.
const (
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01
	// tlsRecordHeaderLen is type(1) + version(2) + length(2).
	tlsRecordHeaderLen = 5
	// maxClientHello bounds what will be buffered while looking for the SNI. A
	// ClientHello can legitimately exceed one segment — post-quantum key shares
	// alone push it past 1500 bytes — but it cannot exceed one record, and a
	// peer that never completes one must not be able to grow this buffer for as
	// long as it likes.
	maxClientHello = 16384 + tlsRecordHeaderLen

	extServerName   = 0x0000
	sniTypeHostName = 0x00
)

var (
	// ErrNotClientHello means the stream did not begin with a TLS handshake
	// record. Reported rather than guessed at: something else entirely is
	// talking to this port and the operator needs to know which.
	ErrNotClientHello = errors.New("frontrouter: stream does not begin with a TLS ClientHello")
	// ErrShortClientHello means the record is incomplete. The caller should read
	// more bytes and try again; it is not a protocol error.
	ErrShortClientHello = errors.New("frontrouter: ClientHello is incomplete")
	// ErrNoServerName means the hello carried no SNI. There is no safe default:
	// sending the stream to any backend hands the client a certificate for a
	// name it did not ask for, and the failure it then reports names neither
	// this router nor the real cause.
	ErrNoServerName = errors.New("frontrouter: TLS ClientHello carries no server name")
)

// ServerName returns the SNI host from a TLS ClientHello, lower-cased.
//
// It walks the record by length prefixes and never trusts one without checking
// it against what is left, because every one of them is attacker-controlled on
// a public port. ErrShortClientHello is returned for anything that runs off the
// end, which is also how a caller reading from a socket learns to read more.
func ServerName(packet []byte) (string, error) {
	if len(packet) < tlsRecordHeaderLen {
		if len(packet) > 0 && packet[0] != recordTypeHandshake {
			return "", ErrNotClientHello
		}
		if len(packet) == 0 {
			return "", ErrNotClientHello
		}
		return "", ErrShortClientHello
	}
	if packet[0] != recordTypeHandshake {
		return "", ErrNotClientHello
	}
	recordLen := int(binary.BigEndian.Uint16(packet[3:5]))
	if recordLen == 0 || recordLen > maxClientHello {
		return "", ErrNotClientHello
	}
	body := packet[tlsRecordHeaderLen:]
	if len(body) < recordLen {
		return "", ErrShortClientHello
	}
	body = body[:recordLen]

	// Handshake header: type(1) + length(3).
	if len(body) < 4 {
		return "", ErrShortClientHello
	}
	if body[0] != handshakeClientHello {
		return "", ErrNotClientHello
	}
	helloLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if len(body) < helloLen {
		return "", ErrShortClientHello
	}
	body = body[:helloLen]

	// client_version(2) + random(32).
	if len(body) < 34 {
		return "", ErrShortClientHello
	}
	body = body[34:]

	var ok bool
	if body, ok = skipVector8(body); !ok { // legacy_session_id
		return "", ErrShortClientHello
	}
	if body, ok = skipVector16(body); !ok { // cipher_suites
		return "", ErrShortClientHello
	}
	if body, ok = skipVector8(body); !ok { // legacy_compression_methods
		return "", ErrShortClientHello
	}

	// A ClientHello with no extensions block at all is legal and simply has no
	// SNI — TLS 1.2 and earlier. It is unroutable here all the same.
	if len(body) < 2 {
		return "", ErrNoServerName
	}
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < extLen {
		return "", ErrShortClientHello
	}
	exts := body[:extLen]

	for len(exts) >= 4 {
		kind := binary.BigEndian.Uint16(exts[:2])
		size := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < size {
			return "", ErrShortClientHello
		}
		if kind != extServerName {
			exts = exts[size:]
			continue
		}
		return hostNameFromSNI(exts[:size])
	}
	return "", ErrNoServerName
}

// hostNameFromSNI reads the first host_name entry of a server_name extension.
func hostNameFromSNI(ext []byte) (string, error) {
	if len(ext) < 2 {
		return "", ErrShortClientHello
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	ext = ext[2:]
	if len(ext) < listLen {
		return "", ErrShortClientHello
	}
	list := ext[:listLen]
	for len(list) >= 3 {
		nameType := list[0]
		size := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if len(list) < size {
			return "", ErrShortClientHello
		}
		if nameType != sniTypeHostName {
			list = list[size:]
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(string(list[:size]), "."))
		if name == "" {
			return "", ErrNoServerName
		}
		return name, nil
	}
	return "", ErrNoServerName
}

// skipVector8 skips a vector with a one-byte length prefix.
func skipVector8(b []byte) ([]byte, bool) {
	if len(b) < 1 {
		return nil, false
	}
	n := int(b[0])
	if len(b) < 1+n {
		return nil, false
	}
	return b[1+n:], true
}

// skipVector16 skips a vector with a two-byte length prefix.
func skipVector16(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return nil, false
	}
	return b[2+n:], true
}
