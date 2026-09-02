//go:build harness

// dnswire.go is a minimal DNS message encoder/decoder. The harness needs UDP
// traffic whose payload it can verify end to end, and DNS is the UDP protocol a
// proxy client is actually expected to carry, so the harness speaks it directly
// rather than depending on a resolver library. Only the subset the probes use is
// implemented: a single-question query and an answer section carrying A or TXT.
package harness

import (
	"errors"
	"fmt"
	"strings"
)

// DNS record type codes used by the harness.
const (
	TypeA   = 1
	TypeTXT = 16
	ClassIN = 1
)

// ErrNoAnswer means the response parsed cleanly but carried no matching record.
var ErrNoAnswer = errors.New("dns: no answer record of the requested type")

// BuildQuery encodes a standard recursive query for one name/type.
func BuildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	var b []byte
	b = append(b, byte(id>>8), byte(id))
	b = append(b, 0x01, 0x00) // QR=0 OPCODE=0 RD=1
	b = append(b, 0x00, 0x01) // QDCOUNT=1
	b = append(b, 0x00, 0x00) // ANCOUNT
	b = append(b, 0x00, 0x00) // NSCOUNT
	b = append(b, 0x00, 0x00) // ARCOUNT
	qn, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	b = append(b, qn...)
	b = append(b, byte(qtype>>8), byte(qtype), 0x00, ClassIN)
	return b, nil
}

// Question is the single question of a decoded message.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Answer is one decoded resource record, reduced to what the probes assert on.
type Answer struct {
	Name string
	Type uint16
	A    string // dotted-quad when Type == TypeA
	TXT  string // concatenated character-strings when Type == TypeTXT
}

// ParseMessage decodes a DNS message far enough to read its question and answer
// records. Name compression pointers are followed, because a server is free to
// use them in the answer's owner name even for a single-record reply.
func ParseMessage(msg []byte) (id uint16, q Question, answers []Answer, err error) {
	if len(msg) < 12 {
		return 0, q, nil, errors.New("dns: message shorter than a header")
	}
	id = uint16(msg[0])<<8 | uint16(msg[1])
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	for i := 0; i < qd; i++ {
		name, n, e := decodeName(msg, off)
		if e != nil {
			return id, q, nil, e
		}
		off = n
		if off+4 > len(msg) {
			return id, q, nil, errors.New("dns: truncated question")
		}
		if i == 0 {
			q = Question{Name: name,
				Type:  uint16(msg[off])<<8 | uint16(msg[off+1]),
				Class: uint16(msg[off+2])<<8 | uint16(msg[off+3])}
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		name, n, e := decodeName(msg, off)
		if e != nil {
			return id, q, answers, e
		}
		off = n
		if off+10 > len(msg) {
			return id, q, answers, errors.New("dns: truncated answer header")
		}
		rtype := uint16(msg[off])<<8 | uint16(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return id, q, answers, errors.New("dns: truncated rdata")
		}
		rd := msg[off : off+rdlen]
		off += rdlen
		a := Answer{Name: name, Type: rtype}
		switch rtype {
		case TypeA:
			if len(rd) != 4 {
				return id, q, answers, fmt.Errorf("dns: A rdata is %d bytes, want 4", len(rd))
			}
			a.A = fmt.Sprintf("%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3])
		case TypeTXT:
			var sb strings.Builder
			for p := 0; p < len(rd); {
				l := int(rd[p])
				p++
				if p+l > len(rd) {
					break
				}
				sb.Write(rd[p : p+l])
				p += l
			}
			a.TXT = sb.String()
		}
		answers = append(answers, a)
	}
	return id, q, answers, nil
}

// BuildResponse encodes an answer to q. Each entry of ips becomes an A record
// and each entry of txts a TXT record; an empty pair yields NXDOMAIN.
func BuildResponse(id uint16, q Question, ips []string, txts []string, ttl uint32) ([]byte, error) {
	qn, err := encodeName(q.Name)
	if err != nil {
		return nil, err
	}
	var rrs []byte
	count := 0
	if q.Type == TypeA || q.Type == 255 {
		for _, ip := range ips {
			var quad [4]byte
			if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &quad[0], &quad[1], &quad[2], &quad[3]); err != nil {
				return nil, fmt.Errorf("dns: bad A value %q: %w", ip, err)
			}
			rrs = append(rrs, qn...)
			rrs = append(rrs, 0x00, TypeA, 0x00, ClassIN)
			rrs = append(rrs, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
			rrs = append(rrs, 0x00, 0x04)
			rrs = append(rrs, quad[:]...)
			count++
		}
	}
	if q.Type == TypeTXT || q.Type == 255 {
		for _, t := range txts {
			if len(t) > 255 {
				t = t[:255]
			}
			rrs = append(rrs, qn...)
			rrs = append(rrs, 0x00, TypeTXT, 0x00, ClassIN)
			rrs = append(rrs, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
			rdlen := len(t) + 1
			rrs = append(rrs, byte(rdlen>>8), byte(rdlen), byte(len(t)))
			rrs = append(rrs, t...)
			count++
		}
	}
	rcode := byte(0)
	if count == 0 {
		rcode = 3 // NXDOMAIN
	}
	var b []byte
	b = append(b, byte(id>>8), byte(id))
	b = append(b, 0x81, 0x80|rcode) // QR=1 RD=1 RA=1
	b = append(b, 0x00, 0x01)
	b = append(b, byte(count>>8), byte(count))
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	b = append(b, qn...)
	b = append(b, byte(q.Type>>8), byte(q.Type), byte(q.Class>>8), byte(q.Class))
	b = append(b, rrs...)
	return b, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("dns: bad label %q in %q", label, name)
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	return append(out, 0x00), nil
}

// decodeName reads a (possibly compressed) name and returns the offset just
// past the name in the *original* stream.
func decodeName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	hops := 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("dns: name runs past end of message")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, errors.New("dns: truncated compression pointer")
			}
			ptr := (l&0x3F)<<8 | int(msg[off+1])
			if next < 0 {
				next = off + 2
			}
			hops++
			if hops > 16 {
				return "", 0, errors.New("dns: compression pointer loop")
			}
			off = ptr
			continue
		}
		if off+1+l > len(msg) {
			return "", 0, errors.New("dns: truncated label")
		}
		labels = append(labels, string(msg[off+1:off+1+l]))
		off += 1 + l
	}
	if next >= 0 {
		off = next
	}
	return strings.Join(labels, "."), off, nil
}
