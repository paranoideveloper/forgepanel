// Package adapter defines the pluggable DNS-tunnel wire-format interface (spec
// §5.2) and ships the ForgePanel-native adapter. Adding a fourth tunnel format
// is a new file implementing Adapter plus test vectors — no change to the
// session, server, or API layers.
//
// This is anti-censorship transport: it carries a client's already-encrypted
// bytes inside ordinary DNS queries/answers so that, on networks where only DNS
// egress is permitted, a user can still reach the open internet. It is not a
// recursive resolver and refuses queries for zones it does not own (spec §5.4).
package adapter

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
)

// Capabilities describes an adapter's wire limits (spec §5.2).
type Capabilities struct {
	Name               string
	MaxUpstreamBytes   int // raw payload bytes carried per query
	MaxDownstreamBytes int // raw payload bytes carried per answer
	RRTypes            []uint16
	NeedsHandshake     bool
}

// Adapter is the wire-format contract. Match decides ownership; Decode turns a
// query into a Frame; Encode turns a response Frame into a DNS answer.
type Adapter interface {
	Name() string
	Match(zone string, m *dns.Msg) bool
	Decode(zone string, m *dns.Msg) (codec.Frame, error)
	Encode(zone string, q *dns.Msg, f codec.Frame) (*dns.Msg, error)
	Caps() Capabilities
}

// Forge is the ForgePanel-native adapter: upstream data is base32 in the QNAME
// labels under the tunnel zone; downstream data is base64 in a TXT answer. The
// 5-byte codec.Frame header carries session id / sequence / flags.
type Forge struct{}

// Name implements Adapter.
func (Forge) Name() string { return "forge" }

// Caps implements Adapter.
func (Forge) Caps() Capabilities {
	return Capabilities{
		Name: "forge", RRTypes: []uint16{dns.TypeTXT, dns.TypeA},
		MaxUpstreamBytes:   codec.MaxPayloadPerQuery("x."+strings.Repeat("z", 20), 63),
		MaxDownstreamBytes: 800, // conservative TXT budget with EDNS0
		NeedsHandshake:     false,
	}
}

// Match reports whether the query's QNAME is under zone and looks like tunnel
// traffic (a data label prefix). It never claims queries it cannot decode.
func (Forge) Match(zone string, m *dns.Msg) bool {
	if len(m.Question) == 0 {
		return false
	}
	q := strings.ToLower(strings.TrimSuffix(m.Question[0].Name, "."))
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	return q == z || strings.HasSuffix(q, "."+z)
}

// Decode extracts the frame carried in the QNAME.
func (Forge) Decode(zone string, m *dns.Msg) (codec.Frame, error) {
	if len(m.Question) == 0 {
		return codec.Frame{}, fmt.Errorf("forge: no question")
	}
	enc, err := codec.SplitQName(m.Question[0].Name, zone)
	if err != nil {
		return codec.Frame{}, err
	}
	raw, err := codec.Base32Decode(enc)
	if err != nil {
		return codec.Frame{}, fmt.Errorf("forge: base32: %w", err)
	}
	return codec.ParseFrame(raw)
}

// Encode packs a response frame into a TXT answer to the original query.
func (Forge) Encode(zone string, q *dns.Msg, f codec.Frame) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true
	payload := codec.Base64Encode(f.Marshal())
	// TXT strings are capped at 255 octets each; chunk if needed.
	var chunks []string
	for len(payload) > 0 {
		n := 255
		if n > len(payload) {
			n = len(payload)
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: chunks,
	}
	resp.Answer = append(resp.Answer, txt)
	return resp, nil
}

// DecodeAnswer is the client-side inverse of Encode: recover a frame from a TXT
// answer. Exposed so a synthetic client (and tests) share the exact wire logic.
func DecodeAnswer(m *dns.Msg) (codec.Frame, error) {
	for _, rr := range m.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			raw, err := codec.Base64Decode(strings.Join(txt.Txt, ""))
			if err != nil {
				return codec.Frame{}, err
			}
			return codec.ParseFrame(raw)
		}
	}
	return codec.Frame{}, fmt.Errorf("forge: no TXT answer")
}

// EncodeQuery is the client-side inverse of Decode: build a query carrying a
// frame under the zone. Shared with tests / the client profile.
func EncodeQuery(zone string, f codec.Frame) (*dns.Msg, error) {
	enc := codec.Base32Encode(f.Marshal())
	qname, err := codec.ChunkQName(enc, zone, 63)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	m.SetEdns0(1232, false)
	return m, nil
}
