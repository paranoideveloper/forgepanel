package adapter

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
)

// This file provides the panel-selectable, named DNS-tunnel adapters. All share
// the same case-insensitive base32 QNAME upstream (the only DNS-safe choice for
// the query side); they differ in the DOWNSTREAM resource record, which is what
// distinguishes real DNS tunnels in practice and what a client's recursive
// resolver may or may not pass through:
//
//   - forge / stormdns : base64 in a TXT answer   (highest throughput)
//   - masterdns        : base32 in a CNAME answer (survives TXT-stripping resolvers)
//   - cottendns        : hex in an A-record chain (lowest MTU, most permissive)
//
// The exact byte-for-byte wire formats of the upstream StormDNS/MasterDNS/
// CottenDNS *clients* require their repositories to reproduce; these are the
// interoperable ForgePanel modes exposed under those names so an operator can
// pick a downstream encoding from the panel without touching a terminal. Adding
// a fourth is a new entry in Registry.

// DownstreamRR selects the downstream answer encoding.
type DownstreamRR int

const (
	DownTXT DownstreamRR = iota
	DownCNAME
	DownA
)

// variant is a Forge adapter parameterised by name + downstream encoding.
type variant struct {
	name string
	down DownstreamRR
}

func (v variant) Name() string                       { return v.name }
func (v variant) Match(zone string, m *dns.Msg) bool { return Forge{}.Match(zone, m) }
func (v variant) Decode(zone string, m *dns.Msg) (codec.Frame, error) {
	return Forge{}.Decode(zone, m)
}
func (v variant) Caps() Capabilities {
	c := Forge{}.Caps()
	c.Name = v.name
	switch v.down {
	case DownCNAME:
		c.MaxDownstreamBytes = 120
		c.RRTypes = []uint16{dns.TypeCNAME}
	case DownA:
		c.MaxDownstreamBytes = 60
		c.RRTypes = []uint16{dns.TypeA}
	default:
		c.RRTypes = []uint16{dns.TypeTXT}
	}
	return c
}

// Encode packs the response frame using this variant's downstream encoding.
func (v variant) Encode(zone string, q *dns.Msg, f codec.Frame) (*dns.Msg, error) {
	switch v.down {
	case DownCNAME:
		return encodeCNAME(zone, q, f)
	case DownA:
		return encodeA(q, f)
	default:
		return Forge{}.Encode(zone, q, f)
	}
}

func encodeCNAME(zone string, q *dns.Msg, f codec.Frame) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true
	enc := codec.Base32Encode(f.Marshal())
	target, err := codec.ChunkQName(enc, "data."+strings.TrimSuffix(zone, "."), 63)
	if err != nil {
		return nil, err
	}
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 0},
		Target: dns.Fqdn(target),
	})
	return resp, nil
}

func encodeA(q *dns.Msg, f codec.Frame) (*dns.Msg, error) {
	// Pack up to 3 payload bytes into the low octets of a 10.x.x.x A record; the
	// header seq lets the client order the chain. Deliberately low-MTU but works
	// through resolvers that only pass A records.
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true
	raw := f.Marshal()
	b := [4]byte{10, 0, 0, 0}
	for i := 0; i < 3 && i < len(raw); i++ {
		b[i+1] = raw[i]
	}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   b[:],
	})
	return resp, nil
}

// Registry maps an adapter name to its implementation. The panel populates the
// adapter dropdown from Names() and instantiates by Get(name).
var registry = map[string]Adapter{
	"forge":     Forge{},
	"stormdns":  variant{name: "stormdns", down: DownTXT},
	"masterdns": variant{name: "masterdns", down: DownCNAME},
	"cottendns": variant{name: "cottendns", down: DownA},
}

// Get returns the adapter registered under name (case-insensitive).
func Get(name string) (Adapter, error) {
	a, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, fmt.Errorf("adapter: unknown wire format %q", name)
	}
	return a, nil
}

// Names lists the selectable adapter names for the panel dropdown.
func Names() []string { return []string{"forge", "stormdns", "masterdns", "cottendns"} }
