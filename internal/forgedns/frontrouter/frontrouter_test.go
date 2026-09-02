package frontrouter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// buildQuery assembles a DNS query for name, so the parser tests exercise real
// wire bytes rather than a convenient abstraction.
func buildQuery(name string) []byte {
	p := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(p[2:4], 0x0100) // standard query, RD set
	binary.BigEndian.PutUint16(p[4:6], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		p = append(p, byte(len(label)))
		p = append(p, label...)
	}
	return append(p, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN
}

// repeatedLabels builds a query carrying count labels of size bytes each.
func repeatedLabels(count, size int) []byte {
	p := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(p[4:6], 1)
	for i := 0; i < count; i++ {
		p = append(p, byte(size))
		p = append(p, bytes.Repeat([]byte{'a'}, size)...)
	}
	return append(p, 0, 0, 1, 0, 1)
}

func TestQuestionNameReadsTheFirstQuestion(t *testing.T) {
	got, err := QuestionName(buildQuery("AbC.Tunnel.Example.COM"))
	if err != nil {
		t.Fatalf("QuestionName: %v", err)
	}
	if got != "abc.tunnel.example.com" {
		t.Fatalf("name = %q, want lower-cased abc.tunnel.example.com", got)
	}
}

func TestQuestionNameRejectsMalformedInput(t *testing.T) {
	compressed := append(make([]byte, dnsHeaderLen), 0xc0, 0x0c)
	binary.BigEndian.PutUint16(compressed[4:6], 1)

	response := buildQuery("a.example.com")
	binary.BigEndian.PutUint16(response[2:4], 0x8180) // QR set

	noQuestion := buildQuery("a.example.com")
	binary.BigEndian.PutUint16(noQuestion[4:6], 0)

	dotted := append(make([]byte, dnsHeaderLen), 3, 'a', '.', 'b', 0, 0, 1, 0, 1)
	binary.BigEndian.PutUint16(dotted[4:6], 1)

	for _, tc := range []struct {
		name   string
		packet []byte
		want   error
	}{
		{"short packet", []byte{1, 2, 3}, ErrShortPacket},
		{"response not query", response, ErrNotQuery},
		{"no question", noQuestion, ErrNoQuestion},
		{"compression pointer", compressed, ErrCompressedQNAME},
		{"unterminated name", buildQuery("example.com")[:20], ErrUnterminatedName},
		{"dot inside a label", dotted, ErrInvalidLabel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := QuestionName(tc.packet); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A name past the 255-octet wire limit must be refused before it is built.
// Without the mid-walk check a single 64 KB DNS-over-TCP query yields a ~64 KB
// label slice and two ~64 KB strings, all on a public port, before any routing
// decision is taken.
func TestQuestionNameRejectsOversizedName(t *testing.T) {
	if _, err := QuestionName(repeatedLabels(1000, 63)); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("1000 x 63-byte labels: err = %v, want ErrNameTooLong", err)
	}
	// 4 x 63-byte labels encode to 4*(1+63)+1 = 257 octets: just over.
	if _, err := QuestionName(repeatedLabels(4, 63)); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("257-octet name: err = %v, want ErrNameTooLong", err)
	}
}

// The limit must not be over-tightened. DNS tunnels deliberately use names close
// to the maximum to carry as much payload per query as possible, so refusing a
// legal 253-octet name would throttle the very traffic this router carries.
func TestQuestionNameAcceptsMaximumLengthName(t *testing.T) {
	p := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(p[4:6], 1)
	for i := 0; i < 3; i++ { // 3 * (1+63) = 192
		p = append(p, 63)
		p = append(p, bytes.Repeat([]byte{'a'}, 63)...)
	}
	p = append(p, 59) // + (1+59) = 252, + root = 253 octets
	p = append(p, bytes.Repeat([]byte{'b'}, 59)...)
	p = append(p, 0, 0, 1, 0, 1)

	name, err := QuestionName(p)
	if err != nil {
		t.Fatalf("a legal maximum-length name was refused: %v", err)
	}
	if len(name) != 251 {
		t.Fatalf("name length = %d, want 251 (3*63 + 59 + 3 dots)", len(name))
	}
}

func testTable(t *testing.T) *Table {
	t.Helper()
	tbl, err := NewTable([]Backend{
		{Name: "generic", Suffixes: []string{"t.example.com"}, UDPAddr: "127.0.0.1:5301"},
		{Name: "deep", Suffixes: []string{"deep.t.example.com"}, UDPAddr: "127.0.0.1:5302", TCPAddr: "127.0.0.1:5302"},
		{Name: "multi", Suffixes: []string{"a.example.net", "b.example.org"}, UDPAddr: "127.0.0.1:5303"},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	return tbl
}

func TestTableMatchesLongestSuffix(t *testing.T) {
	tbl := testTable(t)
	for _, tc := range []struct{ qname, want string }{
		{"x.t.example.com", "generic"},
		{"t.example.com", "generic"},
		{"payload.deep.t.example.com", "deep"}, // more specific wins over generic
		{"deep.t.example.com", "deep"},
		{"q.a.example.net", "multi"},
		{"q.b.example.org", "multi"}, // one backend, several tunnel domains
		{"X.T.EXAMPLE.COM.", "generic"},
	} {
		got, ok := tbl.Match(tc.qname)
		if !ok {
			t.Errorf("%q did not match any backend", tc.qname)
			continue
		}
		if got.Name != tc.want {
			t.Errorf("%q -> %q, want %q", tc.qname, got.Name, tc.want)
		}
	}
}

// The dot in the suffix comparison is load-bearing. A bare strings.HasSuffix
// would send "notexample.com" to the backend owning "example.com", which lets
// anyone reach a tunnel by registering a name that merely ends with the same
// letters.
func TestTableDoesNotMatchOnUnanchoredSuffix(t *testing.T) {
	tbl := testTable(t)
	for _, qname := range []string{
		"nott.example.com",   // shares the tail, different label
		"t.example.com.evil", // suffix appears, but not at the end
		"example.com",        // parent of the route, not covered by it
		"com",
		"",
	} {
		if b, ok := tbl.Match(qname); ok {
			t.Errorf("%q wrongly matched backend %q", qname, b.Name)
		}
	}
}

func TestNewTableRejectsUnroutableConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		backends []Backend
		wantSub  string
	}{
		{"duplicate suffix across backends",
			[]Backend{
				{Name: "one", Suffixes: []string{"t.example.com"}, UDPAddr: "127.0.0.1:1"},
				{Name: "two", Suffixes: []string{"T.example.com."}, UDPAddr: "127.0.0.1:2"},
			}, "claimed by both"},
		{"backend with no domain",
			[]Backend{{Name: "orphan", UDPAddr: "127.0.0.1:1"}}, "claims no domain"},
		{"backend with no udp address",
			[]Backend{{Name: "noaddr", Suffixes: []string{"t.example.com"}}}, "no UDP address"},
		{"backend with no name",
			[]Backend{{Suffixes: []string{"t.example.com"}, UDPAddr: "127.0.0.1:1"}}, "has no name"},
		{"label too long",
			[]Backend{{Name: "big", Suffixes: []string{strings.Repeat("a", 64) + ".com"}, UDPAddr: "127.0.0.1:1"}},
			"label longer than"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTable(tc.backends)
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// Match order is what an operator reasons about when a query lands in the wrong
// tunnel, so Routes must report the order actually evaluated.
func TestRoutesReportMatchOrder(t *testing.T) {
	got := testTable(t).Routes()
	if len(got) != 4 {
		t.Fatalf("routes = %v, want 4 entries", got)
	}
	if !strings.HasPrefix(got[0], "deep.t.example.com ->") {
		t.Fatalf("longest suffix must be evaluated first, got %v", got)
	}
}

// The zone apex must be routable when a backend claims the bare zone.
//
// This is the delegation trap: measured against real resolvers, traffic under
// t1.<zone> resolved fine through 1.1.1.1, 8.8.8.8 and 9.9.9.9 while SOA/NS
// queries for <zone> itself were dropped, because no backend owned the bare
// name. Registrars and monitoring probe the apex, so a zone whose apex never
// answers looks broken even though every tunnel through it works.
func TestApexIsRoutableWhenABackendClaimsTheBareZone(t *testing.T) {
	zone := "dnslab.example.com"
	tbl, err := NewTable([]Backend{
		{Name: "primary", Suffixes: []string{"t1." + zone, zone}, UDPAddr: "127.0.0.1:5301"},
		{Name: "deep", Suffixes: []string{"deep.t1." + zone}, UDPAddr: "127.0.0.1:5302"},
	})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	// The apex itself resolves...
	if b, ok := tbl.Match(zone); !ok || b.Name != "primary" {
		t.Fatalf("apex %q -> %+v ok=%v, want the primary backend", zone, b, ok)
	}
	// ...and claiming the apex must not swallow the more specific routes.
	if b, ok := tbl.Match("payload.deep.t1." + zone); !ok || b.Name != "deep" {
		t.Fatalf("deep route lost to the apex claim: %+v ok=%v", b, ok)
	}
	if b, ok := tbl.Match("x.t1." + zone); !ok || b.Name != "primary" {
		t.Fatalf("t1 route broken: %+v ok=%v", b, ok)
	}
	// A sibling zone that merely ends the same way must still not match.
	if b, ok := tbl.Match("notdnslab.example.com"); ok {
		t.Fatalf("unanchored suffix matched %q", b.Name)
	}
}
