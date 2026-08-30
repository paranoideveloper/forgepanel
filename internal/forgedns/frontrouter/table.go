package frontrouter

import (
	"fmt"
	"sort"
	"strings"
)

// Backend is one tunnel sitting behind the shared public port.
//
// UDPAddr and TCPAddr are separate because the two are not interchangeable: a
// tunnel may accept UDP on one private port and DNS-over-TCP on another, and
// several accept no TCP at all. Routing TCP to a UDP-only backend produces a
// connection that hangs rather than an error the operator can see, so an empty
// TCPAddr means "this backend does not serve TCP" and is refused explicitly.
type Backend struct {
	// Name identifies the backend in logs and the API. It is the zone name in
	// practice, and it is what an operator sees when a route misfires.
	Name string
	// Suffixes are the tunnel domains this backend owns. A zone can be
	// authoritative for several at once, which is why this is a list.
	Suffixes []string
	UDPAddr  string
	TCPAddr  string
	// TLSAddr and HTTPSAddr are the backend's private DNS-over-TLS and
	// DNS-over-HTTPS listeners. Empty means the zone does not serve that
	// protocol, and the router refuses the stream rather than dialling nothing
	// — an empty dial target produces a hang, which reads as a broken backend.
	TLSAddr   string
	HTTPSAddr string
}

// route is one flattened suffix -> backend pair.
type route struct {
	suffix  string
	backend Backend
}

// Table resolves a QNAME to the backend that owns it.
//
// Longest suffix wins. Routes are sorted once at construction by descending
// suffix length, so matching is a linear scan that returns the most specific
// route first. The table is immutable after New, which is what makes it safe to
// share across every goroutine serving the public socket without a lock.
type Table struct {
	routes []route
}

// NewTable builds the routing table.
//
// It refuses duplicate suffixes rather than silently preferring one. Two
// backends claiming the same tunnel domain is a configuration mistake with no
// correct resolution: whichever the sort happened to place first would win, and
// the operator would see traffic vanish into the wrong tunnel with nothing
// logged.
func NewTable(backends []Backend) (*Table, error) {
	routes := make([]route, 0, len(backends))
	owner := make(map[string]string, len(backends))

	for _, b := range backends {
		if strings.TrimSpace(b.Name) == "" {
			return nil, fmt.Errorf("frontrouter: backend with suffixes %v has no name", b.Suffixes)
		}
		if strings.TrimSpace(b.UDPAddr) == "" {
			return nil, fmt.Errorf("frontrouter: backend %q has no UDP address", b.Name)
		}
		if len(b.Suffixes) == 0 {
			return nil, fmt.Errorf("frontrouter: backend %q claims no domain, so nothing can route to it", b.Name)
		}
		for _, raw := range b.Suffixes {
			suffix, err := NormalizeSuffix(raw)
			if err != nil {
				return nil, fmt.Errorf("frontrouter: backend %q: %w", b.Name, err)
			}
			if prev, taken := owner[suffix]; taken {
				return nil, fmt.Errorf("frontrouter: %q is claimed by both %q and %q; "+
					"one tunnel domain can only belong to one backend", suffix, prev, b.Name)
			}
			owner[suffix] = b.Name
			routes = append(routes, route{suffix: suffix, backend: b})
		}
	}

	// Longest first, so the scan below returns the most specific match. Ties are
	// broken alphabetically purely to make the order deterministic — two
	// suffixes of equal length can never both match the same name anyway.
	sort.Slice(routes, func(i, j int) bool {
		if len(routes[i].suffix) != len(routes[j].suffix) {
			return len(routes[i].suffix) > len(routes[j].suffix)
		}
		return routes[i].suffix < routes[j].suffix
	})
	return &Table{routes: routes}, nil
}

// Match returns the backend owning a QNAME.
//
// DELEGATION NOTE: a name matches a suffix when it IS the suffix, so listing the
// delegated zone itself as a suffix is what makes the ZONE APEX routable. That
// matters more than it looks. Measured against real resolvers: tunnel traffic
// under t1.<zone> resolved correctly through 1.1.1.1, 8.8.8.8 and 9.9.9.9 while
// SOA and NS queries for <zone> itself were dropped, because no backend claimed
// the bare name. Registrars and monitoring probe the apex, and a zone whose apex
// never answers looks broken even though every tunnel through it works.
// ForgePanel's own authoritative server documents the same trap: answering the
// apex NXDOMAIN "makes the zone undelegatable".
//
// A name matches a suffix when it IS the suffix or ends with "."+suffix. The
// dot is what makes this safe: a plain strings.HasSuffix would route
// "notexample.com" to the backend that owns "example.com", handing an attacker
// a way to reach a tunnel by registering a name that merely ends with the same
// letters.
func (t *Table) Match(qname string) (Backend, bool) {
	if t == nil {
		return Backend{}, false
	}
	qname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	for _, r := range t.routes {
		if qname == r.suffix || strings.HasSuffix(qname, "."+r.suffix) {
			return r.backend, true
		}
	}
	return Backend{}, false
}

// Routes reports the flattened suffix -> backend-name pairs in match order, for
// the API and for diagnostics. An operator debugging "why did this go there"
// needs to see the order the router actually evaluates.
func (t *Table) Routes() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.routes))
	for _, r := range t.routes {
		out = append(out, r.suffix+" -> "+r.backend.Name)
	}
	return out
}

// NormalizeSuffix canonicalises a configured tunnel domain.
func NormalizeSuffix(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if domain == "" {
		return "", fmt.Errorf("empty tunnel domain")
	}
	// 253 characters is the presentation-form equivalent of the 255-octet wire
	// limit, so a suffix longer than this could never match a legal QNAME.
	if len(domain) > 253 {
		return "", fmt.Errorf("tunnel domain %q exceeds 253 characters", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return "", fmt.Errorf("tunnel domain %q has an empty label", domain)
		}
		if len(label) > maxLabelLen {
			return "", fmt.Errorf("tunnel domain %q has a label longer than %d characters", domain, maxLabelLen)
		}
	}
	return domain, nil
}
