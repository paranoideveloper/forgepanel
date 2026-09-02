// Package wgpeer manages per-client WireGuard/AmneziaWG peers: their tunnel
// addresses, their keys, and the lifecycle of both.
//
// What it replaces: a WireGuard inbound carried exactly ONE client keypair and
// ONE peer address, so "assign five users to this WireGuard inbound" could not
// be expressed at all. Every user handed the same private key and the same
// tunnel IP does not merely leak between them — it does not work: WireGuard
// keys an endpoint by public key, so the second client to connect takes the
// session away from the first, repeatedly.
//
// The server-config renderer has always accepted a LIST of peers. Both callers
// passed a one-element slice containing the inbound itself.
package wgpeer

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// ReuseCooldown is how long a released tunnel address is held back before it can
// be handed to a different client.
//
// Not tidiness. A peer that is removed and whose address is immediately given to
// someone else meets a fleet of clients — and a server routing table — that
// still believe the old owner is there: packets for the new client's session get
// matched against the old peer's AllowedIPs, and traffic lands on the wrong
// tunnel. Waiting longer than any plausible handshake retry makes the address
// genuinely free before it moves.
const ReuseCooldown = 30 * time.Minute

// Pool is an address range a peer can be allocated from.
type Pool struct {
	prefix netip.Prefix
	// server is the server's own address in this prefix, which is never handed
	// out.
	server netip.Addr
}

// Reservation is one address that is not available.
type Reservation struct {
	Addr netip.Addr
	// ReleasedAt is when the address stopped being in use. Zero means it is
	// still held by a live peer.
	ReleasedAt time.Time
}

// NewPool builds an allocation pool from a server address in CIDR form, such as
// "10.66.66.1/24".
func NewPool(serverCIDR string) (*Pool, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(serverCIDR))
	if err != nil {
		return nil, fmt.Errorf("wgpeer: %q is not an address with a prefix (expected something like 10.66.66.1/24): %w", serverCIDR, err)
	}
	// A /32 or /128 leaves no room for a single client, and silently returning
	// an empty pool would look like "the server is full" rather than "this
	// inbound was configured with no room for anyone".
	if p.Addr().Is4() && p.Bits() > 30 {
		return nil, fmt.Errorf("wgpeer: %s has no room for clients — use /30 or wider", serverCIDR)
	}
	if p.Addr().Is6() && p.Bits() > 126 {
		return nil, fmt.Errorf("wgpeer: %s has no room for clients — use /126 or wider", serverCIDR)
	}
	return &Pool{prefix: p.Masked(), server: p.Addr()}, nil
}

// ErrPoolExhausted is returned when every address in the range is taken.
var ErrPoolExhausted = errors.New("wgpeer: no free tunnel address in this inbound's range")

// Allocate returns the lowest free address, honouring the reuse cooldown.
//
// Lowest-free rather than random so an operator reading `wg show` sees a
// contiguous block that matches the order clients were added, which is what
// makes an unexpected peer obvious.
func (p *Pool) Allocate(taken []Reservation, now time.Time) (netip.Addr, error) {
	blocked := map[netip.Addr]bool{}
	for _, r := range taken {
		if !r.Addr.IsValid() {
			continue
		}
		if r.ReleasedAt.IsZero() || now.Sub(r.ReleasedAt) < ReuseCooldown {
			blocked[r.Addr] = true
		}
	}
	for addr := range p.iter() {
		if addr == p.server || blocked[addr] {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// iter yields every assignable address in the prefix, lowest first.
//
// The network and broadcast addresses of an IPv4 prefix are skipped: handing
// out the broadcast address produces a peer that some stacks answer for and
// others drop, which is an intermittent fault nobody would trace back to
// address allocation.
func (p *Pool) iter() func(func(netip.Addr) bool) {
	return func(yield func(netip.Addr) bool) {
		addr := p.prefix.Addr()
		isV4 := addr.Is4()
		last := lastAddr(p.prefix)
		if isV4 {
			addr = addr.Next() // skip the network address
		}
		for addr.IsValid() && p.prefix.Contains(addr) {
			if isV4 && addr == last {
				return // skip the broadcast address
			}
			if !yield(addr) {
				return
			}
			addr = addr.Next()
		}
	}
}

// lastAddr is the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	bytes := a.AsSlice()
	bits := p.Bits()
	for i := range bytes {
		lo := i * 8
		for b := 0; b < 8; b++ {
			if lo+b >= bits {
				bytes[i] |= 1 << (7 - b)
			}
		}
	}
	out, _ := netip.AddrFromSlice(bytes)
	return out
}

// HostCIDR renders an address as a single-host CIDR, which is what a peer's
// AllowedIPs and a client's Address both need.
//
// /32 (or /128), NOT the server's prefix. A client whose Address carries the
// whole /24 claims the entire tunnel subnet as on-link and stops routing to any
// other peer through the server; on the server side, AllowedIPs wider than one
// host lets a peer receive traffic addressed to its neighbours.
func HostCIDR(a netip.Addr) string {
	if a.Is4() {
		return a.String() + "/32"
	}
	return a.String() + "/128"
}

// SortReservations orders reservations by address, for stable output.
func SortReservations(rs []Reservation) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Addr.Less(rs[j].Addr) })
}
