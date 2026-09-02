package export

import (
	"fmt"
	"net/netip"
	"strings"
)

// wgQuickNAT writes the PostUp/PostDown lines that make a kernel WireGuard or
// AmneziaWG server actually carry traffic.
//
// WHY THIS IS NOT OPTIONAL. Without it the tunnel comes up and does nothing
// useful: the handshake completes, the client can ping the server's own tunnel
// address, and every packet aimed anywhere else leaves the box with a private
// source address and is never answered. That is exactly the state a live panel
// was found in — both its WireGuard and AmneziaWG inbounds handshaking, pinging
// the gateway, and reaching no part of the internet. Adding only this rule by
// hand took the AmneziaWG inbound from nothing to 1MB at 21.7 MB/s.
//
// MASQUERADE carries no -o interface on purpose. The egress interface is not
// knowable when the config is generated — it differs per host (enp1s0, ens3,
// eth0) and can change under the operator — and a rule naming the wrong one
// silently does nothing. Matching on the tunnel's own source prefix is precise
// enough: nothing else on the box uses it.
//
// The FORWARD accepts are there because a host whose default FORWARD policy is
// DROP would otherwise pass NAT and still discard the packet, which looks
// identical to having no NAT at all.
func wgQuickNAT(b *strings.Builder, serverAddrs []string) {
	subnets := natSubnets(serverAddrs)
	if len(subnets) == 0 {
		return
	}
	var up, down []string
	for _, s := range subnets {
		up = append(up, fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -j MASQUERADE", s))
		down = append(down, fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -j MASQUERADE", s))
	}
	up = append(up,
		"iptables -A FORWARD -i %i -j ACCEPT",
		"iptables -A FORWARD -o %i -j ACCEPT",
		"sysctl -q -w net.ipv4.ip_forward=1")
	down = append(down,
		"iptables -D FORWARD -i %i -j ACCEPT",
		"iptables -D FORWARD -o %i -j ACCEPT")

	// `|| true` on teardown: awg-quick/wg-quick abort a PostDown chain on the
	// first failure, and a rule already removed (a crash, a manual cleanup)
	// would then leave the interface half torn down.
	fmt.Fprintf(b, "PostUp = %s\n", strings.Join(up, "; "))
	fmt.Fprintf(b, "PostDown = %s || true\n", strings.Join(down, "; "))
}

// natSubnets turns the server's own tunnel addresses into the prefixes to
// masquerade. A bare host address with no prefix length is skipped rather than
// guessed at: masquerading a /32 would cover the server and none of its peers.
func natSubnets(addrs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" || !strings.Contains(a, "/") {
			continue
		}
		p, err := netip.ParsePrefix(a)
		if err != nil || !p.Addr().Is4() {
			continue // IPv6 tunnels would need ip6tables; not emitted rather than emitted wrong
		}
		if p.Bits() >= 31 {
			continue
		}
		masked := p.Masked().String()
		if !seen[masked] {
			seen[masked] = true
			out = append(out, masked)
		}
	}
	return out
}

// matchAllowedIPsToTunnel drops address families the tunnel cannot carry.
//
// The panel allocates an IPv4 tunnel address and advertised
// "AllowedIPs = 0.0.0.0/0, ::/0" regardless. wg-quick and every AmneziaWG
// client then install a ::/0 route into an interface that has no IPv6 address,
// so every IPv6 packet is dropped at the source-address lookup.
//
// On an IPv4-only test host that is invisible — which is exactly why it
// survived: netns tests, a Linux client, a server with no v6 in the tunnel, all
// pass. On a real dual-stack device it is severe. Happy-eyeballs prefers AAAA,
// most large sites publish one, and the user sees a tunnel that connects,
// shows a handshake, pings the gateway, and cannot load Google.
//
// So the client is offered only what the tunnel can actually deliver.
func matchAllowedIPsToTunnel(allowed, tunnelAddrs []string) []string {
	var hasV4, hasV6 bool
	for _, a := range tunnelAddrs {
		s := strings.TrimSpace(a)
		if s == "" {
			continue
		}
		if i := strings.Index(s, "/"); i >= 0 {
			s = s[:i]
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if ip.Is4() {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	// Nothing parseable: leave the operator's list alone rather than empty it.
	if !hasV4 && !hasV6 {
		return allowed
	}
	out := make([]string, 0, len(allowed))
	for _, a := range allowed {
		s := strings.TrimSpace(a)
		if s == "" {
			continue
		}
		isV6 := strings.Contains(s, ":")
		if isV6 && !hasV6 {
			continue
		}
		if !isV6 && !hasV4 {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return allowed
	}
	return out
}
