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
