package export

import (
	"fmt"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// WireGuardConf renders the standard wg-quick client configuration for a
// WireGuard node — the format every WireGuard and AmneziaWG client imports. The
// panel provisions both keypairs, so this is a complete, ready-to-connect config:
// the client's private key + tunnel address in [Interface], and the SERVER's
// public key + endpoint in [Peer]. host is the server's reachable address (the
// panel's public address is substituted before calling this).
func WireGuardConf(n *model.Node, host string) (string, error) {
	if n.Protocol != model.ProtoWireGuard || n.WireGuard == nil {
		return "", fmt.Errorf("export: not a wireguard node")
	}
	w := n.WireGuard
	if w.PeerPrivateKey == "" || w.PublicKey == "" {
		return "", fmt.Errorf("export: wireguard node is missing keys")
	}
	if host == "" {
		host = n.Address
	}
	addr := w.PeerAddress
	if len(addr) == 0 {
		addr = []string{"10.66.66.2/32"}
	}
	allowed := w.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	mtu := w.MTU
	if mtu == 0 {
		mtu = 1420
	}
	keep := w.Keepalive
	if keep == 0 {
		keep = 25
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", w.PeerPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addr, ", "))
	b.WriteString("DNS = 1.1.1.1, 8.8.8.8\n")
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", w.PublicKey)
	if w.PreSharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", w.PreSharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", host, n.Port)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keep)
	return b.String(), nil
}
