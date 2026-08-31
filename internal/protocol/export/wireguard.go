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

// WireGuardServerConf renders the SERVER wg-quick config for a WireGuard
// inbound the panel serves on the kernel datapath.
//
// WHY THIS EXISTS. The panel served WireGuard only as a sing-box userspace
// endpoint. Measured on one box, same client and same destination, the kernel
// datapath moves 2.24-2.49 Gbit/s where the userspace endpoint moves
// 0.74-0.83 — about three times the throughput, because the userspace path
// copies every packet through a netstack instead of encrypting in the kernel.
//
// It is deliberately NOT AmneziaWGServerConf minus the obfuscation: that
// function writes Jc/Jmin/Jmax/S1/S2/H1..H4 unconditionally, and wg-quick
// rejects a config carrying keys the plain module does not know.
func WireGuardServerConf(server *model.Node, peers []*model.Node) (string, error) {
	if server.Protocol != model.ProtoWireGuard || server.WireGuard == nil {
		return "", fmt.Errorf("export: not a wireguard node")
	}
	server = server.Clone()
	server.Normalize()
	w := server.WireGuard
	if w.PrivateKey == "" {
		return "", fmt.Errorf("export: wireguard server is missing its private key")
	}
	saddr := w.ServerAddress
	if len(saddr) == 0 {
		saddr = w.LocalAddress
	}
	if len(saddr) == 0 {
		saddr = []string{"10.66.66.1/24"}
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", w.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(saddr, ", "))
	fmt.Fprintf(&b, "ListenPort = %d\n", server.Port)
	if w.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", w.MTU)
	}

	// No PersistentKeepalive on any peer below. These are roaming clients whose
	// endpoint is unknown until they dial in, and keepalive means "send
	// unprompted packets TO this peer" — it belongs in the client config, which
	// WireGuardConf writes.
	wrote := 0
	if len(w.Peers) > 0 {
		for _, pe := range w.Peers {
			if pe.PublicKey == "" || len(pe.AllowedIPs) == 0 {
				continue
			}
			b.WriteString("\n[Peer]\n")
			fmt.Fprintf(&b, "PublicKey = %s\n", pe.PublicKey)
			if pe.PresharedKey != "" {
				fmt.Fprintf(&b, "PresharedKey = %s\n", pe.PresharedKey)
			}
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(pe.AllowedIPs, ", "))
			wrote++
		}
		if wrote == 0 {
			return "", fmt.Errorf("export: wireguard server has a peer list but no usable peer")
		}
		return b.String(), nil
	}
	for _, p := range peers {
		if p == nil || p.WireGuard == nil {
			continue
		}
		pw := p.WireGuard
		if pw.PeerPublicKey == "" || len(pw.PeerAddress) == 0 {
			continue
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", pw.PeerPublicKey)
		if pw.PreSharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", pw.PreSharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(pw.PeerAddress, ", "))
		wrote++
	}
	if wrote == 0 {
		return "", fmt.Errorf("export: wireguard server has no peer to serve")
	}
	return b.String(), nil
}
