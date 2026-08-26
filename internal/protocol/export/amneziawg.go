package export

import (
	"fmt"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// awgObfuscation writes the AmneziaWG [Interface] obfuscation lines shared by the
// client and server configs. These MUST be identical on both ends of a tunnel.
func awgObfuscation(b *strings.Builder, a *model.AmneziaWGOptions) {
	fmt.Fprintf(b, "Jc = %d\n", a.Jc)
	fmt.Fprintf(b, "Jmin = %d\n", a.Jmin)
	fmt.Fprintf(b, "Jmax = %d\n", a.Jmax)
	fmt.Fprintf(b, "S1 = %d\n", a.S1)
	fmt.Fprintf(b, "S2 = %d\n", a.S2)
	fmt.Fprintf(b, "H1 = %d\n", a.H1)
	fmt.Fprintf(b, "H2 = %d\n", a.H2)
	fmt.Fprintf(b, "H3 = %d\n", a.H3)
	fmt.Fprintf(b, "H4 = %d\n", a.H4)
}

// AmneziaWGConf renders the CLIENT awg-quick configuration for an AmneziaWG node:
// a standard wg-quick config plus the AmneziaWG obfuscation parameters in
// [Interface]. It imports unchanged into the AmneziaWG client app or into
// awg-quick with the kernel module. host is the server's reachable address.
func AmneziaWGConf(n *model.Node, host string) (string, error) {
	if n.Protocol != model.ProtoAmneziaWG || n.AmneziaWG == nil {
		return "", fmt.Errorf("export: not an amneziawg node")
	}
	a := n.AmneziaWG
	w := &a.WireGuardOptions
	if w.PeerPrivateKey == "" || w.PublicKey == "" {
		return "", fmt.Errorf("export: amneziawg node is missing keys")
	}
	if host == "" {
		host = n.Address
	}
	addr := w.PeerAddress
	if len(addr) == 0 {
		addr = []string{"10.67.67.2/32"}
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
	awgObfuscation(&b, a)
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

// AmneziaWGServerConf renders the SERVER awg-quick config the kernel-mode engine
// writes to /etc/amnezia/amneziawg/<iface>.conf: the server [Interface] (its own
// private key, ListenPort, tunnel Address and the obfuscation params) plus one
// [Peer] block per bound client (the client's public key, AllowedIPs pinned to
// that client's tunnel IP). peers are the per-user materialized nodes.
func AmneziaWGServerConf(server *model.Node, peers []*model.Node) (string, error) {
	if server.Protocol != model.ProtoAmneziaWG || server.AmneziaWG == nil {
		return "", fmt.Errorf("export: not an amneziawg node")
	}
	a := server.AmneziaWG
	w := &a.WireGuardOptions
	if w.PrivateKey == "" {
		return "", fmt.Errorf("export: amneziawg server is missing its private key")
	}
	saddr := w.ServerAddress
	if len(saddr) == 0 {
		saddr = []string{"10.67.67.1/24"}
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", w.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(saddr, ", "))
	fmt.Fprintf(&b, "ListenPort = %d\n", server.Port)
	awgObfuscation(&b, a)
	// Per-client peers when the panel has resolved them. This is the path that
	// makes several users on one WireGuard inbound possible at all; the loop
	// below stays for an inbound with none assigned, which renders exactly as
	// it always did.
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
		}
		return b.String(), nil
	}
	for _, p := range peers {
		if p == nil || p.AmneziaWG == nil {
			continue
		}
		pw := &p.AmneziaWG.WireGuardOptions
		if pw.PeerPublicKey == "" || len(pw.PeerAddress) == 0 {
			continue
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", pw.PeerPublicKey)
		if pw.PreSharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", pw.PreSharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(pw.PeerAddress, ", "))
	}
	return b.String(), nil
}
