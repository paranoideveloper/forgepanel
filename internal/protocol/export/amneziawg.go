package export

import (
	"fmt"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// awgObfuscation writes the AmneziaWG [Interface] obfuscation lines shared by the
// client and server configs. These MUST be identical on both ends of a tunnel.
func awgObfuscation(b *strings.Builder, a *model.AmneziaWGOptions) {
	// Emitted by GENERATION, not "everything that happens to be set".
	// AmneziaWG parameters are two-sided: a 3.x key in a config whose peer
	// speaks 1.5 does not degrade, it stops the handshake. Writing only the
	// selected generation's keys is what keeps a config connectable.
	fmt.Fprintf(b, "Jc = %d\n", a.Jc)
	fmt.Fprintf(b, "Jmin = %d\n", a.Jmin)
	fmt.Fprintf(b, "Jmax = %d\n", a.Jmax)
	fmt.Fprintf(b, "S1 = %d\n", a.S1)
	fmt.Fprintf(b, "S2 = %d\n", a.S2)
	line(b, "H1", a.H1)
	line(b, "H2", a.H2)
	line(b, "H3", a.H3)
	line(b, "H4", a.H4)

	if a.AtLeast(model.AWG20) {
		// S3/S4 and the I1..I3 custom junk packets.
		fmt.Fprintf(b, "S3 = %d\n", a.S3)
		fmt.Fprintf(b, "S4 = %d\n", a.S4)
		for _, kv := range []struct {
			k, v string
		}{{"I1", a.I1}, {"I2", a.I2}, {"I3", a.I3}} {
			if strings.TrimSpace(kv.v) != "" {
				fmt.Fprintf(b, "%s = %s\n", kv.k, kv.v)
			}
		}
	}

	if a.AtLeast(model.AWG30) {
		if a.HeaderProtectionKey != "" {
			fmt.Fprintf(b, "HeaderProtectionKey = %s\n", a.HeaderProtectionKey)
		}
		line(b, "ContentPaddingAddition", a.ContentPaddingAddition)
		line(b, "RekeyAfterTime", a.RekeyAfterTime)
		line(b, "RekeyTimeout", a.RekeyTimeout)
		line(b, "RejectAfterTime", a.RejectAfterTime)
		line(b, "KeepaliveTimeout", a.KeepaliveTimeout)
		line(b, "MaxHandshakeAttempts", a.MaxHandshakeAttempts)
	}

	if a.AtLeast(model.AWG31) {
		// 3.1 over 3.0 is exactly these two, and RandomTrailers is two-sided —
		// which is why a 3.0 client cannot talk to a 3.1 server at all.
		if a.RandomTrailers {
			b.WriteString("RandomTrailers = on\n")
		}
		if a.DisableCookies {
			b.WriteString("DisableCookies = on\n")
		}
	}
}

// line writes "K = V" when V is set, and nothing when it is not.
func line(b *strings.Builder, key string, v model.AWGRange) {
	if !v.Empty() {
		fmt.Fprintf(b, "%s = %s\n", key, v.String())
	}
}

// AmneziaWGConf renders the CLIENT awg-quick configuration for an AmneziaWG node:
// a standard wg-quick config plus the AmneziaWG obfuscation parameters in
// [Interface]. It imports unchanged into the AmneziaWG client app or into
// awg-quick with the kernel module. host is the server's reachable address.
func AmneziaWGConf(n *model.Node, host string) (string, error) {
	if n.Protocol != model.ProtoAmneziaWG || n.AmneziaWG == nil {
		return "", fmt.Errorf("export: not an amneziawg node")
	}
	// Clone and normalise, exactly as export.URI does. A caller that hands over
	// a node built by hand would otherwise get a conf with the obfuscation
	// fields missing — which is not a weaker AmneziaWG config, it is a plain
	// WireGuard config that no AmneziaWG server will answer.
	n = n.Clone()
	n.Normalize()
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
	fmt.Fprintf(&b, "AllowedIPs = %s\n",
		strings.Join(matchAllowedIPsToTunnel(allowed, addr), ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keep)
	// AdvancedSecurity is a PEER-level flag, and 3.0 or newer only.
	if a.AdvancedSecurity && a.AtLeast(model.AWG30) {
		b.WriteString("AdvancedSecurity = on\n")
	}
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
	server = server.Clone()
	server.Normalize()
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
	wgQuickNAT(&b, saddr)
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
			if a.AdvancedSecurity && a.AtLeast(model.AWG30) {
				b.WriteString("AdvancedSecurity = on\n")
			}
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
