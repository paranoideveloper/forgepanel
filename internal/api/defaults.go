package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// applyCreateDefaults makes the panel "do the work" (user request): it fills in
// every sensible default so an operator can create a working inbound with
// minimal input. This runs when an inbound is created.
//
//   - REALITY: generate the X25519 keypair + shortId if missing, default the
//     dest to a proven steal-site (www.cloudflare.com, NOT microsoft), mirror it
//     into serverNames/serverName, set spiderX and a chrome fingerprint; for
//     VLESS-REALITY over raw TCP, default the flow to xtls-rprx-vision (best).
//   - VLESS: default encryption none.
//   - TLS: default a chrome fingerprint.
//   - VMess: alterId 0 (AEAD).
func applyCreateDefaults(n *model.Node) {
	// The create form intentionally leaves address blank ("auto — panel public
	// address"): an inbound LISTENS on 0.0.0.0 (all interfaces), and exported
	// client links substitute the real public address at export time
	// (substituteAddr). Without this default a blank-address create — i.e. every
	// create from the UI — was rejected with "address is required".
	if strings.TrimSpace(n.Address) == "" {
		n.Address = "0.0.0.0"
	}

	switch n.Protocol {
	case model.ProtoVLESS:
		if n.Encryption == "" {
			n.Encryption = "none"
		}
	}

	if n.Security.Type == model.SecReality {
		if n.Security.Reality == nil {
			n.Security.Reality = &model.Reality{}
		}
		r := n.Security.Reality
		// Auto-generate keys so a user can create REALITY with zero crypto input.
		if r.PrivateKey == "" || r.PublicKey == "" {
			if kp, err := keygen.RealityKeys(); err == nil {
				r.PrivateKey, r.PublicKey = kp.PrivateKey, kp.PublicKey
			}
		} else if r.PublicKey == "" && r.PrivateKey != "" {
			if pub, err := keygen.RealityPublicFromPrivate(r.PrivateKey); err == nil {
				r.PublicKey = pub
			}
		}
		if r.ShortID == "" && len(r.ShortIDs) == 0 {
			if sid, err := keygen.ShortID(8); err == nil {
				r.ShortID = sid
			}
		}
		// A good default steal-site so REALITY works out of the box.
		if r.Dest == "" {
			r.Dest = defaultRealityDest + ":443"
		}
		if len(r.ServerNames) == 0 {
			r.ServerNames = []string{hostOf(r.Dest)}
		}
		if n.Security.ServerName == "" {
			n.Security.ServerName = r.ServerNames[0]
		}
		if r.SpiderX == "" {
			r.SpiderX = "/"
		}
		if n.Security.Fingerprint == "" {
			n.Security.Fingerprint = "chrome"
		}
		// Vision is the best pairing for VLESS-REALITY over raw TCP.
		if n.Protocol == model.ProtoVLESS && n.Transport.Network == model.NetTCP && n.Flow == "" {
			n.Flow = "xtls-rprx-vision"
		}
	}

	// A uTLS fingerprint only applies to TCP-TLS handshakes. QUIC protocols
	// (Hysteria2, TUIC) have their own TLS stack and reject a uTLS block, so do
	// not stamp one on them.
	if n.Security.Type == model.SecTLS && n.Security.Fingerprint == "" && !n.Protocol.IsQUICBased() {
		n.Security.Fingerprint = "chrome"
	}

	// Ensure required credentials exist so "create with one click" works.
	switch n.Protocol {
	case model.ProtoVLESS, model.ProtoVMess:
		if n.UUID == "" {
			n.UUID = keygen.UUID()
		}
	case model.ProtoTrojan, model.ProtoHysteria2, model.ProtoAnyTLS:
		if n.Password == "" {
			n.Password, _ = keygen.Password(16)
		}
		// Salamander obfuscation needs its own password; sing-box refuses to start a
		// hysteria2 inbound whose obfs password is empty (and takes the whole engine
		// down with it). Mint one when the operator ticks salamander but leaves it
		// blank, so the inbound works and the client link carries the same value.
		if n.Protocol == model.ProtoHysteria2 && n.Hysteria2 != nil &&
			n.Hysteria2.ObfsType != "" && n.Hysteria2.ObfsPassword == "" {
			n.Hysteria2.ObfsPassword, _ = keygen.Password(16)
		}
	case model.ProtoTUIC:
		if n.UUID == "" {
			n.UUID = keygen.UUID()
		}
		if n.Password == "" {
			n.Password, _ = keygen.Password(16)
		}
	case model.ProtoShadowsocks:
		if n.Method == "" {
			n.Method = model.SS2022AES128
		}
		if n.Password == "" {
			if psk, err := keygen.SS2022PSK(n.Method); err == nil {
				n.Password = psk
			} else {
				n.Password, _ = keygen.Password(16)
			}
		}
	case model.ProtoBrook:
		if n.Password == "" {
			n.Password, _ = keygen.Password(16)
		}
	case model.ProtoShadowTLS:
		if n.ShadowTLS == nil {
			n.ShadowTLS = &model.ShadowTLSOptions{}
		}
		if n.ShadowTLS.Password == "" {
			n.ShadowTLS.Password, _ = keygen.Password(16)
		}
		if n.ShadowTLS.Version == 0 {
			n.ShadowTLS.Version = 3
		}
		if n.ShadowTLS.HandshakeHost == "" {
			n.ShadowTLS.HandshakeHost = "www.apple.com"
		}
		if n.ShadowTLS.HandshakePort == 0 {
			n.ShadowTLS.HandshakePort = 443
		}
		// ShadowTLS is only a camouflage layer; mint the inner Shadowsocks that
		// actually carries traffic so the node is a complete tunnel.
		if n.ShadowTLS.InnerMethod == "" {
			n.ShadowTLS.InnerMethod = model.SS2022AES128
		}
		if n.ShadowTLS.InnerPassword == "" {
			if psk, err := keygen.SS2022PSK(n.ShadowTLS.InnerMethod); err == nil {
				n.ShadowTLS.InnerPassword = psk
			} else {
				n.ShadowTLS.InnerPassword, _ = keygen.Password(16)
			}
		}
	case model.ProtoSSH:
		if n.SSH == nil {
			n.SSH = &model.SSHOptions{}
		}
		if n.SSH.User == "" {
			n.SSH.User = "root"
		}
		if n.SSH.Password == "" && n.SSH.PrivateKey == "" {
			n.SSH.Password, _ = keygen.Password(16)
		}
	case model.ProtoWireGuard:
		if n.WireGuard == nil {
			n.WireGuard = &model.WireGuardOptions{}
		}
		w := n.WireGuard
		// Mint the SERVER keypair (this box) so it can run a real WG server.
		if w.PrivateKey == "" || w.PublicKey == "" {
			if kp, err := keygen.WireGuardKeys(); err == nil {
				if w.PrivateKey == "" {
					w.PrivateKey = kp.PrivateKey
				}
				if w.PublicKey == "" {
					w.PublicKey = kp.PublicKey
				}
			}
		}
		// Mint the CLIENT (peer) keypair so the exported .conf is a complete,
		// working tunnel — no manual key exchange. The client's public key is
		// registered as the server's peer; the client's private key goes in the conf.
		if w.PeerPrivateKey == "" || w.PeerPublicKey == "" {
			if kp, err := keygen.WireGuardKeys(); err == nil {
				if w.PeerPrivateKey == "" {
					w.PeerPrivateKey = kp.PrivateKey
				}
				if w.PeerPublicKey == "" {
					w.PeerPublicKey = kp.PublicKey
				}
			}
		}
		// Tunnel addressing (private range). Server .1, client .2.
		//
		// LocalAddress is deliberately NOT adopted here. It is the dialer's own
		// address — the parser fills it from a wireguard:// link, which describes
		// a CLIENT — so an inbound created from an imported link took the
		// client's 10.0.0.2/32 as the server's interface address, leaving the
		// server and the peer it provisions on different subnets and the tunnel
		// dead. The panel allocates its own subnet instead.
		if len(w.ServerAddress) == 0 {
			w.ServerAddress = []string{"10.66.66.1/24"}
		}
		if len(w.PeerAddress) == 0 {
			w.PeerAddress = []string{"10.66.66.2/32"}
		}
		if len(w.AllowedIPs) == 0 {
			w.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
		}
		if w.MTU == 0 {
			w.MTU = 1420
		}
		if w.Keepalive == 0 {
			w.Keepalive = 25
		}
	case model.ProtoAmneziaWG:
		if n.AmneziaWG == nil {
			n.AmneziaWG = &model.AmneziaWGOptions{}
		}
		w := &n.AmneziaWG.WireGuardOptions
		// Same keypair provisioning as WireGuard (awg is WG + obfuscation).
		if w.PrivateKey == "" || w.PublicKey == "" {
			if kp, err := keygen.WireGuardKeys(); err == nil {
				if w.PrivateKey == "" {
					w.PrivateKey = kp.PrivateKey
				}
				if w.PublicKey == "" {
					w.PublicKey = kp.PublicKey
				}
			}
		}
		if w.PeerPrivateKey == "" || w.PeerPublicKey == "" {
			if kp, err := keygen.WireGuardKeys(); err == nil {
				if w.PeerPrivateKey == "" {
					w.PeerPrivateKey = kp.PrivateKey
				}
				if w.PeerPublicKey == "" {
					w.PeerPublicKey = kp.PublicKey
				}
			}
		}
		if len(w.ServerAddress) == 0 {
			w.ServerAddress = []string{"10.67.67.1/24"}
		}
		if len(w.PeerAddress) == 0 {
			w.PeerAddress = []string{"10.67.67.2/32"}
		}
		if len(w.AllowedIPs) == 0 {
			w.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
		}
		// Normalize() fills the obfuscation defaults (Jc/Jmin/Jmax/S1/S2/H1..H4).
	}
	n.Normalize()
}

const defaultRealityDest = "www.cloudflare.com"

// substituteAddr replaces a bind-all/empty inbound listen address with the
// server's real reachable address so exported client links are usable. The
// operator's configured public address wins; otherwise the host the client
// reached the panel on is used.
func (s *Server) substituteAddr(n *model.Node, fallbackHost string) {
	// A configured domain is the client-facing address: exported links must dial
	// the domain (so they ride its cert/CDN), not the raw bind IP. This is the
	// address half of the domain cascade.
	if d := strings.TrimSpace(n.Domain); d != "" {
		n.Address = d
		return
	}
	a := n.Address
	if a == "" || a == "0.0.0.0" || a == "::" || a == "[::]" || a == "127.0.0.1" || a == "localhost" {
		pub := s.knobs().String("public_address")
		if pub == "" && s.cfg != nil {
			pub = s.cfg.Panel().Domain
		}
		if pub == "" {
			pub = fallbackHost
		}
		if pub != "" {
			n.Address = pub
		}
	}
}

// applyExportDefaults makes exported CLIENT links work out of the box: it
// substitutes the public address and, for a TLS inbound using the panel's
// self-signed cert, sets allowInsecure so clients don't reject it.
func (s *Server) applyExportDefaults(n *model.Node) {
	if n.Security.Type != model.SecTLS {
		return
	}
	// If the operator configured a real domain with an imported/ACME cert, keep
	// strict verification — the client trusts it through the public CA, no pin
	// needed.
	if s.hasRealCert(n.SNI()) {
		return
	}
	// Self-signed cert. Xray 26 removed allowInsecure outright, so an xray client
	// can only accept the panel's self-signed cert by pinning its exact SHA-256
	// (tlsSettings.pinnedPeerCertSha256, hex-encoded). Pin the very cert the
	// engine serves so the emitted subscription actually connects. sing-box has
	// no cert-pin field and honours `insecure`, so the sing-box-rendered
	// protocols keep AllowInsecure instead.
	if render.EngineFor(n.Protocol) == "xray" {
		if pin := s.selfSignedPinHex(); pin != "" {
			n.Security.PinSHA256 = []string{pin}
			return
		}
	}
	n.Security.AllowInsecure = true
}

// selfSignedPinHex returns hex(SHA-256(DER)) of the panel's self-signed leaf
// certificate — the one cert.EnsureSelfSigned generates and the engine serves
// for TLS inbounds that have no real certificate (internal/core/manager.go uses
// the same path). Empty if it cannot be produced, in which case the caller falls
// back to the sing-box `insecure` path.
func (s *Server) selfSignedPinHex() string {
	if s.cfg == nil {
		return ""
	}
	cp, _, err := cert.EnsureSelfSigned(filepath.Join(s.cfg.DataDir, "certs"))
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(cp)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// hasRealCert reports whether the panel holds a real (imported/ACME) certificate
// covering host, so its TLS links can keep strict verification.
func (s *Server) hasRealCert(host string) bool {
	if s.certs == nil || host == "" {
		return false
	}
	for _, imp := range s.certs.List() {
		for _, d := range imp.Domains {
			if d == host || (len(d) > 1 && d[0] == '*' && hasSuffix(host, d[1:])) {
				return true
			}
		}
	}
	return false
}

func hostOf(hostport string) string {
	for i := 0; i < len(hostport); i++ {
		if hostport[i] == ':' {
			return hostport[:i]
		}
	}
	return hostport
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// hostOnly strips a :port from a host[:port].
func hostOnly(h string) string {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i] == ':' {
			return h[:i]
		}
		if h[i] == ']' {
			return h // ipv6 without port
		}
	}
	return h
}
