package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Proprietary client-config formats (Surge, Loon, Quantumult X). None has a CLI
// core that can validate them, so they are emitted per each app's documented
// line syntax and golden-file locked for structural stability. Each covers the
// protocols with stable, well-known syntax in that app (Shadowsocks, VMess,
// Trojan, HTTP, SOCKS5); a node the format cannot express is skipped with a
// comment rather than emitted wrong.

func propName(n *model.Node, i int) string {
	if n.Remark != "" {
		return n.Remark
	}
	return fmt.Sprintf("%s-%d", n.Protocol, i)
}

// surgeSubscription renders a Surge [Proxy] block. Loon shares this syntax.
func surgeSubscription(nodes []*model.Node) []byte {
	return proxyLineFormat(nodes, "surge")
}

// loonSubscription renders a Loon proxy list (Surge-compatible line syntax).
func loonSubscription(nodes []*model.Node) []byte {
	return proxyLineFormat(nodes, "loon")
}

func proxyLineFormat(nodes []*model.Node, dialect string) []byte {
	var b strings.Builder
	b.WriteString("#!name=ForgePanel\n[Proxy]\n")
	for i, n := range nodes {
		addr := n.EffectiveClientAddress()
		name := propName(n, i)
		tls := n.Security.Type == model.SecTLS
		sni := n.Security.ServerName
		switch n.Protocol {
		case model.ProtoShadowsocks:
			fmt.Fprintf(&b, "%s = ss, %s, %d, encrypt-method=%s, password=%s\n", name, addr, n.Port, n.Method, n.Password)
		case model.ProtoVMess:
			line := fmt.Sprintf("%s = vmess, %s, %d, username=%s", name, addr, n.Port, n.UUID)
			if tls {
				line += ", tls=true"
				if sni != "" {
					line += ", sni=" + sni
				}
			}
			if n.Transport.Network == model.NetWS {
				line += ", ws=true, ws-path=" + orSlash(n.Transport.Path)
				if n.Transport.Host != "" {
					line += ", ws-headers=Host:" + n.Transport.Host
				}
			}
			b.WriteString(line + "\n")
		case model.ProtoTrojan:
			line := fmt.Sprintf("%s = trojan, %s, %d, password=%s", name, addr, n.Port, n.Password)
			if sni != "" {
				line += ", sni=" + sni
			}
			b.WriteString(line + "\n")
		case model.ProtoHTTP:
			scheme := "http"
			if tls {
				scheme = "https"
			}
			fmt.Fprintf(&b, "%s = %s, %s, %d, username=%s, password=%s\n", name, scheme, addr, n.Port, n.Username, n.Password)
		case model.ProtoSOCKS:
			fmt.Fprintf(&b, "%s = socks5, %s, %d, username=%s, password=%s\n", name, addr, n.Port, n.Username, n.Password)
		default:
			fmt.Fprintf(&b, "# %s: %s is not expressible in %s\n", name, n.Protocol, dialect)
		}
	}
	return []byte(b.String())
}

// quantumultxSubscription renders a Quantumult X [server_local] list.
func quantumultxSubscription(nodes []*model.Node) []byte {
	var b strings.Builder
	b.WriteString("[server_local]\n")
	for i, n := range nodes {
		addr := n.EffectiveClientAddress()
		name := propName(n, i)
		tls := n.Security.Type == model.SecTLS
		switch n.Protocol {
		case model.ProtoShadowsocks:
			fmt.Fprintf(&b, "shadowsocks=%s:%d, method=%s, password=%s, tag=%s\n", addr, n.Port, n.Method, n.Password, name)
		case model.ProtoVMess:
			line := fmt.Sprintf("vmess=%s:%d, method=chacha20-poly1305, password=%s", addr, n.Port, n.UUID)
			if n.Transport.Network == model.NetWS {
				line += ", obfs=ws, obfs-uri=" + orSlash(n.Transport.Path)
				if n.Transport.Host != "" {
					line += ", obfs-host=" + n.Transport.Host
				}
			} else if tls {
				line += ", obfs=over-tls"
			}
			b.WriteString(line + ", tag=" + name + "\n")
		case model.ProtoTrojan:
			fmt.Fprintf(&b, "trojan=%s:%d, password=%s, over-tls=%t, tls-host=%s, tag=%s\n",
				addr, n.Port, n.Password, tls, n.Security.ServerName, name)
		case model.ProtoHTTP:
			fmt.Fprintf(&b, "http=%s:%d, username=%s, password=%s, tag=%s\n", addr, n.Port, n.Username, n.Password, name)
		case model.ProtoSOCKS:
			fmt.Fprintf(&b, "socks5=%s:%d, username=%s, password=%s, tag=%s\n", addr, n.Port, n.Username, n.Password, name)
		default:
			fmt.Fprintf(&b, "# %s: %s not expressible in quantumult-x\n", name, n.Protocol)
		}
	}
	return []byte(b.String())
}

func orSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

var _ = url.QueryEscape
