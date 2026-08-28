// Package export renders a canonical model.Node into every client-facing
// format (spec §3, §8.8): share links (vless://, vmess://, …), Clash/Clash.Meta
// YAML, sing-box JSON outbound, and QR codes. Export is a pure function of the
// canonical node; parse/ is its inverse and the two satisfy the round-trip
// property test in spec §15.
package export

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// URI renders the canonical node as its native client share link. The remark
// becomes the URL fragment. Server-only secrets (REALITY private key, ML-DSA
// seed) are never emitted.
func URI(n *model.Node) (string, error) {
	c := n.Clone()
	c.Normalize()
	switch c.Protocol {
	case model.ProtoVLESS:
		return vlessURI(c), nil
	case model.ProtoVMess:
		return vmessURI(c)
	case model.ProtoTrojan:
		return trojanURI(c), nil
	case model.ProtoShadowsocks:
		return ssURI(c), nil
	case model.ProtoSOCKS:
		return socksURI(c), nil
	case model.ProtoHTTP:
		return httpURI(c), nil
	case model.ProtoHysteria2:
		return hysteria2URI(c), nil
	case model.ProtoTUIC:
		return tuicURI(c), nil
	case model.ProtoAnyTLS:
		return anytlsURI(c), nil
	case model.ProtoWireGuard:
		return wireguardURI(c), nil
	case model.ProtoBrook:
		return brookURI(c)
	case model.ProtoSSH:
		return sshURI(c), nil
	case model.ProtoShadowTLS:
		return "", fmt.Errorf("shadowtls has no standalone URI; export the wrapped shadowsocks node")
	case model.ProtoForgeDNS:
		return forgednsURI(c), nil
	default:
		return "", fmt.Errorf("export: unsupported protocol %q", c.Protocol)
	}
}

// hostPort joins an address and port, bracketing IPv6 literals.
func hostPort(addr string, port int) string {
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		return "[" + addr + "]:" + strconv.Itoa(port)
	}
	return addr + ":" + strconv.Itoa(port)
}

// frag returns the URL fragment (#remark) or empty string.
func frag(remark string) string {
	if remark == "" {
		return ""
	}
	return "#" + url.PathEscape(remark)
}

// transportSecurityParams builds the query parameters shared by VLESS, Trojan,
// AnyTLS and (mostly) VMess-as-query links. This is the single source of truth
// for how the canonical transport+security maps onto the de-facto standard
// share-link parameters, so every protocol stays consistent.
func transportSecurityParams(n *model.Node, v url.Values) {
	t := n.Transport
	v.Set("type", string(t.Network))
	switch t.Network {
	case model.NetWS, model.NetHTTPUpgrade:
		if t.Path != "" {
			v.Set("path", t.Path)
		}
		if t.Host != "" {
			v.Set("host", t.Host)
		}
	case model.NetGRPC:
		if t.ServiceName != "" {
			v.Set("serviceName", t.ServiceName)
		}
		if t.MultiMode {
			v.Set("mode", "multi")
		} else {
			v.Set("mode", "gun")
		}
	case model.NetXHTTP:
		if t.Path != "" {
			v.Set("path", t.Path)
		}
		if t.Host != "" {
			v.Set("host", t.Host)
		}
		if t.XHTTPMode != "" && t.XHTTPMode != "auto" {
			v.Set("mode", t.XHTTPMode)
		}
		// The rest of the modern XHTTP field set (padding shape, session/seq
		// carriage, flow control, xmux, the split download leg) has no
		// individual share-link parameter; it rides in the `extra` payload the
		// clients and the other panels already read. Without it the link is a
		// lossy export: the node comes back from a re-import with its CDN
		// tuning silently reset to defaults.
		if extra := t.XHTTPExtra(); extra != "" {
			v.Set("extra", extra)
		}
	case model.NetH2:
		if t.Path != "" {
			v.Set("path", t.Path)
		}
		if t.Host != "" {
			v.Set("host", t.Host)
		}
	case model.NetMKCP:
		if t.Seed != "" {
			v.Set("seed", t.Seed)
		}
		if t.HeaderObfs != nil && t.HeaderObfs.Type != "" {
			v.Set("headerType", t.HeaderObfs.Type)
		}
	case model.NetTCP:
		if t.HeaderObfs != nil && t.HeaderObfs.Type == "http" {
			v.Set("headerType", "http")
			if t.Host != "" {
				v.Set("host", t.Host)
			}
			if t.Path != "" {
				v.Set("path", t.Path)
			}
		}
	case model.NetQUIC:
		if t.QUICSecurity != "" && t.QUICSecurity != "none" {
			v.Set("quicSecurity", t.QUICSecurity)
			v.Set("key", t.QUICKey)
		}
		if t.HeaderObfs != nil && t.HeaderObfs.Type != "" {
			v.Set("headerType", t.HeaderObfs.Type)
		}
	}

	s := n.Security
	switch s.Type {
	case model.SecNone:
		v.Set("security", "none")
	case model.SecTLS:
		v.Set("security", "tls")
		if s.ServerName != "" {
			v.Set("sni", s.ServerName)
		}
		if len(s.ALPN) > 0 {
			v.Set("alpn", strings.Join(s.ALPN, ","))
		}
		if s.Fingerprint != "" {
			v.Set("fp", s.Fingerprint)
		}
		if s.AllowInsecure {
			v.Set("allowInsecure", "1")
		}
		if s.ECH != nil && s.ECH.ConfigList != "" {
			v.Set("ech", s.ECH.ConfigList)
		}
	case model.SecReality:
		v.Set("security", "reality")
		// ExportSNI, not ServerName: REALITY refuses a ClientHello whose SNI is
		// not in reality.serverNames, so the raw field can name something the
		// server will reject.
		if sni := s.ExportSNI(); sni != "" {
			v.Set("sni", sni)
		}
		if s.Fingerprint != "" {
			v.Set("fp", s.Fingerprint)
		} else {
			v.Set("fp", "chrome")
		}
		if r := s.Reality; r != nil {
			v.Set("pbk", r.PublicKey)
			if r.ShortID != "" {
				v.Set("sid", r.ShortID)
			} else if len(r.ShortIDs) > 0 {
				v.Set("sid", r.ShortIDs[0])
			}
			if r.SpiderX != "" && r.SpiderX != "/" {
				v.Set("spx", r.SpiderX)
			}
			if r.MLDSA65Verify != "" {
				v.Set("pqv", r.MLDSA65Verify)
			}
		}
		if len(s.ALPN) > 0 {
			v.Set("alpn", strings.Join(s.ALPN, ","))
		}
	}
}

// encodeQuery renders url.Values with sorted keys so exports are deterministic
// and golden-file stable. url.Values.Encode already sorts, but it escapes
// slashes in paths in a way some clients dislike; we keep Encode for stability.
func encodeQuery(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	return v.Encode()
}

func vlessURI(n *model.Node) string {
	v := url.Values{}
	if n.Flow != "" {
		v.Set("flow", n.Flow)
	}
	if n.Encryption != "" && n.Encryption != "none" {
		v.Set("encryption", n.Encryption)
	}
	transportSecurityParams(n, v)
	return "vless://" + n.UUID + "@" + hostPort(n.Address, n.Port) + "?" + encodeQuery(v) + frag(n.Remark)
}

func trojanURI(n *model.Node) string {
	v := url.Values{}
	if n.Flow != "" {
		v.Set("flow", n.Flow)
	}
	transportSecurityParams(n, v)
	// Trojan default security is TLS; keep the explicit param for round-trip.
	return "trojan://" + url.QueryEscape(n.Password) + "@" + hostPort(n.Address, n.Port) + "?" + encodeQuery(v) + frag(n.Remark)
}

func anytlsURI(n *model.Node) string {
	v := url.Values{}
	transportSecurityParams(n, v)
	if n.AnyTLS != nil && len(n.AnyTLS.PaddingScheme) > 0 {
		v.Set("padding_scheme", strings.Join(n.AnyTLS.PaddingScheme, "\n"))
	}
	return "anytls://" + url.QueryEscape(n.Password) + "@" + hostPort(n.Address, n.Port) + "?" + encodeQuery(v) + frag(n.Remark)
}

// vmessURI emits the base64-JSON "v2rayN" format, which is the interoperable
// default. Fields follow the widely-implemented v2 schema.
func vmessURI(n *model.Node) (string, error) {
	m := map[string]any{
		"v":    "2",
		"ps":   n.Remark,
		"add":  n.Address,
		"port": strconv.Itoa(n.Port),
		"id":   n.UUID,
		"aid":  "0",
		"scy":  n.Encryption,
		"net":  netForVMess(n.Transport.Network),
		"type": "none",
		"host": "",
		"path": "",
		"tls":  "",
		"sni":  "",
		"alpn": "",
		"fp":   "",
	}
	switch n.Transport.Network {
	case model.NetWS, model.NetHTTPUpgrade:
		m["host"] = n.Transport.Host
		m["path"] = n.Transport.Path
	case model.NetGRPC:
		m["path"] = n.Transport.ServiceName
		if n.Transport.MultiMode {
			m["type"] = "multi"
		} else {
			m["type"] = "gun"
		}
	case model.NetH2:
		m["host"] = n.Transport.Host
		m["path"] = n.Transport.Path
	case model.NetTCP:
		if n.Transport.HeaderObfs != nil && n.Transport.HeaderObfs.Type == "http" {
			m["type"] = "http"
			m["host"] = n.Transport.Host
			m["path"] = n.Transport.Path
		}
	case model.NetMKCP:
		if n.Transport.HeaderObfs != nil {
			m["type"] = n.Transport.HeaderObfs.Type
		}
		m["path"] = n.Transport.Seed
	}
	if n.Security.Type == model.SecTLS {
		m["tls"] = "tls"
		m["sni"] = n.Security.ExportSNI()
		m["fp"] = n.Security.Fingerprint
		if len(n.Security.ALPN) > 0 {
			m["alpn"] = strings.Join(n.Security.ALPN, ",")
		}
	} else if n.Security.Type == model.SecReality {
		m["tls"] = "reality"
		m["sni"] = n.Security.ExportSNI()
		m["fp"] = n.Security.Fingerprint
		if r := n.Security.Reality; r != nil {
			m["pbk"] = r.PublicKey
			m["sid"] = r.ShortID
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
}

func netForVMess(nw model.Network) string {
	switch nw {
	case model.NetH2:
		return "h2"
	case model.NetHTTPUpgrade:
		return "httpupgrade"
	case model.NetMKCP:
		return "kcp"
	default:
		return string(nw)
	}
}

func ssURI(n *model.Node) string {
	// SIP002: ss://base64(method:password)@host:port#tag  (userinfo is
	// base64url without padding of "method:password").
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(n.Method + ":" + n.Password))
	uri := "ss://" + userinfo + "@" + hostPort(n.Address, n.Port)
	q := url.Values{}
	if n.SSPlugin != nil && n.SSPlugin.Name != "" {
		plugin := n.SSPlugin.Name
		if n.SSPlugin.Opts != "" {
			plugin += ";" + n.SSPlugin.Opts
		}
		q.Set("plugin", plugin)
	}
	if s := encodeQuery(q); s != "" {
		uri += "?" + s
	}
	return uri + frag(n.Remark)
}

func socksURI(n *model.Node) string {
	// socks://base64(user:pass)@host:port#tag
	uri := "socks://"
	if n.Username != "" || n.Password != "" {
		uri += base64.RawURLEncoding.EncodeToString([]byte(n.Username+":"+n.Password)) + "@"
	}
	return uri + hostPort(n.Address, n.Port) + frag(n.Remark)
}

func httpURI(n *model.Node) string {
	scheme := "http://"
	if n.Security.Type == model.SecTLS {
		scheme = "https://"
	}
	uri := scheme
	if n.Username != "" || n.Password != "" {
		uri += url.QueryEscape(n.Username) + ":" + url.QueryEscape(n.Password) + "@"
	}
	return uri + hostPort(n.Address, n.Port) + frag(n.Remark)
}

func hysteria2URI(n *model.Node) string {
	v := url.Values{}
	if n.Security.ServerName != "" {
		v.Set("sni", n.Security.ServerName)
	}
	if n.Security.AllowInsecure {
		v.Set("insecure", "1")
	}
	if h := n.Hysteria2; h != nil {
		if h.ObfsType != "" {
			v.Set("obfs", h.ObfsType)
			v.Set("obfs-password", h.ObfsPassword)
		}
		if h.PortHopping != "" {
			v.Set("mport", h.PortHopping)
		}
		if h.PortHopInterval > 0 {
			v.Set("hop_interval", strconv.Itoa(h.PortHopInterval))
		}
		if h.UpMbps > 0 {
			v.Set("up", strconv.Itoa(h.UpMbps))
		}
		if h.DownMbps > 0 {
			v.Set("down", strconv.Itoa(h.DownMbps))
		}
	}
	if len(n.Security.PinSHA256) > 0 {
		v.Set("pinSHA256", n.Security.PinSHA256[0])
	}
	q := encodeQuery(v)
	if q != "" {
		q = "?" + q
	}
	return "hysteria2://" + url.QueryEscape(n.Password) + "@" + hostPort(n.Address, n.Port) + q + frag(n.Remark)
}

func tuicURI(n *model.Node) string {
	v := url.Values{}
	if n.Security.ServerName != "" {
		v.Set("sni", n.Security.ServerName)
	}
	if len(n.Security.ALPN) > 0 {
		v.Set("alpn", strings.Join(n.Security.ALPN, ","))
	}
	if n.Security.AllowInsecure {
		v.Set("allow_insecure", "1")
	}
	if t := n.TUIC; t != nil {
		if t.CongestionControl != "" {
			v.Set("congestion_control", t.CongestionControl)
		}
		if t.UDPRelayMode != "" {
			v.Set("udp_relay_mode", t.UDPRelayMode)
		}
	}
	// tuic://uuid:password@host:port?params#tag
	return "tuic://" + n.UUID + ":" + url.QueryEscape(n.Password) + "@" + hostPort(n.Address, n.Port) + "?" + encodeQuery(v) + frag(n.Remark)
}

func wireguardURI(n *model.Node) string {
	// wireguard://<privkey-urlsafe>@host:port?publickey=&reserved=&address=&mtu=#tag
	v := url.Values{}
	w := n.WireGuard
	priv := w.PrivateKey
	if priv == "" {
		priv = w.PeerPrivateKey
	}
	v.Set("publickey", w.PublicKey)
	if w.PreSharedKey != "" {
		v.Set("presharedkey", w.PreSharedKey)
	}
	if len(w.LocalAddress) > 0 {
		v.Set("address", strings.Join(w.LocalAddress, ","))
	}
	if w.MTU > 0 {
		v.Set("mtu", strconv.Itoa(w.MTU))
	}
	if len(w.Reserved) == 3 {
		v.Set("reserved", fmt.Sprintf("%d,%d,%d", w.Reserved[0], w.Reserved[1], w.Reserved[2]))
	}
	return "wireguard://" + url.QueryEscape(priv) + "@" + hostPort(n.Address, n.Port) + "?" + encodeQuery(v) + frag(n.Remark)
}

func brookURI(n *model.Node) (string, error) {
	// brook://server?password=&server=host%3Aport  (brook's own scheme)
	v := url.Values{}
	v.Set("password", n.Password)
	v.Set("server", net.JoinHostPort(n.Address, strconv.Itoa(n.Port)))
	mode := "server"
	if n.Brook != nil {
		if n.Brook.Mode != "" {
			mode = n.Brook.Mode
		}
		// UDP over TCP was stored and never emitted, so a client configured for
		// it silently ran plain UDP — which is exactly the case where UDP does
		// not survive the network in between, and the reason the setting exists.
		// The parameter name and value were taken from the pinned brook binary's
		// own output (`brook link --udpovertcp`), not from documentation.
		if n.Brook.UDPOverTCP {
			v.Set("udpovertcp", "true")
		}
	}
	return "brook://" + mode + "?" + encodeQuery(v) + frag(n.Remark), nil
}

func sshURI(n *model.Node) string {
	// ssh://user@host:port#tag  (password/keys are not embedded in the link)
	uri := "ssh://"
	if n.SSH != nil && n.SSH.User != "" {
		uri += url.QueryEscape(n.SSH.User) + "@"
	}
	return uri + hostPort(n.Address, n.Port) + frag(n.Remark)
}

func forgednsURI(n *model.Node) string {
	// forgedns://<adapter>@<zone>?key=&rr=#tag  — ForgePanel-native scheme.
	v := url.Values{}
	f := n.ForgeDNS
	if f.Key != "" {
		v.Set("key", f.Key)
	}
	if f.RRType != "" {
		v.Set("rr", f.RRType)
	}
	if f.NSHost != "" {
		v.Set("ns", f.NSHost)
	}
	q := encodeQuery(v)
	if q != "" {
		q = "?" + q
	}
	return "forgedns://" + f.Adapter + "@" + f.Zone + q + frag(n.Remark)
}

// SortedKeys is a tiny helper exposed for golden tests that need deterministic
// map iteration.
func SortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
