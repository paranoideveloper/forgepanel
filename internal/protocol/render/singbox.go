// singbox.go is the second half of the render/ contract described in the
// package doc on xray.go: model.Node -> sing-box configuration.
//
// WHY a separate renderer instead of translating Xray JSON: the two engines do
// not share a schema, and sing-box rejects unknown JSON keys outright, so a
// "close enough" translation silently becomes a config that will not start.
// Every key emitted here therefore has to exist in the sing-box 1.11 schema,
// and anything the canonical model can express but sing-box cannot (xhttp and
// mKCP transports, TCP http-obfuscation headers, Brook, ForgeDNS) is reported
// as an error rather than dropped -- a dropped transport is a broken tunnel,
// and the supervisor (spec §6) needs to know so it can route to another engine.
//
// WHY sing-box at all, given Xray covers the classic protocols: Hysteria2,
// TUIC, AnyTLS, ShadowTLS and SSH have no Xray implementation, and those are
// exactly the protocols that survive Iranian DPI best. EngineFor in xray.go is
// the routing table; this file is what it routes to.

package render

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// SingboxOutbound renders the canonical node as a sing-box outbound object
// (sing-box 1.11 schema). The node is cloned, normalized and validated first,
// so the caller's value is never mutated and the output is a pure function of
// the canonical form -- the same invariant XrayOutbound upholds.
func SingboxOutbound(n *model.Node) (map[string]any, error) {
	outs, err := SingboxOutbounds(n)
	if err != nil {
		return nil, err
	}
	return outs[0], nil
}

// SingboxOutbounds renders a node as every outbound it needs, primary FIRST.
//
// Most protocols are one outbound. ShadowTLS is two, and rendering it as one was
// a client config that connected, performed the TLS mimicry perfectly, and
// carried no traffic at all.
//
// ShadowTLS is camouflage, not a proxy: sing-box models it as a shadowtls
// outbound that the REAL proxy detours through. The server side always got this
// right — SingboxInbound sets detour to an inner Shadowsocks inbound — and the
// client side emitted a bare {"type":"shadowtls"} with nothing inside it. That
// object is valid, sing-box starts, the handshake to the decoy host succeeds,
// and then there is no proxy protocol to speak, so every ShadowTLS config this
// panel handed out was decoration.
//
// Any caller ASSEMBLING A CONFIG must use this rather than SingboxOutbound, or
// the support outbound is dropped and the detour points at a tag that does not
// exist — which sing-box refuses outright, so at least it fails loudly.
func SingboxOutbounds(n *model.Node) ([]map[string]any, error) {
	c := n.Clone()
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out, err := singboxProtocol(c)
	if err != nil {
		return nil, err
	}
	tag := tagOr(c.Tag, "proxy")
	out["tag"] = tag
	if sbSupportsMultiplex(c.Protocol) {
		if m := sbMultiplex(c.Multiplex); m != nil {
			out["multiplex"] = m
		}
	}
	if c.Protocol == model.ProtoShadowTLS {
		inner, support := sbShadowTLSPair(c, tag, out)
		return []map[string]any{inner, support}, nil
	}
	return []map[string]any{out}, nil
}

// stlsSupportSuffix names the camouflage half of a ShadowTLS pair.
const stlsSupportSuffix = "-stls"

// RetagOutbounds renames the primary outbound and repoints anything that
// detours through it, so a caller that must deduplicate tags across many nodes
// cannot leave a detour aimed at a tag that no longer exists.
//
// sing-box refuses a config whose detour names an unknown outbound, so getting
// this wrong fails loudly rather than silently — but it fails at the operator's
// client, after the subscription has been handed out.
func RetagOutbounds(outs []map[string]any, tag string) {
	if len(outs) == 0 {
		return
	}
	old, _ := outs[0]["tag"].(string)
	outs[0]["tag"] = tag
	if len(outs) == 1 || old == "" {
		return
	}
	for _, o := range outs[1:] {
		prev, _ := o["tag"].(string)
		if !strings.HasPrefix(prev, old) {
			continue
		}
		next := tag + strings.TrimPrefix(prev, old)
		o["tag"] = next
		if d, _ := outs[0]["detour"].(string); d == prev {
			outs[0]["detour"] = next
		}
	}
}

// SetChainDetour points a rendered node's OUTERMOST outbound at the previous hop
// in a relay chain.
//
// Outermost matters. A one-outbound node detours from itself, but a ShadowTLS
// node is a pair: the inner Shadowsocks already detours through the camouflage,
// and it is the CAMOUFLAGE that opens the connection to the server. Putting the
// chain's detour on the primary would give one outbound two detours — the second
// silently replacing the first — and the traffic would leave the machine without
// the camouflage, or without the chain, depending on which won.
func SetChainDetour(outs []map[string]any, previousTag string) {
	if len(outs) == 0 || previousTag == "" {
		return
	}
	outs[len(outs)-1]["detour"] = previousTag
}

// sbShadowTLSPair splits a rendered shadowtls outbound into the Shadowsocks that
// actually carries traffic and the shadowtls camouflage it detours through.
//
// The primary keeps the node's tag, because that is the tag a route rule, a
// selector or a chain already points at; the camouflage takes a derived one. The
// credentials are the INNER Shadowsocks pair the panel mints for the inbound —
// the shadowtls password authenticates the mimicry layer and is not a proxy
// credential, so using it here would produce a config that cannot authenticate.
func sbShadowTLSPair(c *model.Node, tag string, stls map[string]any) (inner, support map[string]any) {
	supportTag := tag + stlsSupportSuffix
	stls["tag"] = supportTag

	method, password := "", ""
	if c.ShadowTLS != nil {
		method, password = c.ShadowTLS.InnerMethod, c.ShadowTLS.InnerPassword
	}
	inner = jobj{
		"type": "shadowsocks", "tag": tag,
		"method": method, "password": password,
		// No server/server_port: the detour supplies the connection. Setting them
		// makes sing-box dial the address itself and bypass the camouflage
		// entirely, which is the failure this is here to prevent.
		"detour": supportTag,
	}
	if m := sbMultiplex(c.Multiplex); m != nil {
		inner["multiplex"] = m
	}
	// Multiplex belongs to the proxy, not to the camouflage.
	delete(stls, "multiplex")
	return inner, stls
}

// RenderSingboxJSON returns a complete, indented sing-box config carrying the
// node as its single proxy outbound plus a direct outbound. This is the exact
// shape `sing-box check -c` validates, which is how spec §18 gates a release.
func RenderSingboxJSON(n *model.Node) ([]byte, error) {
	outs, err := SingboxOutbounds(n)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(outs)+1)
	for _, o := range outs {
		list = append(list, o)
	}
	list = append(list, jobj{"type": "direct", "tag": "direct"})
	cfg := jobj{
		"log":       jobj{"level": "warn", "timestamp": true},
		"outbounds": list,
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// singboxProtocol builds the protocol-specific part of the outbound. The tag
// and multiplex block are added by the caller so that every branch here stays
// focused on what actually differs between protocols.
func singboxProtocol(n *model.Node) (jobj, error) {
	switch n.Protocol {
	case model.ProtoVLESS:
		o := jobj{
			"type": "vless", "server": n.Address, "server_port": n.Port,
			"uuid": n.UUID,
			// xudp is sing-box's default and the only encoding Xray's VLESS
			// server understands for UDP-over-VLESS; make it explicit so the
			// rendered config does not depend on the engine's default.
			"packet_encoding": "xudp",
		}
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
		if err := sbApplyStream(n, o, false); err != nil {
			return nil, err
		}
		return o, nil

	case model.ProtoVMess:
		o := jobj{
			"type": "vmess", "server": n.Address, "server_port": n.Port,
			"uuid": n.UUID, "security": firstNonEmpty(n.Encryption, "auto"),
			// VMessAEAD only: a non-zero alterId is the legacy MD5 handshake,
			// which sing-box does not implement at all.
			"alter_id": 0,
		}
		if err := sbApplyStream(n, o, false); err != nil {
			return nil, err
		}
		return o, nil

	case model.ProtoTrojan:
		o := jobj{"type": "trojan", "server": n.Address, "server_port": n.Port, "password": n.Password}
		if err := sbApplyStream(n, o, false); err != nil {
			return nil, err
		}
		return o, nil

	case model.ProtoShadowsocks:
		// sing-box's shadowsocks outbound has no v2ray transport or TLS layer;
		// obfuscation rides on a SIP003 plugin instead. Refusing a non-TCP
		// transport here is what keeps a ws-fronted SS node from being rendered
		// into a config that connects in the clear.
		if n.Transport.Network != model.NetTCP {
			return nil, fmt.Errorf("render/singbox: shadowsocks over %q is expressed as a SIP003 plugin in sing-box, not a transport", n.Transport.Network)
		}
		o := jobj{
			"type": "shadowsocks", "server": n.Address, "server_port": n.Port,
			"method": n.Method, "password": n.Password,
		}
		if p := n.SSPlugin; p != nil && p.Name != "" {
			o["plugin"] = p.Name
			if p.Opts != "" {
				o["plugin_opts"] = p.Opts
			}
		}
		return o, nil

	case model.ProtoSOCKS:
		o := jobj{"type": "socks", "server": n.Address, "server_port": n.Port, "version": "5"}
		if n.Username != "" {
			o["username"] = n.Username
			o["password"] = n.Password
		}
		return o, nil

	case model.ProtoHTTP:
		// The HTTP CONNECT outbound takes TLS directly (that is "https proxy"),
		// but never a v2ray transport.
		o := jobj{"type": "http", "server": n.Address, "server_port": n.Port}
		if n.Username != "" {
			o["username"] = n.Username
			o["password"] = n.Password
		}
		if tls := sbTLS(n, false); tls != nil {
			o["tls"] = tls
		}
		return o, nil

	case model.ProtoHysteria2:
		o := jobj{"type": "hysteria2", "server": n.Address, "server_port": n.Port, "password": n.Password}
		if h := n.Hysteria2; h != nil {
			if h.UpMbps > 0 {
				o["up_mbps"] = h.UpMbps
			}
			if h.DownMbps > 0 {
				o["down_mbps"] = h.DownMbps
			}
			if h.ObfsType != "" && h.ObfsPassword != "" {
				o["obfs"] = jobj{"type": h.ObfsType, "password": h.ObfsPassword}
			}
			if ports := sbPortRanges(h.PortHopping); len(ports) > 0 {
				o["server_ports"] = ports
				if h.PortHopInterval > 0 {
					o["hop_interval"] = sbSeconds(h.PortHopInterval)
				}
			}
		}
		o["tls"] = sbTLS(n, true)
		return o, nil

	case model.ProtoTUIC:
		o := jobj{
			"type": "tuic", "server": n.Address, "server_port": n.Port,
			"uuid": n.UUID, "password": n.Password,
		}
		tls := sbTLS(n, true)
		if t := n.TUIC; t != nil {
			if t.CongestionControl != "" {
				o["congestion_control"] = t.CongestionControl
			}
			if t.UDPRelayMode != "" {
				o["udp_relay_mode"] = t.UDPRelayMode
			}
			if t.ZeroRTTHandshake {
				o["zero_rtt_handshake"] = true
			}
			if t.HeartbeatSeconds > 0 {
				o["heartbeat"] = sbSeconds(t.HeartbeatSeconds)
			}
			if t.DisableSNI {
				tls["disable_sni"] = true
			}
		}
		o["tls"] = tls
		return o, nil

	case model.ProtoAnyTLS:
		o := jobj{"type": "anytls", "server": n.Address, "server_port": n.Port, "password": n.Password}
		if a := n.AnyTLS; a != nil {
			if len(a.PaddingScheme) > 0 {
				o["padding_scheme"] = a.PaddingScheme
			}
			if a.IdleSessionCheckInterval > 0 {
				o["idle_session_check_interval"] = sbSeconds(a.IdleSessionCheckInterval)
			}
			if a.IdleSessionTimeout > 0 {
				o["idle_session_timeout"] = sbSeconds(a.IdleSessionTimeout)
			}
			if a.MinIdleSessions > 0 {
				o["min_idle_session"] = a.MinIdleSessions
			}
		}
		o["tls"] = sbTLS(n, true)
		return o, nil

	case model.ProtoShadowTLS:
		s := n.ShadowTLS
		o := jobj{
			"type": "shadowtls", "server": n.Address, "server_port": n.Port,
			"version": s.Version, "password": s.Password,
		}
		// The handshake host is the domain sing-box actually talks TLS to; it
		// is the whole point of ShadowTLS, so it wins over the node SNI.
		tls := sbTLS(n, true)
		if s.HandshakeHost != "" {
			tls["server_name"] = s.HandshakeHost
		}
		if s.StrictMode && s.Version == 3 {
			o["strict_mode"] = true
		}
		o["tls"] = tls
		return o, nil

	case model.ProtoWireGuard:
		w := n.WireGuard
		o := jobj{
			// A client outbound uses the CLIENT's key (PeerPrivateKey); w.PrivateKey
			// is the server's and must never be shipped to a client.
			"type": "wireguard", "server": n.Address, "server_port": n.Port,
			"private_key": w.PeerPrivateKey, "peer_public_key": w.PublicKey,
		}
		if w.PreSharedKey != "" {
			o["pre_shared_key"] = w.PreSharedKey
		}
		if len(w.LocalAddress) > 0 {
			o["local_address"] = w.LocalAddress
		}
		if w.MTU > 0 {
			o["mtu"] = w.MTU
		}
		// Cloudflare WARP wants these three bytes; sing-box only accepts them
		// as an exactly-3-element array, which Validate already guarantees.
		if len(w.Reserved) == 3 {
			o["reserved"] = w.Reserved
		}
		if w.Workers > 0 {
			o["workers"] = w.Workers
		}
		// AllowedIPs and Keepalive are deliberately not emitted: the 1.11
		// wireguard *outbound* has no such keys (they belong to the newer
		// endpoint form), and sing-box rejects unknown keys.
		return o, nil

	case model.ProtoSSH:
		s := n.SSH
		o := jobj{"type": "ssh", "server": n.Address, "server_port": n.Port, "user": s.User}
		if s.Password != "" {
			o["password"] = s.Password
		}
		if s.PrivateKey != "" {
			o["private_key"] = s.PrivateKey
		}
		if s.PrivateKeyPassword != "" {
			o["private_key_passphrase"] = s.PrivateKeyPassword
		}
		if len(s.HostKeyAlgorithms) > 0 {
			o["host_key_algorithms"] = s.HostKeyAlgorithms
		}
		if s.ClientVersion != "" {
			o["client_version"] = s.ClientVersion
		}
		return o, nil

	default:
		return nil, fmt.Errorf("render/singbox: protocol %q is not a sing-box protocol; use engine %q", n.Protocol, EngineFor(n.Protocol))
	}
}

// sbApplyStream attaches the "transport" and "tls" blocks for the protocols
// that layer over the pluggable stack (VLESS/VMess/Trojan).
func sbApplyStream(n *model.Node, o jobj, forceTLS bool) error {
	tr, err := sbTransport(n.Transport)
	if err != nil {
		return err
	}
	if tr != nil {
		o["transport"] = tr
	}
	if tls := sbTLS(n, forceTLS); tls != nil {
		o["tls"] = tls
	}
	return nil
}

// sbTransport maps the canonical transport onto sing-box's V2Ray transport
// object. A nil result means "plain TCP", which sing-box expresses by omitting
// the key entirely.
func sbTransport(t model.Transport) (jobj, error) {
	switch t.Network {
	case model.NetTCP:
		if t.HeaderObfs != nil && t.HeaderObfs.Type != "" && t.HeaderObfs.Type != "none" {
			return nil, fmt.Errorf("render/singbox: tcp header obfuscation %q has no sing-box equivalent", t.HeaderObfs.Type)
		}
		return nil, nil

	case model.NetWS:
		ws := jobj{"type": "ws", "path": firstNonEmpty(t.Path, "/")}
		if h := sbHeaders(t, true); len(h) > 0 {
			ws["headers"] = h
		}
		if t.EarlyData > 0 {
			ws["max_early_data"] = t.EarlyData
			ws["early_data_header_name"] = firstNonEmpty(t.EDHeader, "Sec-WebSocket-Protocol")
		}
		return ws, nil

	case model.NetHTTPUpgrade:
		// httpupgrade has a first-class host field, so Host must not be
		// duplicated into headers -- sing-box would send it twice.
		hu := jobj{"type": "httpupgrade", "path": firstNonEmpty(t.Path, "/")}
		if t.Host != "" {
			hu["host"] = t.Host
		}
		if h := sbHeaders(t, false); len(h) > 0 {
			hu["headers"] = h
		}
		return hu, nil

	case model.NetGRPC:
		g := jobj{"type": "grpc", "service_name": t.ServiceName}
		if t.IdleTimeout > 0 {
			g["idle_timeout"] = sbSeconds(t.IdleTimeout)
		}
		if t.PermitWithout {
			g["permit_without_stream"] = true
		}
		// MultiMode is an Xray-only extension; sing-box's gRPC transport is
		// always single-stream ("gun"), so it is intentionally not emitted.
		return g, nil

	case model.NetH2:
		h := jobj{"type": "http", "path": firstNonEmpty(t.Path, "/")}
		hosts := t.H2Hosts
		if len(hosts) == 0 && t.Host != "" {
			hosts = []string{t.Host}
		}
		if len(hosts) > 0 {
			h["host"] = hosts
		}
		if hh := sbHeaders(t, false); len(hh) > 0 {
			h["headers"] = hh
		}
		return h, nil

	case model.NetQUIC:
		// sing-box's V2Ray QUIC transport takes no options; the obfuscation
		// header and QUIC key are Xray-only knobs and cannot be carried.
		return jobj{"type": "quic"}, nil

	default:
		return nil, fmt.Errorf("render/singbox: transport %q is not supported by sing-box; use xray", t.Network)
	}
}

// sbHeaders builds the extra-headers map. withHost folds Transport.Host into a
// Host header, which is how ws carries virtual-host fronting in sing-box.
func sbHeaders(t model.Transport, withHost bool) jobj {
	h := jobj{}
	for k, v := range t.Headers {
		h[k] = v
	}
	if withHost && t.Host != "" {
		if _, ok := h["Host"]; !ok {
			h["Host"] = t.Host
		}
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// sbTLS renders the canonical security layer as a sing-box TLS object. It
// returns nil when there is no TLS and force is false; force is used by the
// protocols that are TLS/QUIC by construction (Hysteria2, TUIC, AnyTLS,
// ShadowTLS), where an absent tls block is simply invalid.
func sbTLS(n *model.Node, force bool) jobj {
	s := n.Security
	if s.Type == model.SecNone && !force {
		return nil
	}
	tls := jobj{"enabled": true, "server_name": n.SNI()}
	if len(s.ALPN) > 0 {
		tls["alpn"] = s.ALPN
	}
	if s.AllowInsecure {
		tls["insecure"] = true
	}
	if s.MinVersion != "" {
		tls["min_version"] = s.MinVersion
	}
	if s.MaxVersion != "" {
		tls["max_version"] = s.MaxVersion
	}

	fp := s.Fingerprint
	if s.Type == model.SecReality {
		r := jobj{"enabled": true}
		if rr := s.Reality; rr != nil {
			if rr.PublicKey != "" {
				r["public_key"] = rr.PublicKey
			}
			sid := rr.ShortID
			if sid == "" && len(rr.ShortIDs) > 0 {
				sid = rr.ShortIDs[0]
			}
			r["short_id"] = sid
		}
		tls["reality"] = r
		// REALITY is a uTLS-only handshake in sing-box: without a fingerprint
		// the client cannot produce the ClientHello the server expects.
		fp = firstNonEmpty(fp, "chrome")
	}
	// uTLS is a TCP-TLS ClientHello fingerprint. QUIC protocols (Hysteria2, TUIC)
	// run their own TLS 1.3 stack, and sing-box rejects a utls block on them
	// ("unsupported usage for uTLS"), so never emit it there — even when
	// applyCreateDefaults has stamped a default fingerprint on the node.
	if fp != "" && !n.Protocol.IsQUICBased() {
		tls["utls"] = jobj{"enabled": true, "fingerprint": fp}
	}
	if e := s.ECH; e != nil && (e.Enabled || e.ConfigList != "" || e.AutoFetch) {
		ech := jobj{"enabled": true}
		// An empty config list means "resolve the ECHConfigList from the DNS
		// HTTPS record", which is sing-box's default behaviour.
		if e.ConfigList != "" {
			ech["config"] = []string{e.ConfigList}
		}
		tls["ech"] = ech
	}
	return tls
}

// sbMultiplex renders the canonical multiplex block. sing-box's mux is not
// mux.cool, so the Xray-only Concurrency field has no counterpart here.
func sbMultiplex(m *model.Multiplex) jobj {
	if m == nil || !m.Enabled {
		return nil
	}
	o := jobj{"enabled": true}
	if m.Protocol != "" {
		o["protocol"] = m.Protocol
	}
	if m.MaxConns > 0 {
		o["max_connections"] = m.MaxConns
	}
	if m.MinStreams > 0 {
		o["min_streams"] = m.MinStreams
	}
	if m.MaxStreams > 0 {
		o["max_streams"] = m.MaxStreams
	}
	if m.Padding {
		o["padding"] = true
	}
	if b := m.Brutal; b != nil && b.Enabled {
		o["brutal"] = jobj{"enabled": true, "up_mbps": b.UpMbps, "down_mbps": b.DownMbps}
	}
	return o
}

// sbSupportsMultiplex reports whether a sing-box outbound accepts a multiplex
// block. Emitting it elsewhere would trip sing-box's unknown-field check.
func sbSupportsMultiplex(p model.Protocol) bool {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks:
		return true
	default:
		return false
	}
}

// sbSeconds renders an integer number of seconds as a sing-box duration
// string; sing-box parses durations, not bare numbers.
func sbSeconds(sec int) string { return strconv.Itoa(sec) + "s" }

// sbPortRanges converts the canonical Hysteria2 port-hopping spec ("20000-50000",
// optionally comma-separated) into sing-box's server_ports form, which uses a
// colon separator ("20000:50000"). Malformed entries are skipped rather than
// failing the whole render: port hopping is an optimisation, not a requirement.
func sbPortRanges(spec string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(part, "-", ":")
		lo, hi, ok := strings.Cut(part, ":")
		if !ok {
			// A single port is still a legal (degenerate) range.
			if _, err := strconv.Atoi(part); err != nil {
				continue
			}
			out = append(out, part+":"+part)
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSpace(lo)); err != nil {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			continue
		}
		out = append(out, strings.TrimSpace(lo)+":"+strings.TrimSpace(hi))
	}
	return out
}

// SingboxInbound renders the canonical node as a sing-box INBOUND object (server
// side), for the supervisor's aggregate config. It covers the protocols
// sing-box serves natively; returns an error for the rest so the caller routes
// them to the correct engine.
// ServesInbound reports whether ForgePanel can serve this protocol as an
// INBOUND, as opposed to only dialling it as an outbound hop.
//
// SSH is the whole reason this exists. sing-box has an SSH OUTBOUND and no SSH
// inbound, and the engine map routes SSH to sing-box — so the panel advertised
// SSH in its protocol list, minted a default credential for it, accepted the
// inbound, and then failed to render it on every reload. The inbound existed in
// the database and served nobody.
//
// A false here is not a gap to be filled later: no core in this panel implements
// an SSH server, and SSH tunnelling on a VPS is provided by the host's own sshd,
// which is not this panel's to manage.
func ServesInbound(p model.Protocol) bool {
	switch p {
	case model.ProtoSSH:
		return false
	default:
		return true
	}
}

func SingboxInbound(n *model.Node) (jobj, error) {
	c := n.Clone()
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	tag := c.Tag
	if tag == "" {
		tag = "in-" + string(c.Protocol)
	}
	in := jobj{"tag": tag, "listen": "::", "listen_port": c.Port}
	switch c.Protocol {
	case model.ProtoVLESS:
		in["type"] = "vless"
		user := jobj{"uuid": c.UUID, "name": firstNonEmpty(c.Remark, "user")}
		if c.Flow != "" {
			user["flow"] = c.Flow
		}
		in["users"] = []any{user}
	case model.ProtoVMess:
		in["type"] = "vmess"
		in["users"] = []any{jobj{"uuid": c.UUID, "name": firstNonEmpty(c.Remark, "user"), "alterId": 0}}
	case model.ProtoTrojan:
		in["type"] = "trojan"
		in["users"] = []any{jobj{"password": c.Password, "name": firstNonEmpty(c.Remark, "user")}}
	case model.ProtoShadowsocks:
		in["type"] = "shadowsocks"
		in["method"] = c.Method
		in["password"] = c.Password
	case model.ProtoHysteria2:
		in["type"] = "hysteria2"
		in["users"] = []any{jobj{"password": c.Password}}
		if h := c.Hysteria2; h != nil {
			if h.UpMbps > 0 {
				in["up_mbps"] = h.UpMbps
			}
			if h.DownMbps > 0 {
				in["down_mbps"] = h.DownMbps
			}
			if h.ObfsType != "" && h.ObfsPassword != "" {
				in["obfs"] = jobj{"type": h.ObfsType, "password": h.ObfsPassword}
			}
			if h.IgnoreClientBandwidth {
				in["ignore_client_bandwidth"] = true
			}
			if m := hy2Masquerade(h); m != nil {
				in["masquerade"] = m
			}
			// NB: brutal_cc is NOT a sing-box field and is never emitted.
		}
	case model.ProtoTUIC:
		in["type"] = "tuic"
		in["users"] = []any{jobj{"uuid": c.UUID, "password": c.Password}}
		if t := c.TUIC; t != nil {
			if t.CongestionControl != "" {
				in["congestion_control"] = t.CongestionControl
			}
		}
	case model.ProtoAnyTLS:
		in["type"] = "anytls"
		in["users"] = []any{jobj{"password": c.Password}}
		if c.AnyTLS != nil && len(c.AnyTLS.PaddingScheme) > 0 {
			in["padding_scheme"] = c.AnyTLS.PaddingScheme
		}
	case model.ProtoShadowTLS:
		in["type"] = "shadowtls"
		v := 3
		if c.ShadowTLS != nil && c.ShadowTLS.Version != 0 {
			v = c.ShadowTLS.Version
		}
		in["version"] = v
		if c.ShadowTLS != nil {
			in["users"] = []any{jobj{"name": "user", "password": c.ShadowTLS.Password}}
			if c.ShadowTLS.HandshakeHost != "" {
				in["handshake"] = jobj{"server": c.ShadowTLS.HandshakeHost, "server_port": firstInt(c.ShadowTLS.HandshakePort, 443)}
			}
		}
		// ShadowTLS is camouflage only; the unwrapped stream is handed to an inner
		// Shadowsocks inbound (emitted by SingboxInbounds) via detour.
		in["detour"] = stlsInnerTag(c)
	default:
		return nil, fmt.Errorf("render/singbox: protocol %q has no sing-box inbound here", c.Protocol)
	}
	// TLS + transport, reusing the outbound helpers. ShadowTLS is excluded: it
	// carries its TLS mimicry in the `handshake` field, so a top-level `tls` block
	// makes sing-box reject the inbound.
	needsTLS := (c.Security.Type == model.SecTLS || c.Protocol.IsQUICBased() || c.Protocol == model.ProtoAnyTLS) &&
		c.Protocol != model.ProtoShadowTLS
	if needsTLS {
		tls := sbTLS(c, true)
		if tls == nil {
			tls = jobj{"enabled": true}
		}
		delete(tls, "insecure")
		delete(tls, "utls")
		if c.Security.CertificateFile != "" {
			tls["certificate_path"] = c.Security.CertificateFile
			tls["key_path"] = c.Security.KeyFile
		}
		if c.Security.ServerName != "" {
			tls["server_name"] = c.Security.ServerName
		}
		in["tls"] = tls
	}
	if c.Protocol.UsesTransport() {
		if tr, err := sbTransport(c.Transport); err == nil && tr != nil {
			in["transport"] = tr
		}
	}
	return in, nil
}

// firstInt returns v if non-zero, else def.
func firstInt(v, def int) int {
	if v != 0 {
		return v
	}
	return def
}

// hy2Masquerade builds the sing-box hysteria2 masquerade object (verified against
// the pinned sing-box: proxy/file/string types). Returns nil when unset.
func hy2Masquerade(h *model.Hysteria2Options) jobj {
	m := h.Masquerade
	if m == nil || m.Type == "" {
		return nil
	}
	out := jobj{"type": m.Type}
	switch m.Type {
	case "proxy":
		out["url"] = m.URL
		if m.RewriteHost {
			out["rewrite_host"] = true
		}
	case "file":
		out["directory"] = m.Directory
	case "string":
		if m.StatusCode > 0 {
			out["status_code"] = m.StatusCode
		}
		if len(m.Headers) > 0 {
			out["headers"] = m.Headers
		}
		out["content"] = m.Content
	}
	return out
}

// stlsInnerTag / stlsInnerPort name the loopback Shadowsocks inbound that a
// ShadowTLS inbound detours to. The inner port is loopback-only, so it just has
// to avoid the outer port; a fixed high offset keeps it deterministic.
func stlsInnerTag(n *model.Node) string { return fmt.Sprintf("stls-inner-%d", n.Port) }

func stlsInnerPort(n *model.Node) int {
	p := n.Port + 20000
	if p > 65535 {
		p = n.Port - 20000
	}
	return p
}

// IsSingboxEndpoint reports whether a node renders as a sing-box endpoints[]
// entry rather than an inbounds[] entry. Only WireGuard does today (sing-box
// ≥1.13: WireGuard is an endpoint, never an inbound/outbound).
func IsSingboxEndpoint(n *model.Node) bool { return n.Protocol == model.ProtoWireGuard }

// SingboxEndpoint renders a WireGuard SERVER as a sing-box endpoints[] entry
// (schema option/wireguard.go): the server's private key + listen_port + its own
// tunnel address, and the client registered as a peer by public key. This is a
// real, standard WireGuard server any wg/Amnezia client can connect to.
func SingboxEndpoint(n *model.Node) (jobj, error) {
	if n.Protocol != model.ProtoWireGuard {
		return nil, fmt.Errorf("render/singbox: %q is not a sing-box endpoint", n.Protocol)
	}
	w := n.WireGuard
	if w == nil || w.PrivateKey == "" {
		return nil, fmt.Errorf("render/singbox: wireguard endpoint needs a private key")
	}
	addr := w.ServerAddress
	if len(addr) == 0 {
		addr = w.LocalAddress
	}
	if len(addr) == 0 {
		addr = []string{"10.66.66.1/24"}
	}
	peer := jobj{"public_key": w.PeerPublicKey}
	peerIPs := w.PeerAddress
	if len(peerIPs) == 0 {
		peerIPs = []string{"10.66.66.2/32"}
	}
	peer["allowed_ips"] = peerIPs
	if w.PreSharedKey != "" {
		peer["pre_shared_key"] = w.PreSharedKey
	}
	if w.Keepalive > 0 {
		peer["persistent_keepalive_interval"] = w.Keepalive
	}
	ep := jobj{
		"type":        "wireguard",
		"tag":         firstNonEmpty(n.Tag, fmt.Sprintf("wg-%d", n.Port)),
		"address":     addr,
		"private_key": w.PrivateKey,
		"listen_port": n.Port,
		"peers":       []any{peer},
	}
	if w.MTU > 0 {
		ep["mtu"] = w.MTU
	}
	return ep, nil
}

// SingboxInbounds renders every sing-box inbound a node materialises. Most nodes
// map to exactly one inbound; ShadowTLS maps to two — the public camouflage
// inbound plus the loopback Shadowsocks inbound it detours to (that inner SS is
// what actually carries the tunnel). Callers should append ALL returned inbounds.
func SingboxInbounds(n *model.Node) ([]jobj, error) {
	primary, err := SingboxInbound(n)
	if err != nil {
		return nil, err
	}
	out := []jobj{primary}
	if n.Protocol == model.ProtoShadowTLS && n.ShadowTLS != nil {
		method := n.ShadowTLS.InnerMethod
		if method == "" {
			method = model.SS2022AES128
		}
		out = append(out, jobj{
			"type":        "shadowsocks",
			"tag":         stlsInnerTag(n),
			"listen":      "127.0.0.1",
			"listen_port": stlsInnerPort(n),
			"method":      method,
			"password":    n.ShadowTLS.InnerPassword,
		})
	}
	return out, nil
}
