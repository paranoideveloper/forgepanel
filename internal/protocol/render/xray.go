// Package render turns a canonical model.Node into a concrete engine
// configuration (spec §3 render/, §4 P4): Xray JSON, sing-box JSON, and Brook
// args. The output of RenderXray for a transport/security combination Xray
// supports must be accepted by `xray run -test` (spec §18).
package render

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// jobj is a small ordered-ish JSON object helper. Xray does not care about key
// order, so a plain map is fine; we omit empty values for clean output.
type jobj = map[string]any

// XrayInbound renders the node as an Xray inbound object. Not every protocol is
// an Xray protocol (Hysteria2/TUIC/AnyTLS/WireGuard/Brook/ForgeDNS route to
// sing-box or a dedicated engine); RenderXray returns an error for those so the
// caller can fall back to the right engine.
func XrayInbound(n *model.Node) (jobj, error) {
	c := n.Clone()
	c.Normalize()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	settings, err := xraySettings(c, true)
	if err != nil {
		return nil, err
	}
	in := jobj{
		"tag":      tagOr(c.Tag, "inbound"),
		"protocol": string(c.Protocol),
		"port":     c.Port,
		"listen":   c.Address,
		"settings": settings,
	}
	if ss := xrayStreamSettings(c, true); ss != nil {
		// Inbound TLS needs a server certificate; wire the (self-signed or
		// imported) cert files the engine provisioned onto the node.
		if c.Security.Type == model.SecTLS && c.Security.CertificateFile != "" {
			if tls, ok := ss["tlsSettings"].(jobj); ok {
				tls["certificates"] = []any{jobj{
					"certificateFile": c.Security.CertificateFile,
					"keyFile":         c.Security.KeyFile,
				}}
			}
		}
		in["streamSettings"] = ss
	}
	in["sniffing"] = jobj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}
	return in, nil
}

// XrayOutbound renders the node as an Xray outbound object (client side).
func XrayOutbound(n *model.Node) (jobj, error) {
	c := n.Clone()
	c.Normalize()
	settings, err := xraySettings(c, false)
	if err != nil {
		return nil, err
	}
	out := jobj{
		"tag":      tagOr(c.Tag, "proxy"),
		"protocol": string(c.Protocol),
		"settings": settings,
	}
	if ss := xrayStreamSettings(c, false); ss != nil {
		out["streamSettings"] = ss
	}
	return out, nil
}

// RenderXrayJSON returns a complete, indented Xray config with the node as the
// single outbound and a socks inbound -- exactly what `xray run -test` checks.
func RenderXrayJSON(n *model.Node) ([]byte, error) {
	out, err := XrayOutbound(n)
	if err != nil {
		return nil, err
	}
	cfg := jobj{
		"log":       jobj{"loglevel": "warning"},
		"inbounds":  []any{jobj{"tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": jobj{"udp": true}}},
		"outbounds": []any{out},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func tagOr(tag, def string) string {
	if tag != "" {
		return tag
	}
	return def
}

func xraySettings(n *model.Node, inbound bool) (jobj, error) {
	switch n.Protocol {
	case model.ProtoVLESS:
		if inbound {
			client := jobj{"id": n.UUID}
			if n.Flow != "" {
				client["flow"] = n.Flow
			}
			return jobj{"clients": []any{client}, "decryption": "none"}, nil
		}
		user := jobj{"id": n.UUID, "encryption": firstNonEmpty(n.Encryption, "none")}
		if n.Flow != "" {
			user["flow"] = n.Flow
		}
		return jobj{"vnext": []any{jobj{"address": n.Address, "port": n.Port, "users": []any{user}}}}, nil

	case model.ProtoVMess:
		if inbound {
			return jobj{"clients": []any{jobj{"id": n.UUID, "alterId": 0}}}, nil
		}
		return jobj{"vnext": []any{jobj{"address": n.Address, "port": n.Port,
			"users": []any{jobj{"id": n.UUID, "alterId": 0, "security": firstNonEmpty(n.Encryption, "auto")}}}}}, nil

	case model.ProtoTrojan:
		if inbound {
			return jobj{"clients": []any{jobj{"password": n.Password}}}, nil
		}
		return jobj{"servers": []any{jobj{"address": n.Address, "port": n.Port, "password": n.Password}}}, nil

	case model.ProtoShadowsocks:
		if inbound {
			return jobj{"method": n.Method, "password": n.Password, "network": "tcp,udp"}, nil
		}
		return jobj{"servers": []any{jobj{"address": n.Address, "port": n.Port, "method": n.Method, "password": n.Password}}}, nil

	case model.ProtoSOCKS:
		if inbound {
			s := jobj{"auth": "noauth", "udp": true}
			if n.Username != "" {
				s["auth"] = "password"
				s["accounts"] = []any{jobj{"user": n.Username, "pass": n.Password}}
			}
			return s, nil
		}
		srv := jobj{"address": n.Address, "port": n.Port}
		if n.Username != "" {
			srv["users"] = []any{jobj{"user": n.Username, "pass": n.Password}}
		}
		return jobj{"servers": []any{srv}}, nil

	case model.ProtoHTTP:
		if inbound {
			s := jobj{}
			if n.Username != "" {
				s["accounts"] = []any{jobj{"user": n.Username, "pass": n.Password}}
			}
			return s, nil
		}
		srv := jobj{"address": n.Address, "port": n.Port}
		if n.Username != "" {
			srv["users"] = []any{jobj{"user": n.Username, "pass": n.Password}}
		}
		return jobj{"servers": []any{srv}}, nil

	case model.ProtoWireGuard:
		w := n.WireGuard
		s := jobj{
			"secretKey": w.PrivateKey,
			"peers": []any{jobj{
				"publicKey": w.PublicKey, "endpoint": fmt.Sprintf("%s:%d", n.Address, n.Port),
				"allowedIPs": defaultStrs(w.AllowedIPs, []string{"0.0.0.0/0", "::/0"}),
			}},
		}
		if len(w.LocalAddress) > 0 {
			s["address"] = w.LocalAddress
		}
		if w.MTU > 0 {
			s["mtu"] = w.MTU
		}
		if len(w.Reserved) == 3 {
			s["reserved"] = w.Reserved
		}
		return s, nil

	default:
		return nil, fmt.Errorf("render/xray: protocol %q is not an Xray protocol; use sing-box", n.Protocol)
	}
}

// xrayStreamSettings maps the canonical transport+security onto Xray's
// streamSettings. Returns nil for protocols that do not use the transport
// stack.
func xrayStreamSettings(n *model.Node, inbound bool) jobj {
	if !n.Protocol.UsesTransport() {
		return nil
	}
	return xrayStream(n.Transport, n.Security, n.SNI(), inbound)
}

// xrayStream builds a streamSettings object from a transport + security pair.
// It is split out of xrayStreamSettings because XHTTP's downloadSettings is a
// COMPLETE second streamSettings (its own transport and its own TLS/REALITY
// layer) and must be rendered by exactly the same code -- a hand-rolled second
// implementation is how the download leg silently ends up with a different TLS
// shape from the upload leg.
func xrayStream(t model.Transport, sec model.Security, sni string, inbound bool) jobj {
	ss := jobj{"network": networkName(t.Network)}
	switch t.Network {
	case model.NetTCP:
		if t.HeaderObfs != nil && t.HeaderObfs.Type == "http" {
			req := jobj{"path": splitOr(t.Path, "/")}
			// An empty Host was being sent as `"Host": [""]`. The point of this
			// transport is to look like ordinary web traffic, and a request with
			// a blank Host header looks like nothing else on the internet — it
			// made the camouflage more distinctive than no camouflage. Omit the
			// header entirely when there is nothing to put in it.
			if t.Host != "" {
				req["headers"] = jobj{"Host": []string{t.Host}}
			}
			ss["tcpSettings"] = jobj{"header": jobj{"type": "http", "request": req}}
		}
	case model.NetWS:
		wsHeaders := jobj{}
		if t.Host != "" {
			wsHeaders["Host"] = t.Host
		}
		ws := jobj{"path": firstNonEmpty(t.Path, "/")}
		if t.EarlyData > 0 {
			ws["maxEarlyData"] = t.EarlyData
		}
		if t.EDHeader != "" {
			ws["earlyDataHeaderName"] = t.EDHeader
		}
		if len(wsHeaders) > 0 {
			ws["headers"] = wsHeaders
		}
		ss["wsSettings"] = ws
	case model.NetHTTPUpgrade:
		hu := jobj{"path": firstNonEmpty(t.Path, "/")}
		if t.Host != "" {
			hu["host"] = t.Host
		}
		ss["httpupgradeSettings"] = hu
	case model.NetGRPC:
		g := jobj{"serviceName": t.ServiceName, "multiMode": t.MultiMode}
		if t.IdleTimeout > 0 {
			g["idle_timeout"] = t.IdleTimeout
		}
		if t.InitialWindows > 0 {
			g["initial_windows_size"] = t.InitialWindows
		}
		if t.HealthCheckTimeout > 0 {
			g["health_check_timeout"] = t.HealthCheckTimeout
		}
		if t.PermitWithout {
			g["permit_without_stream"] = true
		}
		ss["grpcSettings"] = g
	case model.NetXHTTP:
		ss["xhttpSettings"] = xrayXHTTPSettings(t, inbound)
	case model.NetH2:
		h2 := jobj{"path": firstNonEmpty(t.Path, "/")}
		if t.Host != "" {
			h2["host"] = []string{t.Host}
		}
		ss["httpSettings"] = h2
	case model.NetMKCP:
		k := jobj{"header": jobj{"type": "none"}}
		if t.Seed != "" {
			k["seed"] = t.Seed
		}
		if t.HeaderObfs != nil && t.HeaderObfs.Type != "" {
			k["header"] = jobj{"type": t.HeaderObfs.Type}
		}
		ss["kcpSettings"] = k
	case model.NetQUIC:
		ss["quicSettings"] = jobj{"security": firstNonEmpty(t.QUICSecurity, "none"), "key": t.QUICKey, "header": jobj{"type": "none"}}
	}

	switch sec.Type {
	case model.SecTLS:
		ss["security"] = "tls"
		tls := jobj{"serverName": sni}
		if len(sec.ALPN) > 0 {
			tls["alpn"] = sec.ALPN
		}
		if sec.Fingerprint != "" {
			tls["fingerprint"] = sec.Fingerprint
		}
		if sec.MinVersion != "" {
			tls["minVersion"] = sec.MinVersion
		}
		if sec.MaxVersion != "" {
			tls["maxVersion"] = sec.MaxVersion
		}
		if sec.CipherSuites != "" {
			tls["cipherSuites"] = sec.CipherSuites
		}
		// Xray 26 removed "allowInsecure"; skip-verify is now pinnedPeerCertSha256.
		if len(sec.PinSHA256) > 0 {
			tls["pinnedPeerCertSha256"] = sec.PinSHA256[0]
		}
		ss["tlsSettings"] = tls
	case model.SecReality:
		ss["security"] = "reality"
		r := sec.Reality
		rs := jobj{"show": false, "fingerprint": firstNonEmpty(sec.Fingerprint, "chrome")}
		if r != nil {
			// A server inbound carries privateKey; a client outbound carries
			// publicKey. Emitting both makes Xray's REALITY outbound treat the
			// node as a server and report "publicKey == nil".
			if inbound {
				if r.PrivateKey != "" {
					rs["privateKey"] = r.PrivateKey
				}
			} else {
				if r.PublicKey != "" {
					rs["publicKey"] = r.PublicKey
				}
			}
			rs["serverName"] = sni
			sid := r.ShortID
			if sid == "" && len(r.ShortIDs) > 0 {
				sid = r.ShortIDs[0]
			}
			if sid != "" {
				rs["shortId"] = sid
			}
			// dest/target, serverNames[] and shortIds[] are SERVER-only fields;
			// emitting them on a client outbound makes Xray 26 treat the node as
			// a server and demand a privateKey. Gate them to the inbound.
			if inbound {
				if r.Dest != "" {
					rs["dest"] = r.Dest
					rs["target"] = r.Dest
				}
				if len(r.ServerNames) > 0 {
					rs["serverNames"] = r.ServerNames
				}
				// Xray's REALITY inbound requires a non-empty shortIds array; a
				// single empty string matches any client shortId.
				shortIds := append([]string{}, r.ShortIDs...)
				if len(shortIds) == 0 {
					if sid != "" {
						shortIds = []string{sid}
					} else {
						shortIds = []string{""}
					}
				}
				rs["shortIds"] = shortIds
				if r.Xver > 0 {
					rs["xver"] = r.Xver
				}
			}

			if r.SpiderX != "" {
				rs["spiderX"] = r.SpiderX
			}
		}
		ss["realitySettings"] = rs
	}
	return ss
}

// xrayXHTTPSettings renders the full modern xhttpSettings object. Every key
// below exists in the pinned Xray's XHTTP schema (verified against the binary);
// keys are omitted when unset so the emitted config stays the operator's own
// configuration rather than a wall of defaults that hides what was chosen.
func xrayXHTTPSettings(t model.Transport, inbound bool) jobj {
	xh := jobj{"path": firstNonEmpty(t.Path, "/"), "mode": firstNonEmpty(t.XHTTPMode, model.XHTTPModeAuto)}
	if t.Host != "" {
		xh["host"] = t.Host
	}
	if len(t.Headers) > 0 {
		h := jobj{}
		for k, v := range t.Headers {
			h[k] = v
		}
		xh["headers"] = h
	}

	setStr := func(key, val string) {
		if val != "" {
			xh[key] = val
		}
	}
	setInt := func(key string, val int) {
		if val > 0 {
			xh[key] = val
		}
	}
	setStr("xPaddingBytes", t.XPaddingB)
	if t.XPaddingObfsMode {
		// The padding key/header/placement/method family is only read when
		// obfuscated padding is on, so emitting it otherwise would advertise a
		// configuration the core is not actually applying.
		xh["xPaddingObfsMode"] = true
		setStr("xPaddingKey", t.XPaddingKey)
		setStr("xPaddingHeader", t.XPaddingHeader)
		setStr("xPaddingPlacement", t.XPaddingPlacement)
		setStr("xPaddingMethod", t.XPaddingMethod)
	}
	if t.NoGRPCHeader {
		xh["noGRPCHeader"] = true
	}
	if t.NoSSEHeader {
		xh["noSSEHeader"] = true
	}
	setStr("scMaxEachPostBytes", t.SCMaxEachPostBytes)
	setStr("scMinPostsIntervalMs", t.SCMinPostsIntervalMs)
	setInt("scMaxBufferedPosts", t.SCMaxBufferedPosts)
	setStr("scStreamUpServerSecs", t.SCStreamUpServerSecs)
	setStr("sessionPlacement", t.SessionPlacement)
	setStr("sessionKey", t.SessionKey)
	setStr("seqPlacement", t.SeqPlacement)
	setStr("seqKey", t.SeqKey)
	setStr("uplinkDataPlacement", t.UplinkDataPlacement)
	setStr("uplinkDataKey", t.UplinkDataKey)
	setStr("uplinkHTTPMethod", t.UplinkHTTPMethod)
	setInt("uplinkChunkSize", t.UplinkChunkSize)

	// serverMaxHeaderBytes caps what the LISTENER will accept; on a client
	// outbound it is meaningless and only widens the config fingerprint.
	if inbound {
		setInt("serverMaxHeaderBytes", t.ServerMaxHeaderBytes)
	}

	if x := t.XMux; x != nil {
		xm := jobj{}
		if x.MaxConcurrency != "" {
			xm["maxConcurrency"] = x.MaxConcurrency
		}
		if x.MaxConnections != "" {
			xm["maxConnections"] = x.MaxConnections
		}
		if x.CMaxReuseTimes != "" {
			xm["cMaxReuseTimes"] = x.CMaxReuseTimes
		}
		if x.HMaxRequestTime != "" {
			xm["hMaxRequestTimes"] = x.HMaxRequestTime
		}
		if x.HMaxReusableSecs != "" {
			xm["hMaxReusableSecs"] = x.HMaxReusableSecs
		}
		if x.HKeepAlivePeriod > 0 {
			xm["hKeepAlivePeriod"] = x.HKeepAlivePeriod
		}
		if len(xm) > 0 {
			xh["xmux"] = xm
		}
	}

	// downloadSettings splits the download direction onto its own stream. The
	// core only honours it on the CLIENT side, and refuses it outright in
	// stream-one mode -- Validate rejects that combination before we get here.
	if d := t.XHTTPDownload; d != nil && !inbound {
		xh["downloadSettings"] = xrayDownloadSettings(d)
	}
	return xh
}

// xrayDownloadSettings renders XHTTP's download leg: a streamSettings object
// plus the address/port it dials, which is what lets the download ride a
// different host (direct, or a second CDN) from the upload.
func xrayDownloadSettings(d *model.XHTTPDownload) jobj {
	t := d.Transport
	// A download leg never carries a further download leg; the core has no
	// nesting and a self-referential transport would recurse forever here.
	t.XHTTPDownload = nil
	ss := xrayStream(t, d.Security, d.SNI(), false)
	if d.Address != "" {
		ss["address"] = d.Address
	}
	if d.Port > 0 {
		ss["port"] = d.Port
	}
	return ss
}

func networkName(n model.Network) string {
	switch n {
	case model.NetMKCP:
		return "kcp"
	case model.NetH2:
		return "http"
	default:
		return string(n)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitOr(s, def string) []string {
	if s == "" {
		return []string{def}
	}
	return []string{s}
}

func defaultStrs(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

// EngineFor reports which engine renders a given protocol. This drives the
// supervisor's routing (spec §6): Xray for the classic V2Ray-family protocols,
// sing-box for the QUIC/modern ones, Brook for Brook.
// EngineFor reports which engine serves a protocol.
//
// The mapping itself lives in model.EngineFor — one authority, because this
// function previously had two hand-maintained duplicates that had silently
// drifted (see internal/protocol/model/engine.go). This wrapper stays because
// it is the name the rest of the codebase and the docs already use.
func EngineFor(p model.Protocol) string { return model.EngineFor(p) }

var _ = strings.TrimSpace
