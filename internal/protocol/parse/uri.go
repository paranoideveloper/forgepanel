// Package parse converts any client link, subscription blob, or foreign panel
// export back into the canonical model.Node (spec §3, §8.3). It is the inverse
// of export/ and the pair satisfies parse(export(x)) == x (spec §15).
package parse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// URI parses a single share link into a normalized canonical node.
func URI(raw string) (*model.Node, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("parse: not a URI: %q", trunc(raw))
	}
	var (
		n   *model.Node
		err error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		n, err = parseVLESS(raw)
	case "vmess":
		n, err = parseVMess(raw)
	case "trojan":
		n, err = parseTrojan(raw)
	case "ss":
		n, err = parseSS(raw)
	case "socks", "socks5":
		n, err = parseSOCKS(raw)
	case "http", "https":
		n, err = parseHTTP(raw)
	case "hysteria2", "hy2":
		n, err = parseHysteria2(raw)
	case "tuic":
		n, err = parseTUIC(raw)
	case "anytls":
		n, err = parseAnyTLS(raw)
	case "wireguard", "wg":
		n, err = parseWireGuard(raw)
	case "brook":
		n, err = parseBrook(raw)
	case "ssh":
		n, err = parseSSH(raw)
	case "forgedns":
		n, err = parseForgeDNS(raw)
	default:
		return nil, fmt.Errorf("parse: unsupported scheme %q", scheme)
	}
	if err != nil {
		return nil, err
	}
	n.Normalize()
	return n, nil
}

func trunc(s string) string {
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}

// splitLink parses the "user@host:port?query#frag" body common to most schemes.
type link struct {
	user  string
	host  string
	port  int
	query url.Values
	frag  string
}

func parseLink(raw, scheme string) (link, error) {
	rest := strings.TrimPrefix(raw, scheme+"://")
	var l link
	if i := strings.Index(rest, "#"); i >= 0 {
		l.frag = decodeFragment(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		q, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return l, fmt.Errorf("bad query: %w", err)
		}
		l.query = q
		rest = rest[:i]
	} else {
		l.query = url.Values{}
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		l.user = rest[:i]
		rest = rest[i+1:]
	}
	host, port, err := splitHostPort(rest)
	if err != nil {
		return l, err
	}
	l.host, l.port = host, port
	return l, nil
}

func decodeFragment(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func splitHostPort(hp string) (string, int, error) {
	hp = strings.TrimSuffix(hp, "/")
	// IPv6 literal [::1]:443
	if strings.HasPrefix(hp, "[") {
		end := strings.Index(hp, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("bad IPv6 literal: %q", hp)
		}
		host := hp[1:end]
		rest := hp[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return host, 0, fmt.Errorf("missing port")
		}
		p, err := strconv.Atoi(rest[1:])
		return host, p, err
	}
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		return hp, 0, fmt.Errorf("missing port in %q", hp)
	}
	p, err := strconv.Atoi(hp[i+1:])
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", hp[i+1:], err)
	}
	return hp[:i], p, nil
}

// applyTransportSecurity is the inverse of export.transportSecurityParams.
func applyTransportSecurity(n *model.Node, q url.Values) {
	t := &n.Transport
	switch strings.ToLower(q.Get("type")) {
	case "ws":
		t.Network = model.NetWS
		t.Path = q.Get("path")
		t.Host = q.Get("host")
	case "httpupgrade":
		t.Network = model.NetHTTPUpgrade
		t.Path = q.Get("path")
		t.Host = q.Get("host")
	case "grpc", "gun":
		t.Network = model.NetGRPC
		t.ServiceName = q.Get("serviceName")
		t.MultiMode = q.Get("mode") == "multi"
	case "xhttp", "splithttp":
		t.Network = model.NetXHTTP
		t.Path = q.Get("path")
		t.Host = q.Get("host")
		if m := q.Get("mode"); m != "" {
			t.XHTTPMode = m
		}
		applyXHTTPExtended(t, q)
	case "h2", "http":
		t.Network = model.NetH2
		t.Path = q.Get("path")
		t.Host = q.Get("host")
	case "kcp", "mkcp":
		t.Network = model.NetMKCP
		t.Seed = q.Get("seed")
		if ht := q.Get("headerType"); ht != "" && ht != "none" {
			t.HeaderObfs = &model.Header{Type: ht}
		}
	case "quic":
		t.Network = model.NetQUIC
		if qs := q.Get("quicSecurity"); qs != "" && qs != "none" {
			t.QUICSecurity = qs
			t.QUICKey = q.Get("key")
		}
		if ht := q.Get("headerType"); ht != "" && ht != "none" {
			t.HeaderObfs = &model.Header{Type: ht}
		}
	case "tcp", "":
		t.Network = model.NetTCP
		if q.Get("headerType") == "http" {
			t.HeaderObfs = &model.Header{Type: "http"}
			t.Host = q.Get("host")
			t.Path = q.Get("path")
		}
	}

	switch strings.ToLower(q.Get("security")) {
	case "tls", "xtls":
		n.Security.Type = model.SecTLS
		n.Security.ServerName = q.Get("sni")
		if a := q.Get("alpn"); a != "" {
			n.Security.ALPN = strings.Split(a, ",")
		}
		n.Security.Fingerprint = q.Get("fp")
		if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
			n.Security.AllowInsecure = true
		}
		if ech := q.Get("ech"); ech != "" {
			n.Security.ECH = &model.ECH{Enabled: true, ConfigList: ech}
		}
	case "reality":
		n.Security.Type = model.SecReality
		n.Security.ServerName = q.Get("sni")
		n.Security.Fingerprint = q.Get("fp")
		if a := q.Get("alpn"); a != "" {
			n.Security.ALPN = strings.Split(a, ",")
		}
		r := &model.Reality{
			PublicKey: q.Get("pbk"),
			ShortID:   q.Get("sid"),
			SpiderX:   q.Get("spx"),
		}
		if pqv := q.Get("pqv"); pqv != "" {
			r.MLDSA65Verify = pqv
		}
		n.Security.Reality = r
	default:
		n.Security.Type = model.SecNone
	}
}

func parseVLESS(raw string) (*model.Node, error) {
	l, err := parseLink(raw, "vless")
	if err != nil {
		return nil, err
	}
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: l.host, Port: l.port,
		UUID: l.user, Remark: l.frag,
		Flow: l.query.Get("flow"), Encryption: l.query.Get("encryption"),
	}
	applyTransportSecurity(n, l.query)
	return n, nil
}

func parseTrojan(raw string) (*model.Node, error) {
	l, err := parseLink(raw, "trojan")
	if err != nil {
		return nil, err
	}
	pw, _ := url.QueryUnescape(l.user)
	n := &model.Node{
		Protocol: model.ProtoTrojan, Address: l.host, Port: l.port,
		Password: pw, Remark: l.frag, Flow: l.query.Get("flow"),
	}
	applyTransportSecurity(n, l.query)
	// Trojan implies TLS unless a CDN-plain security was explicitly set.
	if n.Security.Type == model.SecNone && l.query.Get("security") == "" {
		n.Security.Type = model.SecTLS
		n.Security.ServerName = l.query.Get("sni")
	}
	return n, nil
}

func parseAnyTLS(raw string) (*model.Node, error) {
	l, err := parseLink(raw, "anytls")
	if err != nil {
		return nil, err
	}
	pw, _ := url.QueryUnescape(l.user)
	n := &model.Node{
		Protocol: model.ProtoAnyTLS, Address: l.host, Port: l.port,
		Password: pw, Remark: l.frag,
	}
	applyTransportSecurity(n, l.query)
	if n.Security.Type == model.SecNone && l.query.Get("security") == "" {
		n.Security.Type = model.SecTLS
		n.Security.ServerName = l.query.Get("sni")
	}
	if ps := l.query.Get("padding_scheme"); ps != "" {
		n.AnyTLS = &model.AnyTLSOptions{PaddingScheme: strings.Split(ps, "\n")}
	}
	return n, nil
}

func parseVMess(raw string) (*model.Node, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	rawJSON, err := model.DecodeBase64Any(b64)
	if err != nil {
		return nil, fmt.Errorf("vmess: base64: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, fmt.Errorf("vmess: json: %w", err)
	}
	gs := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.Itoa(int(v))
		default:
			return ""
		}
	}
	port, _ := strconv.Atoi(gs("port"))
	n := &model.Node{
		Protocol: model.ProtoVMess, Address: gs("add"), Port: port,
		UUID: gs("id"), Remark: gs("ps"), Encryption: gs("scy"),
	}
	if n.Encryption == "" {
		n.Encryption = "auto"
	}
	switch gs("net") {
	case "ws":
		n.Transport.Network = model.NetWS
		n.Transport.Host = gs("host")
		n.Transport.Path = gs("path")
	case "grpc":
		n.Transport.Network = model.NetGRPC
		n.Transport.ServiceName = gs("path")
		n.Transport.MultiMode = gs("type") == "multi"
	case "h2":
		n.Transport.Network = model.NetH2
		n.Transport.Host = gs("host")
		n.Transport.Path = gs("path")
	case "httpupgrade":
		n.Transport.Network = model.NetHTTPUpgrade
		n.Transport.Host = gs("host")
		n.Transport.Path = gs("path")
	case "kcp":
		n.Transport.Network = model.NetMKCP
		n.Transport.Seed = gs("path")
		if t := gs("type"); t != "" && t != "none" {
			n.Transport.HeaderObfs = &model.Header{Type: t}
		}
	default:
		n.Transport.Network = model.NetTCP
		if gs("type") == "http" {
			n.Transport.HeaderObfs = &model.Header{Type: "http"}
			n.Transport.Host = gs("host")
			n.Transport.Path = gs("path")
		}
	}
	switch gs("tls") {
	case "tls":
		n.Security.Type = model.SecTLS
		n.Security.ServerName = gs("sni")
		n.Security.Fingerprint = gs("fp")
		if a := gs("alpn"); a != "" {
			n.Security.ALPN = strings.Split(a, ",")
		}
	case "reality":
		n.Security.Type = model.SecReality
		n.Security.ServerName = gs("sni")
		n.Security.Fingerprint = gs("fp")
		n.Security.Reality = &model.Reality{PublicKey: gs("pbk"), ShortID: gs("sid")}
	}
	return n, nil
}

func parseSS(raw string) (*model.Node, error) {
	body := strings.TrimPrefix(raw, "ss://")
	var frag string
	if i := strings.Index(body, "#"); i >= 0 {
		frag = decodeFragment(body[i+1:])
		body = body[:i]
	}
	var q url.Values
	if i := strings.Index(body, "?"); i >= 0 {
		q, _ = url.ParseQuery(body[i+1:])
		body = body[:i]
	}
	var method, password, host string
	var port int
	if at := strings.LastIndex(body, "@"); at >= 0 {
		// SIP002: userinfo may be base64(method:password) or plain method:password
		userinfo := body[:at]
		if dec, err := model.DecodeBase64Any(userinfo); err == nil && strings.Contains(string(dec), ":") {
			method, password, _ = strings.Cut(string(dec), ":")
		} else if uq, err := url.QueryUnescape(userinfo); err == nil && strings.Contains(uq, ":") {
			method, password, _ = strings.Cut(uq, ":")
		} else {
			method, password, _ = strings.Cut(userinfo, ":")
		}
		h, p, err := splitHostPort(body[at+1:])
		if err != nil {
			return nil, err
		}
		host, port = h, p
	} else {
		// Legacy: ss://base64(method:password@host:port)
		dec, err := model.DecodeBase64Any(body)
		if err != nil {
			return nil, fmt.Errorf("ss: %w", err)
		}
		s := string(dec)
		mp, hp, ok := strings.Cut(s, "@")
		if !ok {
			return nil, fmt.Errorf("ss: malformed legacy link")
		}
		method, password, _ = strings.Cut(mp, ":")
		h, p, err := splitHostPort(hp)
		if err != nil {
			return nil, err
		}
		host, port = h, p
	}
	n := &model.Node{
		Protocol: model.ProtoShadowsocks, Address: host, Port: port,
		Method: method, Password: password, Remark: frag,
	}
	if plugin := q.Get("plugin"); plugin != "" {
		name, opts, _ := strings.Cut(plugin, ";")
		n.SSPlugin = &model.SSPluginOptions{Name: name, Opts: opts}
	}
	return n, nil
}

func parseSOCKS(raw string) (*model.Node, error) {
	raw = strings.Replace(raw, "socks5://", "socks://", 1)
	body := strings.TrimPrefix(raw, "socks://")
	var frag string
	if i := strings.Index(body, "#"); i >= 0 {
		frag = decodeFragment(body[i+1:])
		body = body[:i]
	}
	var user, pass string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		ui := body[:at]
		if dec, err := model.DecodeBase64Any(ui); err == nil && strings.Contains(string(dec), ":") {
			user, pass, _ = strings.Cut(string(dec), ":")
		} else {
			user, pass, _ = strings.Cut(ui, ":")
		}
		body = body[at+1:]
	}
	h, p, err := splitHostPort(body)
	if err != nil {
		return nil, err
	}
	return &model.Node{
		Protocol: model.ProtoSOCKS, Address: h, Port: p,
		Username: user, Password: pass, Remark: frag,
	}, nil
}

func parseHTTP(raw string) (*model.Node, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(u.Port())
	n := &model.Node{Protocol: model.ProtoHTTP, Address: u.Hostname(), Port: p, Remark: decodeFragment(u.Fragment)}
	if u.User != nil {
		n.Username = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	if u.Scheme == "https" {
		n.Security.Type = model.SecTLS
	}
	return n, nil
}

func parseHysteria2(raw string) (*model.Node, error) {
	raw = strings.Replace(raw, "hy2://", "hysteria2://", 1)
	l, err := parseLink(raw, "hysteria2")
	if err != nil {
		return nil, err
	}
	pw, _ := url.QueryUnescape(l.user)
	n := &model.Node{
		Protocol: model.ProtoHysteria2, Address: l.host, Port: l.port,
		Password: pw, Remark: l.frag,
	}
	n.Security.Type = model.SecTLS
	n.Security.ServerName = l.query.Get("sni")
	if l.query.Get("insecure") == "1" || l.query.Get("insecure") == "true" {
		n.Security.AllowInsecure = true
	}
	h := &model.Hysteria2Options{}
	if o := l.query.Get("obfs"); o != "" {
		h.ObfsType = o
		h.ObfsPassword = l.query.Get("obfs-password")
	}
	if mp := l.query.Get("mport"); mp != "" {
		h.PortHopping = mp
	}
	if hi := l.query.Get("hop_interval"); hi != "" {
		h.PortHopInterval, _ = strconv.Atoi(hi)
	}
	if up := l.query.Get("up"); up != "" {
		h.UpMbps, _ = strconv.Atoi(up)
	}
	if down := l.query.Get("down"); down != "" {
		h.DownMbps, _ = strconv.Atoi(down)
	}
	n.Hysteria2 = h
	if pin := l.query.Get("pinSHA256"); pin != "" {
		n.Security.PinSHA256 = []string{pin}
	}
	return n, nil
}

func parseTUIC(raw string) (*model.Node, error) {
	l, err := parseLink(raw, "tuic")
	if err != nil {
		return nil, err
	}
	uuid, pw, _ := strings.Cut(l.user, ":")
	pw, _ = url.QueryUnescape(pw)
	n := &model.Node{
		Protocol: model.ProtoTUIC, Address: l.host, Port: l.port,
		UUID: uuid, Password: pw, Remark: l.frag,
	}
	n.Security.Type = model.SecTLS
	n.Security.ServerName = l.query.Get("sni")
	if a := l.query.Get("alpn"); a != "" {
		n.Security.ALPN = strings.Split(a, ",")
	}
	if l.query.Get("allow_insecure") == "1" {
		n.Security.AllowInsecure = true
	}
	n.TUIC = &model.TUICOptions{
		CongestionControl: l.query.Get("congestion_control"),
		UDPRelayMode:      l.query.Get("udp_relay_mode"),
	}
	return n, nil
}

func parseWireGuard(raw string) (*model.Node, error) {
	raw = strings.Replace(raw, "wg://", "wireguard://", 1)
	l, err := parseLink(raw, "wireguard")
	if err != nil {
		return nil, err
	}
	priv, _ := url.QueryUnescape(l.user)
	w := &model.WireGuardOptions{
		PrivateKey:   priv,
		PublicKey:    l.query.Get("publickey"),
		PreSharedKey: l.query.Get("presharedkey"),
	}
	if addr := l.query.Get("address"); addr != "" {
		w.LocalAddress = strings.Split(addr, ",")
	}
	if mtu := l.query.Get("mtu"); mtu != "" {
		w.MTU, _ = strconv.Atoi(mtu)
	}
	if res := l.query.Get("reserved"); res != "" {
		for _, p := range strings.Split(res, ",") {
			v, _ := strconv.Atoi(strings.TrimSpace(p))
			w.Reserved = append(w.Reserved, v)
		}
	}
	return &model.Node{
		Protocol: model.ProtoWireGuard, Address: l.host, Port: l.port,
		Remark: l.frag, WireGuard: w,
	}, nil
}

func parseBrook(raw string) (*model.Node, error) {
	body := strings.TrimPrefix(raw, "brook://")
	var frag string
	if i := strings.Index(body, "#"); i >= 0 {
		frag = decodeFragment(body[i+1:])
		body = body[:i]
	}
	mode, qs, _ := strings.Cut(body, "?")
	q, _ := url.ParseQuery(qs)

	// The parameter naming the server is called after the MODE, and only a plain
	// server carries a bare host:port. wsserver, wssserver and quicserver carry a
	// URL — scheme, host, port and, for the WebSocket modes, the path — and this
	// read `server` for all of them, so importing a real brook ws link failed
	// with "missing port in \"\"" while looking like a malformed link rather than
	// a parser that was not looking at the right field.
	host, port, path := "", 0, ""
	switch mode {
	case "wsserver", "wssserver", "quicserver":
		v := q.Get(mode)
		if v == "" {
			// Tolerate a link that used `server=` anyway: older panels emitted
			// that shape, and refusing it would lose configs on import for no
			// gain.
			v = q.Get("server")
		}
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			h, p, err := splitHostPort(u.Host)
			if err != nil {
				return nil, fmt.Errorf("brook: %w", err)
			}
			host, port, path = h, p, u.Path
		} else {
			h, p, err := splitHostPort(v)
			if err != nil {
				return nil, fmt.Errorf("brook: %w", err)
			}
			host, port = h, p
		}
	default:
		mode = "server"
		h, p, err := splitHostPort(q.Get("server"))
		if err != nil {
			return nil, fmt.Errorf("brook: %w", err)
		}
		host, port = h, p
	}

	return &model.Node{
		Protocol: model.ProtoBrook, Address: host, Port: port,
		Password: q.Get("password"), Remark: frag,
		// udpovertcp round-trips, so importing a link the panel exported (or one
		// brook itself generated) does not quietly drop the setting.
		Brook: &model.BrookOptions{
			Mode:       mode,
			Path:       path,
			UDPOverTCP: q.Get("udpovertcp") == "true",
		},
	}, nil
}

func parseSSH(raw string) (*model.Node, error) {
	l, err := parseLink(raw, "ssh")
	if err != nil {
		return nil, err
	}
	return &model.Node{
		Protocol: model.ProtoSSH, Address: l.host, Port: l.port, Remark: l.frag,
		SSH: &model.SSHOptions{User: l.user},
	}, nil
}

func parseForgeDNS(raw string) (*model.Node, error) {
	body := strings.TrimPrefix(raw, "forgedns://")
	var frag string
	if i := strings.Index(body, "#"); i >= 0 {
		frag = decodeFragment(body[i+1:])
		body = body[:i]
	}
	var q url.Values
	if i := strings.Index(body, "?"); i >= 0 {
		q, _ = url.ParseQuery(body[i+1:])
		body = body[:i]
	} else {
		q = url.Values{}
	}
	adapter, zone, ok := strings.Cut(body, "@")
	if !ok {
		return nil, fmt.Errorf("forgedns: expected adapter@zone")
	}
	return &model.Node{
		Protocol: model.ProtoForgeDNS, Address: zone, Port: 53, Remark: frag,
		ForgeDNS: &model.ForgeDNSOptions{
			Adapter: adapter, Zone: zone, Key: q.Get("key"),
			RRType: q.Get("rr"), NSHost: q.Get("ns"),
		},
	}, nil
}

// stub to keep base64 import used if a build tag prunes callers.
var _ = base64.StdEncoding
