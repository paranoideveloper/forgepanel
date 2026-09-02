// Clash.Meta (mihomo) export.
//
// Why this file exists as a hand-written mapping rather than a struct-tagged
// marshal: Clash.Meta's proxy schema is not a projection of the canonical model
// -- it is a different vocabulary for the same facts. The same canonical SNI is
// spelled "servername" for the VLESS/VMess family and "sni" for
// Trojan/Hysteria2/TUIC/AnyTLS; httpupgrade is spelled as ws plus a flag;
// REALITY lives in its own sub-map. Encoding those rules once, here, keeps
// every other exporter honest and keeps the translation auditable.
//
// Why the tiny YAML emitter at the bottom: ForgePanel ships subscriptions to
// untrusted clients and diffs them in golden tests, so the output must be
// byte-stable, and the dependency surface of a config exporter should stay at
// zero. gopkg.in/yaml.v3 is not in go.mod and is not worth adding for the small
// subset of YAML a Clash config needs (block maps, block sequences, scalars).
//
// Nodes that Clash.Meta genuinely cannot express (xhttp/mKCP/QUIC transports,
// SSH, Brook, ForgeDNS, bare ShadowTLS) are reported with ErrUnsupportedByClash
// so a subscription can skip them instead of shipping a config the client will
// refuse to load.

package export

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// ErrUnsupportedByClash reports that a canonical node has no faithful
// Clash.Meta representation. Callers building a subscription should skip such
// nodes; ClashYAML does exactly that.
var ErrUnsupportedByClash = errors.New("export/clash: not representable in Clash.Meta")

// ClashProxy renders the canonical node as a single Clash.Meta proxy mapping.
// The returned map contains only plain Go scalars, map[string]any and []any, so
// it round-trips through both the YAML emitter below and encoding/json.
func ClashProxy(n *model.Node) (map[string]any, error) {
	c := n.Clone()
	c.Normalize()

	p := map[string]any{
		"name":   clashName(c),
		"server": c.Address,
		"port":   c.Port,
	}

	switch c.Protocol {
	case model.ProtoVLESS:
		p["type"] = "vless"
		p["uuid"] = c.UUID
		p["udp"] = true
		if c.Flow != "" {
			p["flow"] = c.Flow
		}
		if err := clashTransport(c, p); err != nil {
			return nil, err
		}
		clashTLS(c, p, "servername", true)
		clashMux(c, p)

	case model.ProtoVMess:
		p["type"] = "vmess"
		p["uuid"] = c.UUID
		p["alterId"] = c.AlterID
		p["cipher"] = firstNonEmptyStr(c.Encryption, "auto")
		p["udp"] = true
		if err := clashTransport(c, p); err != nil {
			return nil, err
		}
		clashTLS(c, p, "servername", true)
		clashMux(c, p)

	case model.ProtoTrojan:
		p["type"] = "trojan"
		p["password"] = c.Password
		p["udp"] = true
		if c.Flow != "" {
			p["flow"] = c.Flow
		}
		if err := clashTransport(c, p); err != nil {
			return nil, err
		}
		// Trojan is TLS by definition in Clash.Meta: there is no "tls" key, and
		// the server name is spelled "sni".
		clashTLS(c, p, "sni", false)
		clashMux(c, p)

	case model.ProtoShadowsocks:
		p["type"] = "ss"
		p["cipher"] = c.Method
		p["password"] = c.Password
		p["udp"] = true
		clashSSPlugin(c, p)
		clashMux(c, p)

	case model.ProtoSOCKS:
		p["type"] = "socks5"
		p["udp"] = true
		if c.Username != "" {
			p["username"] = c.Username
		}
		if c.Password != "" {
			p["password"] = c.Password
		}
		clashTLS(c, p, "sni", true)

	case model.ProtoHTTP:
		p["type"] = "http"
		if c.Username != "" {
			p["username"] = c.Username
		}
		if c.Password != "" {
			p["password"] = c.Password
		}
		clashTLS(c, p, "sni", true)

	case model.ProtoHysteria2:
		p["type"] = "hysteria2"
		p["password"] = c.Password
		p["udp"] = true
		if h := c.Hysteria2; h != nil {
			// mihomo parses these as bandwidth strings ("30 Mbps"); a bare
			// integer would fail to unmarshal into its string field.
			if h.UpMbps > 0 {
				p["up"] = strconv.Itoa(h.UpMbps) + " Mbps"
			}
			if h.DownMbps > 0 {
				p["down"] = strconv.Itoa(h.DownMbps) + " Mbps"
			}
			if h.ObfsType != "" {
				p["obfs"] = h.ObfsType
				p["obfs-password"] = h.ObfsPassword
			}
			if h.PortHopping != "" {
				p["ports"] = h.PortHopping
			}
			if h.PortHopInterval > 0 {
				p["hop-interval"] = h.PortHopInterval
			}
		}
		clashTLS(c, p, "sni", false)

	case model.ProtoTUIC:
		p["type"] = "tuic"
		p["uuid"] = c.UUID
		p["password"] = c.Password
		p["udp"] = true
		if t := c.TUIC; t != nil {
			if t.CongestionControl != "" {
				p["congestion-controller"] = t.CongestionControl
			}
			if t.UDPRelayMode != "" {
				p["udp-relay-mode"] = t.UDPRelayMode
			}
			if t.ZeroRTTHandshake {
				p["reduce-rtt"] = true
			}
			if t.HeartbeatSeconds > 0 {
				// mihomo's heartbeat-interval is milliseconds.
				p["heartbeat-interval"] = t.HeartbeatSeconds * 1000
			}
			if t.DisableSNI {
				p["disable-sni"] = true
			}
		}
		clashTLS(c, p, "sni", false)

	case model.ProtoAnyTLS:
		p["type"] = "anytls"
		p["password"] = c.Password
		p["udp"] = true
		if a := c.AnyTLS; a != nil {
			if a.IdleSessionCheckInterval > 0 {
				p["idle-session-check-interval"] = a.IdleSessionCheckInterval
			}
			if a.IdleSessionTimeout > 0 {
				p["idle-session-timeout"] = a.IdleSessionTimeout
			}
			if a.MinIdleSessions > 0 {
				p["min-idle-session"] = a.MinIdleSessions
			}
		}
		clashTLS(c, p, "sni", false)

	case model.ProtoWireGuard:
		w := c.WireGuard
		if w == nil {
			return nil, fmt.Errorf("%w: wireguard node without keys", ErrUnsupportedByClash)
		}
		p["type"] = "wireguard"
		p["private-key"] = w.PrivateKey
		p["public-key"] = w.PublicKey
		p["udp"] = true
		if w.PreSharedKey != "" {
			p["pre-shared-key"] = w.PreSharedKey
		}
		// mihomo splits the tunnel address into ip / ipv6.
		for _, addr := range w.LocalAddress {
			if strings.Contains(addr, ":") {
				p["ipv6"] = addr
			} else {
				p["ip"] = addr
			}
		}
		if len(w.AllowedIPs) > 0 {
			p["allowed-ips"] = anySlice(w.AllowedIPs)
		}
		if w.MTU > 0 {
			p["mtu"] = w.MTU
		}
		if w.Keepalive > 0 {
			p["persistent-keepalive"] = w.Keepalive
		}
		if len(w.Reserved) == 3 {
			p["reserved"] = []any{w.Reserved[0], w.Reserved[1], w.Reserved[2]}
		}

	case model.ProtoShadowTLS:
		// Clash.Meta models ShadowTLS as a Shadowsocks plugin, never as a proxy
		// of its own -- same reasoning as URI().
		return nil, fmt.Errorf("%w: shadowtls; export the wrapped shadowsocks node", ErrUnsupportedByClash)

	case model.ProtoSSH, model.ProtoBrook, model.ProtoForgeDNS:
		return nil, fmt.Errorf("%w: protocol %q", ErrUnsupportedByClash, c.Protocol)

	default:
		return nil, fmt.Errorf("export/clash: unsupported protocol %q", c.Protocol)
	}

	return p, nil
}

// ClashYAML renders a whole subscription: every representable node under
// "proxies", a single "PROXY" select group listing them, and a catch-all rule.
// Nodes Clash.Meta cannot express are skipped rather than failing the document,
// because one exotic node must not cost a user their entire subscription.
// ClashProxySelector is the name of the select proxy-group every generated Clash
// document routes to. Exported so routing presets can target it in their rules.
const ClashProxySelector = "PROXY"

// ClashAutoSelect is the name of the latency-tested group. It is the FIRST
// member of the selector and the selector's default, so a subscription works
// without the user picking anything — which is the whole point: most people
// never open the group list, and the one node the selector happened to list
// first is not the one that is up.
const ClashAutoSelect = "Best Ping"

// AutoSelect configures the latency-tested group.
type AutoSelect struct {
	// Interval in seconds between tests. Zero takes DefaultURLTestInterval.
	Interval int
	// URL fetched to measure. Zero-value takes DefaultURLTestURL.
	URL string
	// Tolerance in ms: how much better a node must be before the group switches.
	// Without it a group flaps between two nodes a few milliseconds apart, and
	// every switch drops the connections on the old one.
	Tolerance int
}

const (
	DefaultURLTestInterval = 60
	// A 204 endpoint, because it is the smallest possible successful response
	// and every captive-portal detector already uses it.
	DefaultURLTestURL   = "http://www.gstatic.com/generate_204"
	DefaultURLTolerance = 50
)

func (a AutoSelect) withDefaults() AutoSelect {
	if a.Interval <= 0 {
		a.Interval = DefaultURLTestInterval
	}
	if strings.TrimSpace(a.URL) == "" {
		a.URL = DefaultURLTestURL
	}
	if a.Tolerance <= 0 {
		a.Tolerance = DefaultURLTolerance
	}
	return a
}

func ClashYAML(nodes []*model.Node) (string, error) {
	return ClashYAMLAuto(nodes, AutoSelect{})
}

// ClashYAMLAuto is ClashYAML with the latency test configured.
func ClashYAMLAuto(nodes []*model.Node, auto AutoSelect) (string, error) {
	proxies := make([]any, 0, len(nodes))
	names := make([]any, 0, len(nodes))
	seen := make(map[string]int, len(nodes))

	for _, n := range nodes {
		if n == nil {
			continue
		}
		p, err := ClashProxy(n)
		if err != nil {
			if errors.Is(err, ErrUnsupportedByClash) {
				continue
			}
			return "", err
		}
		// Clash rejects duplicate proxy names, and remarks are user supplied.
		name := uniqueClashName(p["name"].(string), seen)
		p["name"] = name
		proxies = append(proxies, p)
		names = append(names, name)
	}
	if len(names) == 0 {
		// An empty select group is a load error in Clash; DIRECT always exists.
		names = append(names, "DIRECT")
	}

	auto = auto.withDefaults()
	groups := []any{}
	// The selector lists the auto group first and defaults to it, so a client
	// that has never been touched picks the fastest node rather than whichever
	// one happened to be generated first.
	selectorMembers := names
	if len(nodes) > 1 && len(names) > 1 {
		groups = append(groups, map[string]any{
			"name":      ClashAutoSelect,
			"type":      "url-test",
			"proxies":   names,
			"url":       auto.URL,
			"interval":  auto.Interval,
			"tolerance": auto.Tolerance,
		})
		selectorMembers = append([]any{ClashAutoSelect}, names...)
	}
	groups = append(groups, map[string]any{
		"name":    ClashProxySelector,
		"type":    "select",
		"proxies": selectorMembers,
	})

	doc := map[string]any{
		"proxies":      proxies,
		"proxy-groups": groups,
		"rules":        []any{"MATCH," + ClashProxySelector},
	}

	var b strings.Builder
	yamlMap(&b, doc, 0, false)
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// canonical -> Clash.Meta field mapping
// ---------------------------------------------------------------------------

// clashName derives a stable display name; Clash uses it as the proxy's key.
func clashName(n *model.Node) string {
	if s := strings.TrimSpace(n.Remark); s != "" {
		return s
	}
	if s := strings.TrimSpace(n.Tag); s != "" {
		return s
	}
	return string(n.Protocol) + "-" + hostPort(n.Address, n.Port)
}

// uniqueClashName suffixes collisions deterministically.
func uniqueClashName(base string, seen map[string]int) string {
	if _, taken := seen[base]; !taken {
		seen[base] = 1
		return base
	}
	for i := seen[base] + 1; ; i++ {
		cand := base + " #" + strconv.Itoa(i)
		if _, taken := seen[cand]; !taken {
			seen[base] = i
			seen[cand] = 1
			return cand
		}
	}
}

// clashTransport maps the canonical transport onto Clash.Meta's network plus
// its per-network *-opts block. Only the VLESS/VMess/Trojan family reaches
// here; Shadowsocks carries its transport in a SIP003 plugin instead.
func clashTransport(n *model.Node, p map[string]any) error {
	t := n.Transport
	switch t.Network {
	case model.NetTCP:
		// Plain TCP is Clash's default and needs no "network" key; only the
		// HTTP-obfuscated variant does.
		if t.HeaderObfs != nil && t.HeaderObfs.Type == "http" {
			p["network"] = "http"
			opts := map[string]any{
				"method": "GET",
				"path":   []any{firstNonEmptyStr(t.Path, "/")},
			}
			if t.Host != "" {
				opts["headers"] = map[string]any{"Host": []any{t.Host}}
			}
			p["http-opts"] = opts
		}

	case model.NetWS, model.NetHTTPUpgrade:
		// Clash.Meta has no separate httpupgrade network: it is ws plus a flag
		// that suppresses the WebSocket framing.
		p["network"] = "ws"
		ws := map[string]any{"path": firstNonEmptyStr(t.Path, "/")}
		headers := map[string]any{}
		if t.Host != "" {
			headers["Host"] = t.Host
		}
		for k, v := range t.Headers {
			headers[k] = v
		}
		if len(headers) > 0 {
			ws["headers"] = headers
		}
		if t.EarlyData > 0 {
			ws["max-early-data"] = t.EarlyData
			ws["early-data-header-name"] = firstNonEmptyStr(t.EDHeader, "Sec-WebSocket-Protocol")
		}
		if t.Network == model.NetHTTPUpgrade {
			ws["v2ray-http-upgrade"] = true
			ws["v2ray-http-upgrade-fast-open"] = true
		}
		p["ws-opts"] = ws

	case model.NetGRPC:
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": t.ServiceName}

	case model.NetH2:
		p["network"] = "h2"
		h2 := map[string]any{"path": firstNonEmptyStr(t.Path, "/")}
		if t.Host != "" {
			h2["host"] = []any{t.Host}
		}
		p["h2-opts"] = h2

	default:
		// xhttp, mKCP and QUIC transports have no Clash.Meta equivalent.
		return fmt.Errorf("%w: transport %q", ErrUnsupportedByClash, t.Network)
	}
	return nil
}

// clashTLS writes the TLS layer. sniKey is "servername" for the VLESS/VMess
// family and "sni" everywhere else, matching mihomo's schema. emitFlag is false
// for protocols that are TLS by definition (Trojan, Hysteria2, TUIC, AnyTLS)
// and therefore have no "tls" key at all.
func clashTLS(n *model.Node, p map[string]any, sniKey string, emitFlag bool) {
	s := n.Security
	if s.Type == model.SecNone {
		return
	}
	if emitFlag {
		p["tls"] = true
	}
	// SNI() falls back to the address; emitting a literal IP as the server name
	// is noise at best and a handshake failure at worst, so skip that case.
	if sni := n.SNI(); sni != "" && sni != n.Address {
		p[sniKey] = sni
	}
	if len(s.ALPN) > 0 {
		p["alpn"] = anySlice(s.ALPN)
	}
	if s.AllowInsecure {
		p["skip-cert-verify"] = true
	}
	if len(s.PinSHA256) > 0 {
		// mihomo's "fingerprint" is the pinned certificate hash, not uTLS.
		p["fingerprint"] = s.PinSHA256[0]
	}
	switch s.Type {
	case model.SecTLS:
		if s.Fingerprint != "" {
			p["client-fingerprint"] = s.Fingerprint
		}
		if e := s.ECH; e != nil && (e.Enabled || e.ConfigList != "") {
			ech := map[string]any{"enable": true}
			if e.ConfigList != "" {
				ech["config"] = e.ConfigList
			}
			p["ech-opts"] = ech
		}
	case model.SecReality:
		// REALITY always needs a uTLS profile; chrome is the interoperable
		// default, same choice as the share-link exporter.
		p["client-fingerprint"] = firstNonEmptyStr(s.Fingerprint, "chrome")
		ro := map[string]any{}
		if r := s.Reality; r != nil {
			ro["public-key"] = r.PublicKey
			sid := r.ShortID
			if sid == "" && len(r.ShortIDs) > 0 {
				sid = r.ShortIDs[0]
			}
			if sid != "" {
				ro["short-id"] = sid
			}
		}
		p["reality-opts"] = ro
	}
}

// clashSSPlugin maps a SIP003 plugin onto Clash's plugin/plugin-opts pair.
func clashSSPlugin(n *model.Node, p map[string]any) {
	pl := n.SSPlugin
	if pl == nil || pl.Name == "" {
		return
	}
	name := pl.Name
	switch name {
	case "obfs-local", "simple-obfs":
		name = "obfs" // Clash's spelling of the simple-obfs plugin
	}
	p["plugin"] = name
	if opts := parsePluginOpts(pl.Opts); len(opts) > 0 {
		p["plugin-opts"] = opts
	}
}

// parsePluginOpts turns a SIP003 "k=v;k=v" option string into a mapping. A bare
// key becomes true, which is how v2ray-plugin spells "tls".
func parsePluginOpts(s string) map[string]any {
	out := map[string]any{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if k, v, found := strings.Cut(part, "="); found {
			out[strings.TrimSpace(k)] = v
		} else {
			out[part] = true
		}
	}
	return out
}

// clashMux emits the sing-box style multiplex block mihomo calls "smux".
func clashMux(n *model.Node, p map[string]any) {
	m := n.Multiplex
	if m == nil || !m.Enabled {
		return
	}
	smux := map[string]any{
		"enabled":  true,
		"protocol": firstNonEmptyStr(m.Protocol, "smux"),
	}
	if m.MaxConns > 0 {
		smux["max-connections"] = m.MaxConns
	}
	if m.MinStreams > 0 {
		smux["min-streams"] = m.MinStreams
	}
	if m.MaxStreams > 0 {
		smux["max-streams"] = m.MaxStreams
	}
	if m.Padding {
		smux["padding"] = true
	}
	p["smux"] = smux
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func anySlice(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// minimal deterministic YAML emitter
// ---------------------------------------------------------------------------

// yamlPreferredOrder pins a few keys to the front of a mapping so a generated
// subscription reads like a hand-written one. Every other key is sorted, which
// is what makes the output byte-stable across runs and Go versions.
var yamlPreferredOrder = map[string]int{
	"name":   -5,
	"type":   -4,
	"server": -3,
	"port":   -2,
}

func yamlRank(k string) int {
	if r, ok := yamlPreferredOrder[k]; ok {
		return r
	}
	return 0
}

func yamlKeys(m map[string]any) []string {
	ks := SortedKeys(m)
	sort.SliceStable(ks, func(i, j int) bool { return yamlRank(ks[i]) < yamlRank(ks[j]) })
	return ks
}

const yamlIndentUnit = "  "

func yamlPad(depth int) string { return strings.Repeat(yamlIndentUnit, depth) }

// yamlMap writes a block mapping. When dashed is true the caller has already
// written the "- " marker for the first key, so its indentation is suppressed.
func yamlMap(b *strings.Builder, m map[string]any, depth int, dashed bool) {
	for i, k := range yamlKeys(m) {
		if !dashed || i > 0 {
			b.WriteString(yamlPad(depth))
		}
		b.WriteString(yamlScalar(k))
		b.WriteByte(':')
		yamlValue(b, m[k], depth)
	}
}

// yamlSeq writes a block sequence at the given depth.
func yamlSeq(b *strings.Builder, s []any, depth int) {
	for _, item := range s {
		b.WriteString(yamlPad(depth))
		b.WriteByte('-')
		if sub, ok := item.(map[string]any); ok && len(sub) > 0 {
			b.WriteByte(' ')
			yamlMap(b, sub, depth+1, true)
			continue
		}
		yamlValue(b, item, depth)
	}
}

// yamlValue writes a value whose "key:" or "-" marker is already emitted:
// scalars stay on the same line, collections start on the next one.
func yamlValue(b *strings.Builder, v any, depth int) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			b.WriteString(" {}\n")
			return
		}
		b.WriteByte('\n')
		yamlMap(b, t, depth+1, false)
	case []any:
		if len(t) == 0 {
			b.WriteString(" []\n")
			return
		}
		b.WriteByte('\n')
		yamlSeq(b, t, depth+1)
	case []string:
		yamlValue(b, anySlice(t), depth)
	default:
		b.WriteByte(' ')
		b.WriteString(yamlScalar(v))
		b.WriteByte('\n')
	}
}

// yamlScalar renders a scalar, quoting whenever a plain scalar would be
// ambiguous (empty, numeric-looking, a YAML boolean word, or containing an
// indicator character).
func yamlScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case string:
		if yamlNeedsQuote(t) {
			return yamlQuote(t)
		}
		return t
	default:
		return yamlQuote(fmt.Sprint(v))
	}
}

func yamlNeedsQuote(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return true
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~", "y", "n":
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	if strings.ContainsAny(s, ":#,[]{}&*!|>'\"%@`\\\n\r\t") {
		return true
	}
	switch s[0] {
	case '-', '?':
		return true
	}
	return false
}

// yamlQuote emits a YAML double-quoted scalar. It deliberately does not use
// strconv.Quote: Go's \xNN escapes are not valid YAML.
func yamlQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
