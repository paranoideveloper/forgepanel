package api

import (
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// Field describes one form input. Key is a dot-path into the canonical node JSON
// (e.g. "uuid", "security.reality.dest", "hysteria2.obfs_type") so the frontend
// can render every option a protocol supports and build the node generically.
type Field struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`              // text, number, bool, textarea, select, iselect (int select), csv ([]string), csvint ([]int), kv (map[string]string), lines ([]string, one per line), lines ([]string, one per line)
	Options []string `json:"options,omitempty"` // for select
	Default any      `json:"default,omitempty"`
	Keygen  string   `json:"keygen,omitempty"` // reality|uuid|shortid|ss2022|wireguard|password
	Ph      string   `json:"placeholder,omitempty"`
	Help    string   `json:"help,omitempty"`
}

// ProtoSchema is the complete form schema for one protocol.
type ProtoSchema struct {
	Proto      string   `json:"proto"`
	Label      string   `json:"label"`
	Engine     string   `json:"engine"`
	Fields     []Field  `json:"fields"`     // credentials + protocol options
	Transports []string `json:"transports"` // empty => no transport layer
	Securities []string `json:"securities"`
	// Chainable reports whether this protocol's engine can honour an upstream
	// hop. The form uses it to decide whether to offer the chain control at all:
	// showing it for a protocol whose builder ignores it is how an operator ends
	// up believing traffic is relayed when it leaves the machine directly.
	Chainable bool `json:"chainable"`
	// ServesInbound reports whether the panel can LISTEN on this protocol, as
	// opposed to only dialling it as an outbound hop. The form must not offer a
	// protocol that no core can serve: the resulting inbound is accepted, fails
	// to render on every reload, and sits in the database serving nobody.
	ServesInbound bool `json:"serves_inbound"`
}

// handleSchema returns the full field schema so the UI can render every option
// of every protocol — the single source of truth for "what can be created".
func (s *Server) handleSchema(c *gin.Context) {
	fps := model.ValidFingerprints()
	// Only transports Xray 26 actually supports. h2/quic/mKCP were removed and
	// produce an unstartable config (verified against the running core), so they
	// are not offered — xhttp replaces h2/quic for the CDN/HTTP use cases.
	transports := offeredTransports()
	securities := []string{"none", "tls", "reality"}

	c.JSON(200, gin.H{
		"protocols":    protocolSchemas(transports, securities),
		"common":       commonFields(),
		"transports":   transportFields(),
		"securities":   securityFields(fps),
		"fingerprints": fps,
	})
}

// commonFields returns node-level fields that belong to no single protocol,
// transport or security layer.
//
// Egress lived in the model, in the builder and in the API for a whole release
// with no control anywhere in the panel: a multi-hop chain could only be set by
// hand against the API, and — worse — opening such an inbound in the form and
// pressing Update silently erased it, because the form rebuilt the node from
// fields it knew about and the chain was not one of them.
func commonFields() []Field {
	return []Field{
		// A chain is not csv: a share link's query string can contain commas, so
		// splitting on them would cut a hop in half. One hop per line.
		{Key: "egress", Label: "Relay chain (one hop per line)", Type: "lines",
			Ph: "vless://…  (dialled first)\ntrojan://…\nss://…  (the exit)",
			Help: "paste one share link per hop, in order. This server dials the FIRST line; " +
				"each later hop is reached THROUGH the one above it; the last line is where " +
				"traffic reaches the internet. One line = a single relay. Empty = exit directly. " +
				"A hop that cannot be parsed stops the inbound rather than letting it exit directly."},
	}
}

func protocolSchemas(transports, securities []string) []ProtoSchema {
	out := protocolSchemaList(transports, securities)
	// Chainability comes from the one authority that decides it, so a protocol
	// can never advertise a chain the builder would ignore. Servability is
	// derived the same way, for the same reason: SSH was offered in this list
	// while no core could serve it as an inbound, so the form let an operator
	// build one that failed to render on every reload.
	for i := range out {
		p := model.Protocol(out[i].Proto)
		out[i].Chainable = model.SupportsEgress(p)
		out[i].ServesInbound = render.ServesInbound(p)
	}
	return out
}

func protocolSchemaList(transports, securities []string) []ProtoSchema {
	ss := []string{model.SS2022AES256, model.SS2022AES128, model.SS2022ChaCha20,
		model.SSAES256GCM, model.SSAES128GCM, model.SSChaCha20Poly, model.SSXChaCha20Poly, model.SSNone}
	return []ProtoSchema{
		{Proto: "vless", Label: "VLESS", Engine: "xray", Transports: transports, Securities: securities, Fields: []Field{
			{Key: "uuid", Label: "UUID", Type: "text", Keygen: "uuid", Help: "auto-generated if empty"},
			{Key: "flow", Label: "Flow", Type: "select", Options: []string{"", "xtls-rprx-vision"}, Help: "Vision requires TLS/REALITY over TCP"},
		}},
		{Proto: "vmess", Label: "VMess", Engine: "xray", Transports: transports, Securities: securities, Fields: []Field{
			{Key: "uuid", Label: "UUID", Type: "text", Keygen: "uuid"},
			{Key: "encryption", Label: "Security", Type: "select", Options: []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}, Default: "auto"},
		}},
		{Proto: "trojan", Label: "Trojan", Engine: "xray", Transports: transports, Securities: []string{"tls", "reality", "none"}, Fields: []Field{
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
		}},
		{Proto: "shadowsocks", Label: "Shadowsocks", Engine: "xray", Fields: []Field{
			{Key: "method", Label: "Method", Type: "select", Options: ss, Default: model.SS2022AES256},
			{Key: "password", Label: "Password / PSK", Type: "text", Keygen: "password", Help: "2022 methods use a base64 PSK of the exact key length"},
			{Key: "ss_plugin.name", Label: "Plugin", Type: "select", Options: []string{"", "v2ray-plugin", "obfs-local", "shadow-tls"}},
			{Key: "ss_plugin.opts", Label: "Plugin options", Type: "text", Ph: "server;tls;host=example.com"},
		}},
		{Proto: "socks", Label: "SOCKS5", Engine: "xray", Fields: []Field{
			{Key: "username", Label: "Username", Type: "text", Help: "leave empty for no auth"},
			{Key: "password", Label: "Password", Type: "text"},
		}},
		{Proto: "http", Label: "HTTP", Engine: "xray", Securities: []string{"none", "tls"}, Fields: []Field{
			{Key: "username", Label: "Username", Type: "text"},
			{Key: "password", Label: "Password", Type: "text"},
		}},
		{Proto: "hysteria2", Label: "Hysteria2", Engine: "sing-box", Securities: []string{"tls"}, Fields: []Field{
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "hysteria2.up_mbps", Label: "Up (Mbps)", Type: "number", Default: 100},
			{Key: "hysteria2.down_mbps", Label: "Down (Mbps)", Type: "number", Default: 100},
			{Key: "hysteria2.obfs_type", Label: "Obfs", Type: "select", Options: []string{"", "salamander"}},
			{Key: "hysteria2.obfs_password", Label: "Obfs password", Type: "text"},
			{Key: "hysteria2.ignore_client_bandwidth", Label: "Ignore client bandwidth", Type: "bool"},
			{Key: "hysteria2.port_hopping", Label: "Port hopping range", Type: "text", Ph: "20000-50000"},
			{Key: "hysteria2.port_hop_interval", Label: "Hop interval (s)", Type: "number", Default: 30},
			{Key: "hysteria2.hop_interval_max", Label: "Hop interval max (s, randomized)", Type: "number"},
			{Key: "hysteria2.masquerade.type", Label: "Masquerade mode", Type: "select", Options: []string{"", "proxy", "file", "string"}},
			{Key: "hysteria2.masquerade.url", Label: "Masquerade: proxy URL", Type: "text", Ph: "https://example.com"},
			{Key: "hysteria2.masquerade.rewrite_host", Label: "Masquerade: rewrite Host", Type: "bool"},
			{Key: "hysteria2.masquerade.directory", Label: "Masquerade: file directory", Type: "text", Ph: "/var/www"},
			{Key: "hysteria2.masquerade.status_code", Label: "Masquerade: string status code", Type: "number"},
			{Key: "hysteria2.masquerade.content", Label: "Masquerade: string content", Type: "text"},
			{Key: "hysteria2.masquerade.headers", Label: "Masquerade: response headers", Type: "kv",
				Ph: "Server: nginx", Help: "one Name: value per line, sent with the masquerade response"},
		}},
		{Proto: "tuic", Label: "TUIC", Engine: "sing-box", Securities: []string{"tls"}, Fields: []Field{
			{Key: "uuid", Label: "UUID", Type: "text", Keygen: "uuid"},
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "tuic.congestion_control", Label: "Congestion", Type: "select", Options: []string{"bbr", "cubic", "new_reno"}, Default: "bbr"},
			{Key: "tuic.udp_relay_mode", Label: "UDP relay", Type: "select", Options: []string{"native", "quic"}, Default: "native"},
			{Key: "tuic.zero_rtt_handshake", Label: "Zero-RTT", Type: "bool"},
			{Key: "tuic.heartbeat", Label: "Heartbeat (s)", Type: "number",
				Help: "keeps the QUIC connection alive through NAT that drops idle flows"},
			{Key: "tuic.disable_sni", Label: "Disable SNI", Type: "bool",
				Help: "omit the server name from the TLS handshake"},
		}},
		{Proto: "anytls", Label: "AnyTLS", Engine: "sing-box", Securities: []string{"tls"}, Fields: []Field{
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "anytls.idle_session_timeout", Label: "Idle timeout (s)", Type: "number"},
			{Key: "anytls.idle_session_check_interval", Label: "Idle check interval (s)", Type: "number"},
			{Key: "anytls.min_idle_sessions", Label: "Minimum idle sessions", Type: "number",
				Help: "sessions kept open so a new request does not pay a handshake"},
			{Key: "anytls.padding_scheme", Label: "Padding scheme (one rule per line)", Type: "lines",
				Ph: "stop=8\n0=30-30\n1=100-400", Help: "must be IDENTICAL on the client, or the two disagree on frame sizes"},
		}},
		{Proto: "shadowtls", Label: "ShadowTLS", Engine: "sing-box", Fields: []Field{
			{Key: "shadowtls.version", Label: "Version", Type: "iselect", Options: []string{"3", "2", "1"}, Default: 3},
			{Key: "shadowtls.password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "shadowtls.handshake_host", Label: "Handshake host", Type: "text", Ph: "www.apple.com", Default: "www.apple.com"},
			{Key: "shadowtls.handshake_port", Label: "Handshake port", Type: "number", Default: 443},
			{Key: "shadowtls.strict_mode", Label: "Strict mode (v3)", Type: "bool",
				Help: "v3 only: reject clients that do not prove they know the password. Ignored on v1/v2."},
		}},
		{Proto: "wireguard", Label: "WireGuard", Engine: "xray", Fields: []Field{
			{Key: "wireguard.private_key", Label: "Private key", Type: "text", Keygen: "wireguard"},
			{Key: "wireguard.public_key", Label: "Peer public key", Type: "text"},
			{Key: "wireguard.server_address", Label: "Server tunnel address", Type: "csv", Ph: "10.66.66.1/24",
				Help: "this box's address inside the tunnel. The panel allocates one if left empty."},
			{Key: "wireguard.allowed_ips", Label: "Client AllowedIPs", Type: "csv", Ph: "0.0.0.0/0, ::/0",
				Help: "what the CLIENT routes through the tunnel. 0.0.0.0/0, ::/0 sends everything."},
			{Key: "wireguard.pre_shared_key", Label: "Pre-shared key", Type: "text",
				Help: "optional extra symmetric key; must match on both ends"},
			{Key: "wireguard.persistent_keepalive", Label: "Persistent keepalive (s)", Type: "number", Default: 25,
				Help: "0 = off. Needed behind NAT that forgets the flow."},
			{Key: "wireguard.mtu", Label: "MTU", Type: "number", Default: 1420},
			{Key: "wireguard.workers", Label: "Workers", Type: "number",
				Help: "sing-box endpoint worker count; 0 = one per CPU"},
			{Key: "wireguard.reserved", Label: "Reserved (WARP)", Type: "csvint", Ph: "0,0,0"},
		}},
		// AmneziaWG runs in KERNEL mode (amneziawg module + awg-quick). Keys and
		// tunnel addresses are auto-provisioned; the fields below are the shared
		// obfuscation parameters (identical on client and server).
		{Proto: "amneziawg", Label: "AmneziaWG (kernel)", Engine: "amneziawg", Fields: []Field{
			{Key: "amneziawg.private_key", Label: "Server private key (auto)", Type: "text", Keygen: "wireguard"},
			{Key: "amneziawg.public_key", Label: "Peer public key (auto)", Type: "text"},
			{Key: "amneziawg.server_address", Label: "Server tunnel address", Type: "csv", Ph: "10.67.67.1/24",
				Help: "this box's address inside the tunnel. The panel allocates one if left empty."},
			{Key: "amneziawg.allowed_ips", Label: "Client AllowedIPs", Type: "csv", Ph: "0.0.0.0/0, ::/0"},
			{Key: "amneziawg.pre_shared_key", Label: "Pre-shared key", Type: "text",
				Help: "optional extra symmetric key; must match on both ends"},
			{Key: "amneziawg.persistent_keepalive", Label: "Persistent keepalive (s)", Type: "number", Default: 25},
			{Key: "amneziawg.mtu", Label: "MTU", Type: "number", Default: 1420},
			{Key: "amneziawg.jc", Label: "Jc (junk packet count)", Type: "number", Default: 8},
			{Key: "amneziawg.jmin", Label: "Jmin (junk min size)", Type: "number", Default: 50},
			{Key: "amneziawg.jmax", Label: "Jmax (junk max size)", Type: "number", Default: 1000},
			{Key: "amneziawg.s1", Label: "S1 (init junk)", Type: "number", Default: 86},
			{Key: "amneziawg.s2", Label: "S2 (response junk)", Type: "number", Default: 574},
			{Key: "amneziawg.h1", Label: "H1 (header magic)", Type: "number", Default: 1234567},
			{Key: "amneziawg.h2", Label: "H2 (header magic)", Type: "number", Default: 2345678},
			{Key: "amneziawg.h3", Label: "H3 (header magic)", Type: "number", Default: 3456789},
			{Key: "amneziawg.h4", Label: "H4 (header magic)", Type: "number", Default: 4567890},
		}},
		// NOTE: SSH is intentionally NOT a creatable inbound. sing-box implements
		// SSH only as an OUTBOUND (routing THROUGH an SSH server); there is no SSH
		// inbound/server in sing-box (that role belongs to sshd). SSH stays in the
		// model for outbound/import/export use, just not in the create-inbound form.
		{Proto: "brook", Label: "Brook", Engine: "brook", Fields: []Field{
			{Key: "brook.mode", Label: "Mode", Type: "select", Options: []string{"server", "wsserver", "wssserver", "quicserver"}, Default: "server", Help: "server=raw TCP/UDP; ws=WebSocket; wss=WebSocket+TLS; quic=QUIC"},
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "brook.path", Label: "Path (ws/wss)", Type: "text", Default: "/ws"},
			{Key: "brook.udp_over_tcp", Label: "UDP over TCP", Type: "bool",
				Help: "carry UDP inside the TCP stream, for networks that drop or throttle UDP"},
		}},
	}
}

// transportFields returns the extra fields each transport needs.
func transportFields() map[string][]Field {
	return map[string][]Field{
		// TCP is not "no transport" — it is the one that carries Xray's HTTP
		// header camouflage, and this map entry was empty, so the whole feature
		// was reachable only by hand-editing the node through the API even
		// though the renderer, both share-link exporters and the Clash exporter
		// have carried it all along.
		//
		// Measured against Xray 26.2.6 with a real client and server rather than
		// reasoned about: the server validates ONLY the path. A client whose
		// path differs cannot connect at all; a client whose Host header or
		// request method differ connects fine. That is why Path says it must
		// match and Host does not.
		"tcp": {
			{Key: "transport.header.type", Label: "Header camouflage", Type: "select",
				Options: []string{"", "none", "http"},
				Help:    "wrap the stream in a fake HTTP exchange. Empty or \"none\" sends raw TCP."},
			{Key: "transport.path", Label: "Camouflage path", Type: "text", Ph: "/",
				Help: "the path in the fake request. The core CHECKS this: a client using a different path cannot connect."},
			{Key: "transport.host", Label: "Camouflage Host", Type: "text", Ph: "www.example.com",
				Help: "the Host header in the fake request. Not checked by the server; it shapes what a DPI box sees and is carried in the share link."},
		},
		"ws": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/", Ph: "/ws"},
			{Key: "transport.host", Label: "Host", Type: "text"},
			{Key: "transport.early_data", Label: "Max early data", Type: "number", Help: "0 = off; enables 0-RTT early data"},
			{Key: "transport.ed_header", Label: "Early-data header", Type: "text", Ph: "Sec-WebSocket-Protocol"},
		},
		"httpupgrade": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/"},
			{Key: "transport.host", Label: "Host", Type: "text"},
		},
		"grpc": {
			{Key: "transport.service_name", Label: "Service name", Type: "text", Ph: "grpcsvc"},
			{Key: "transport.multi_mode", Label: "Multi mode", Type: "bool"},
			{Key: "transport.idle_timeout", Label: "Idle timeout (s)", Type: "number", Help: "send a health ping after this many idle seconds"},
			{Key: "transport.health_check_timeout", Label: "Health-check timeout (s)", Type: "number", Help: "how long to wait for the health ping response"},
			{Key: "transport.initial_windows", Label: "Initial windows size", Type: "number"},
			{Key: "transport.permit_without_stream", Label: "Permit without stream", Type: "bool"},
		},
		// XHTTP is the one transport an operator genuinely tunes per deployment,
		// and for a long time the form exposed FOUR of its knobs while the model
		// carried the full set. Everything else — the padding shape, session and
		// sequence carriage, uplink shaping, the sc* flow-control limits, xmux
		// and the whole split download leg — could be set through the API and
		// through an imported share link, but never seen or changed in the panel
		// that owns the inbound. The options come from the model's own enum
		// tables so this list cannot drift from what the core accepts.
		"xhttp": xhttpFields(),
	}
}

// offeredTransports is the single list of transports the form may offer.
//
// It used to exist twice: handleSchema hardcoded tcp/ws/grpc/httpupgrade/xhttp,
// while transportFields also shipped field definitions for h2, kcp and quic —
// transports model.Validate rejects outright, so anything built from them was a
// guaranteed 400. Two lists that must agree and no test that they do is how a
// payload ends up advertising options the same server refuses.
func offeredTransports() []string {
	return []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
}

// xhttpFields returns the complete XHTTP surface.
//
// Grouped in the order an operator reasons about them: where it listens, how it
// is shaped, where the session rides, how the uplink behaves, connection reuse,
// and finally the separate download leg.
func xhttpFields() []Field {
	// Optional enums get a leading "" so the form can express "unset". The core
	// treats an empty value as its own default; offering only real values would
	// make a field impossible to clear once set.
	opt := func(vals []string) []string { return append([]string{""}, vals...) }

	f := []Field{
		{Key: "transport.path", Label: "Path", Type: "text", Default: "/"},
		{Key: "transport.host", Label: "Host", Type: "text"},
		{Key: "transport.headers", Label: "Extra headers", Type: "kv",
			Ph: "X-Forwarded-Proto: https", Help: "one Name: value per line"},
		{Key: "transport.xhttp_mode", Label: "Mode", Type: "select", Options: model.AllXHTTPModes(), Default: "auto",
			Help: "packet-up survives CDNs that buffer; stream-one is lowest latency"},
		{Key: "transport.server_max_header_bytes", Label: "Max request header bytes", Type: "number",
			Help: "server-side cap on inbound headers; 0 = core default"},

		// Padding shape.
		{Key: "transport.x_padding_bytes", Label: "Padding bytes", Type: "text", Ph: "100-1000",
			Help: "single number or a low-high range"},
		{Key: "transport.x_padding_obfs_mode", Label: "Obfuscated padding", Type: "bool",
			Help: "derive the padding token from a key instead of sending raw filler"},
		{Key: "transport.x_padding_key", Label: "Padding key", Type: "text", Help: "used when obfuscated padding is on"},
		{Key: "transport.x_padding_header", Label: "Padding header name", Type: "text", Ph: "X-Padding"},
		{Key: "transport.x_padding_placement", Label: "Padding placement", Type: "select",
			Options: opt(model.AllXHTTPPaddingPlacements()), Help: "the core rejects \"path\" here"},
		{Key: "transport.x_padding_method", Label: "Padding method", Type: "select",
			Options: opt(model.AllXHTTPPaddingMethods())},

		// Response shape. Both strip a layer of camouflage a fronting CDN may
		// otherwise mangle.
		{Key: "transport.no_grpc_header", Label: "No gRPC header", Type: "bool"},
		{Key: "transport.no_sse_header", Label: "No SSE header", Type: "bool"},

		// Session and sequence carriage — moving these out of the path is what
		// defeats path-pattern DPI.
		{Key: "transport.session_placement", Label: "Session placement", Type: "select", Options: opt(model.AllXHTTPPlacements())},
		{Key: "transport.session_key", Label: "Session key", Type: "text", Help: "header/cookie/query name carrying the session id"},
		{Key: "transport.seq_placement", Label: "Sequence placement", Type: "select", Options: opt(model.AllXHTTPPlacements())},
		{Key: "transport.seq_key", Label: "Sequence key", Type: "text"},

		// Uplink shaping. The core restricts two of these to packet-up; the
		// help text says so rather than letting the save fail with a core error.
		{Key: "transport.uplink_data_placement", Label: "Uplink data placement", Type: "select",
			Options: opt(model.AllXHTTPUplinkDataPlacements()), Help: "header and cookie require packet-up mode"},
		{Key: "transport.uplink_data_key", Label: "Uplink data key", Type: "text"},
		{Key: "transport.uplink_http_method", Label: "Uplink HTTP method", Type: "select",
			Options: opt(model.AllXHTTPUplinkMethods()), Help: "GET requires packet-up mode"},
		{Key: "transport.uplink_chunk_size", Label: "Uplink chunk size", Type: "number"},

		// packet-up / stream-up flow control. The sc* values are Int32Range
		// literals: "1000000" or "500000-1000000".
		{Key: "transport.sc_max_each_post_bytes", Label: "Max bytes per POST", Type: "text", Ph: "1000000"},
		{Key: "transport.sc_min_posts_interval_ms", Label: "Min interval between POSTs (ms)", Type: "text", Ph: "30-50"},
		{Key: "transport.sc_max_buffered_posts", Label: "Max buffered POSTs", Type: "number"},
		{Key: "transport.sc_stream_up_server_secs", Label: "stream-up server seconds", Type: "text", Ph: "20-80"},

		// Connection reuse (xmux).
		{Key: "transport.xmux.max_concurrency", Label: "xmux max concurrency", Type: "text", Ph: "16-32",
			Help: "streams per connection — an ALTERNATIVE to max connections, not a companion"},
		{Key: "transport.xmux.max_connections", Label: "xmux max connections", Type: "text", Ph: "8",
			Help: "the core rejects this combined with max concurrency; set one or the other"},
		{Key: "transport.xmux.c_max_reuse_times", Label: "xmux connection reuse times", Type: "text", Ph: "64-128"},
		{Key: "transport.xmux.h_max_request_times", Label: "xmux requests per connection", Type: "text", Ph: "600-900"},
		{Key: "transport.xmux.h_max_reusable_secs", Label: "xmux reusable seconds", Type: "text", Ph: "1800-3000"},
		{Key: "transport.xmux.h_keep_alive_period", Label: "xmux keep-alive period (s)", Type: "number"},
	}

	// The split download leg: a COMPLETE second stream with its own address,
	// transport and TLS/REALITY layer. This is what makes "upload through the
	// CDN, download direct" expressible, and it is the single most useful XHTTP
	// feature for operators fighting asymmetric throttling — which is why
	// leaving it out of the form was the costliest omission of the set.
	dl := "transport.download_settings."
	f = append(f,
		Field{Key: dl + "address", Label: "Download leg · address", Type: "text",
			Help: "leave every download field empty to use a single stream"},
		Field{Key: dl + "port", Label: "Download leg · port", Type: "number"},
		Field{Key: dl + "transport.network", Label: "Download leg · transport", Type: "select",
			Options: []string{"", "tcp", "ws", "grpc", "httpupgrade", "xhttp"}},
		Field{Key: dl + "transport.path", Label: "Download leg · path", Type: "text"},
		Field{Key: dl + "transport.host", Label: "Download leg · host", Type: "text"},
		Field{Key: dl + "transport.xhttp_mode", Label: "Download leg · mode", Type: "select", Options: opt(model.AllXHTTPModes())},
		Field{Key: dl + "security.type", Label: "Download leg · security", Type: "select", Options: []string{"", "none", "tls", "reality"}},
		Field{Key: dl + "security.server_name", Label: "Download leg · SNI", Type: "text"},
		Field{Key: dl + "security.fingerprint", Label: "Download leg · uTLS fingerprint", Type: "select", Options: opt(model.ValidFingerprints())},
		Field{Key: dl + "security.alpn", Label: "Download leg · ALPN", Type: "csv", Ph: "h2,http/1.1"},
		Field{Key: dl + "security.reality.dest", Label: "Download leg · REALITY dest", Type: "text", Ph: "www.cloudflare.com:443"},
		Field{Key: dl + "security.reality.server_names", Label: "Download leg · REALITY SNIs", Type: "csv"},
		Field{Key: dl + "security.reality.public_key", Label: "Download leg · REALITY public key", Type: "text"},
		Field{Key: dl + "security.reality.short_ids", Label: "Download leg · REALITY short ids", Type: "csv"},
		Field{Key: dl + "security.reality.spider_x", Label: "Download leg · REALITY spiderX", Type: "text"},
	)
	return f
}

// securityFields returns the fields each security layer needs.
func securityFields(fps []string) map[string][]Field {
	return map[string][]Field{
		"none": {},
		"tls": {
			{Key: "security.server_name", Label: "SNI", Type: "text"},
			{Key: "security.fingerprint", Label: "uTLS fingerprint", Type: "select", Options: fps, Default: "chrome"},
			{Key: "security.alpn", Label: "ALPN (comma-sep)", Type: "csv", Ph: "h2,http/1.1"},
			{Key: "security.min_version", Label: "Min TLS version", Type: "select", Options: []string{"", "1.2", "1.3"}},
			{Key: "security.max_version", Label: "Max TLS version", Type: "select", Options: []string{"", "1.2", "1.3"}},
			{Key: "security.cipher_suites", Label: "Cipher suites", Type: "text", Ph: "TLS_AES_128_GCM_SHA256:..."},
			{Key: "security.allow_insecure", Label: "Allow insecure (auto for self-signed)", Type: "bool"},
			{Key: "security.pin_sha256", Label: "Pinned certificate SHA-256", Type: "csv",
				Help: "clients accept only these certificate fingerprints"},
			// ECH is rendered by the sing-box path (render/singbox.go). It was a
			// live feature with no control anywhere in the panel.
			{Key: "security.ech.enabled", Label: "Encrypted Client Hello", Type: "bool",
				Help: "sing-box protocols only"},
			{Key: "security.ech.config_list", Label: "ECH config list", Type: "textarea",
				Help: "base64 ECHConfigList; leave empty and use auto-fetch to resolve it from DNS"},
			{Key: "security.ech.auto_fetch", Label: "Fetch ECH config from DNS", Type: "bool",
				Help: "resolve the ECHConfigList from the HTTPS resource record"},
		},
		"reality": {
			{Key: "security.reality.dest", Label: "Dest / steal-site", Type: "text", Default: "www.cloudflare.com:443", Help: "avoid microsoft.com; use cloudflare/apple/google"},
			{Key: "security.server_name", Label: "SNI (matches dest)", Type: "text", Default: "www.cloudflare.com"},
			{Key: "security.fingerprint", Label: "uTLS fingerprint", Type: "select", Options: fps, Default: "chrome"},
			{Key: "security.reality.private_key", Label: "Private key", Type: "text", Keygen: "reality", Help: "auto-generated if empty"},
			{Key: "security.reality.public_key", Label: "Public key", Type: "text"},
			{Key: "security.reality.short_id", Label: "Short ID", Type: "text", Keygen: "shortid",
				Help: "the one written into client links"},
			{Key: "security.reality.short_ids", Label: "Accepted short IDs", Type: "csv",
				Help: "every short ID this inbound accepts; lets each client carry its own"},
			// Multi-SNI is the whole basis of SNI rotation, and the form offered
			// exactly one. The rule below is not theory: measured across 34 live
			// REALITY variants, every failure was an SNI its dest does not serve.
			{Key: "security.reality.server_names", Label: "Accepted SNIs", Type: "csv",
				Ph: "www.cloudflare.com,discord.com",
				Help: "each MUST be hosted by the dest above — REALITY relays the ClientHello to dest, " +
					"so an SNI dest cannot serve fails the handshake even though the config is correct"},
			{Key: "security.reality.spider_x", Label: "SpiderX", Type: "text", Ph: "/"},
			{Key: "security.reality.xver", Label: "Proxy protocol (xver)", Type: "iselect", Options: []string{"0", "1", "2"}, Default: 0},
		},
	}
}
