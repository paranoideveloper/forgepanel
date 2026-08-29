// Package model defines THE single canonical representation of a proxy node.
//
// Architectural invariant (spec §3): there is exactly one canonical
// representation of an inbound/outbound, and every other form -- engine config
// (render/), client link or subscription (export/), foreign link or panel DB
// (parse/) -- is a pure function of it.
//
//	parse/  ──►  model.Node  ──►  render/  (xray json, sing-box json, brook args)
//	                         ──►  export/  (vless://, clash yaml, sing-box, QR…)
//
// The mandatory property test is parse(export(x)) == x for every protocol and
// every export format that is lossless for that protocol. To make equality
// well defined, every Node must be run through Normalize before comparison.
package model

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// deriveInnerPSK produces a valid, stable SS2022 PSK (base64 of the method's key
// length) for a ShadowTLS node's inner Shadowsocks, derived from the handshake
// password so it never collides with an empty value and stays reproducible.
func deriveInnerPSK(seed, method string) string {
	size, _ := KeySizeForMethod(method)
	if size <= 0 {
		size = 16
	}
	sum := sha256.Sum256([]byte("forgepanel-shadowtls-inner:" + seed)) // 32 bytes, ≥ aes-128/256 keylen
	return base64.StdEncoding.EncodeToString(sum[:size])
}

// Protocol identifies a wire protocol. These string values are stable: they are
// used as the discriminator in JSON, in the DB, and in the registry.
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoTrojan      Protocol = "trojan"
	ProtoShadowsocks Protocol = "shadowsocks"
	ProtoSOCKS       Protocol = "socks"
	ProtoHTTP        Protocol = "http"
	ProtoHysteria2   Protocol = "hysteria2"
	ProtoTUIC        Protocol = "tuic"
	ProtoAnyTLS      Protocol = "anytls"
	ProtoWireGuard   Protocol = "wireguard"
	ProtoAmneziaWG   Protocol = "amneziawg"
	ProtoShadowTLS   Protocol = "shadowtls"
	ProtoSSH         Protocol = "ssh"
	ProtoBrook       Protocol = "brook"
	ProtoForgeDNS    Protocol = "forgedns"
)

// AllProtocols is the full protocol matrix from spec §3.1. Tests enumerate it.
func AllProtocols() []Protocol {
	return []Protocol{
		ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoSOCKS,
		ProtoHTTP, ProtoHysteria2, ProtoTUIC, ProtoAnyTLS, ProtoWireGuard,
		// AmneziaWG was declared as a protocol and fully implemented (kernel
		// mode, awg-quick) but was missing from this list, which is what the
		// API's protocol metadata and the test matrices enumerate. It was
		// therefore invisible to anything that asked "which protocols exist".
		ProtoAmneziaWG,
		ProtoShadowTLS, ProtoSSH, ProtoBrook, ProtoForgeDNS,
	}
}

// Network is a transport network type (spec §3.2).
type Network string

const (
	NetTCP         Network = "tcp"
	NetWS          Network = "ws"
	NetGRPC        Network = "grpc"
	NetHTTPUpgrade Network = "httpupgrade"
	NetXHTTP       Network = "xhttp"
	NetH2          Network = "h2"
	NetMKCP        Network = "kcp"
	NetQUIC        Network = "quic"
)

// AllNetworks returns every transport, for matrix enumeration in tests.
func AllNetworks() []Network {
	return []Network{NetTCP, NetWS, NetGRPC, NetHTTPUpgrade, NetXHTTP, NetH2, NetMKCP, NetQUIC}
}

// SecurityType is the TLS-layer selector.
type SecurityType string

const (
	SecNone    SecurityType = "none"
	SecTLS     SecurityType = "tls"
	SecReality SecurityType = "reality"
)

// AllSecurityTypes returns every security layer, for matrix enumeration.
func AllSecurityTypes() []SecurityType { return []SecurityType{SecNone, SecTLS, SecReality} }

// Shadowsocks methods. The 2022-blake3-* family requires a base64 PSK whose
// decoded length must equal the cipher key size; see KeySizeForMethod.
const (
	SS2022AES128    = "2022-blake3-aes-128-gcm"
	SS2022AES256    = "2022-blake3-aes-256-gcm"
	SS2022ChaCha20  = "2022-blake3-chacha20-poly1305"
	SSAES256GCM     = "aes-256-gcm"
	SSAES128GCM     = "aes-128-gcm"
	SSChaCha20Poly  = "chacha20-ietf-poly1305"
	SSXChaCha20Poly = "xchacha20-ietf-poly1305"
	SSNone          = "none"
)

// AllShadowsocksMethods lists every method required by spec §3.1.
func AllShadowsocksMethods() []string {
	return []string{
		SS2022AES128, SS2022AES256, SS2022ChaCha20,
		SSAES256GCM, SSAES128GCM, SSChaCha20Poly, SSXChaCha20Poly, SSNone,
	}
}

// KeySizeForMethod returns the required raw key length in bytes for a
// Shadowsocks method, and whether the method is a SIP022 ("2022-blake3") one.
// A zero size means the method takes an arbitrary-length passphrase.
func KeySizeForMethod(method string) (size int, is2022 bool) {
	switch method {
	case SS2022AES128:
		return 16, true
	case SS2022AES256, SS2022ChaCha20:
		return 32, true
	case SSAES128GCM:
		return 16, false
	case SSAES256GCM, SSChaCha20Poly:
		return 32, false
	case SSXChaCha20Poly:
		return 32, false
	default:
		return 0, false
	}
}

// Header is an obfuscation header for tcp/mkcp/quic transports.
//
// Type is the whole of it. This carried Request/Host/Path/Method as well, none
// of which any producer set, any renderer read or any exporter wrote — and for
// the http type they would have been ignored anyway. Measured against Xray
// 26.2.6 with a real client and server on the tcp http header: the server
// validates ONLY the request path (a mismatched path fails the connection), and
// ignores the method and every header including Host. The camouflage request is
// therefore described by Transport.Path and Transport.Host, which is what
// xrayStream renders and what the share-link exporters carry.
type Header struct {
	Type string `json:"type,omitempty"` // none, http, srtp, utp, wechat-video, dtls, wireguard
}

// Transport carries every transport-layer knob, orthogonally to the protocol.
// Only the fields relevant to Network are meaningful; Normalize clears the rest
// so that equality and golden files stay stable.
type Transport struct {
	Network Network `json:"network"`

	// ws / httpupgrade / xhttp / h2
	Path      string            `json:"path,omitempty"`
	Host      string            `json:"host,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	EarlyData int               `json:"early_data,omitempty"` // ws "ed=" max early data
	EDHeader  string            `json:"ed_header,omitempty"`  // early data header name

	// grpc
	ServiceName string `json:"service_name,omitempty"`
	MultiMode   bool   `json:"multi_mode,omitempty"`
	IdleTimeout int    `json:"idle_timeout,omitempty"`
	// HealthCheckTimeout is the seconds Xray waits for a gRPC health-check
	// response. It was a bool ("health_check") that nothing ever rendered: it
	// could be set through the API, survived a clone, and reached no engine. The
	// core takes a TIMEOUT, so a bool could not express it in the first place —
	// verified with `xray run -test` against Xray 26.2.6.
	HealthCheckTimeout int  `json:"health_check_timeout,omitempty"`
	InitialWindows     int  `json:"initial_windows,omitempty"`
	PermitWithout      bool `json:"permit_without_stream,omitempty"`

	// xhttp / splithttp -- see xhttp.go for the enum tables and the rules the
	// core enforces on these. Path/Host/Headers above are shared with ws.
	XHTTPMode string `json:"xhttp_mode,omitempty"` // auto, packet-up, stream-up, stream-one
	XPaddingB string `json:"x_padding_bytes,omitempty"`
	XMux      *XMux  `json:"xmux,omitempty"`

	// Obfuscated padding: where the padding token rides and how it is built.
	XPaddingObfsMode  bool   `json:"x_padding_obfs_mode,omitempty"`
	XPaddingKey       string `json:"x_padding_key,omitempty"`
	XPaddingHeader    string `json:"x_padding_header,omitempty"`
	XPaddingPlacement string `json:"x_padding_placement,omitempty"` // queryInHeader, header, cookie, query
	XPaddingMethod    string `json:"x_padding_method,omitempty"`    // repeat-x, tokenish

	// Response-shape switches. Both strip a layer of camouflage the CDN in
	// front may otherwise mangle.
	NoGRPCHeader bool `json:"no_grpc_header,omitempty"`
	NoSSEHeader  bool `json:"no_sse_header,omitempty"`

	// packet-up / stream-up flow control. The sc* ranges are Int32Range
	// literals ("1000000" or "500000-1000000").
	SCMaxEachPostBytes   string `json:"sc_max_each_post_bytes,omitempty"`
	SCMinPostsIntervalMs string `json:"sc_min_posts_interval_ms,omitempty"`
	SCMaxBufferedPosts   int    `json:"sc_max_buffered_posts,omitempty"`
	SCStreamUpServerSecs string `json:"sc_stream_up_server_secs,omitempty"`

	// Where the session id and the packet sequence number are carried. Moving
	// them out of the path is what defeats path-pattern DPI.
	SessionPlacement string `json:"session_placement,omitempty"` // path, header, cookie, query
	SessionKey       string `json:"session_key,omitempty"`
	SeqPlacement     string `json:"seq_placement,omitempty"` // path, header, cookie, query
	SeqKey           string `json:"seq_key,omitempty"`

	// Uplink shaping (packet-up).
	UplinkDataPlacement string `json:"uplink_data_placement,omitempty"` // body, header, cookie
	UplinkDataKey       string `json:"uplink_data_key,omitempty"`
	UplinkHTTPMethod    string `json:"uplink_http_method,omitempty"` // POST, PUT, PATCH, GET
	UplinkChunkSize     int    `json:"uplink_chunk_size,omitempty"`

	// ServerMaxHeaderBytes caps inbound header size; server-side only.
	ServerMaxHeaderBytes int `json:"server_max_header_bytes,omitempty"`

	// XHTTPDownload is the separate download leg (`downloadSettings`).
	XHTTPDownload *XHTTPDownload `json:"download_settings,omitempty"`

	// h2
	H2Hosts []string `json:"h2_hosts,omitempty"`

	// tcp / mkcp / quic obfuscation
	HeaderObfs *Header `json:"header,omitempty"`

	// mkcp
	Seed         string `json:"seed,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
	TTI          int    `json:"tti,omitempty"`
	UplinkCap    int    `json:"uplink_capacity,omitempty"`
	DownlinkCap  int    `json:"downlink_capacity,omitempty"`
	Congestion   bool   `json:"congestion,omitempty"`
	ReadBufSize  int    `json:"read_buffer_size,omitempty"`
	WriteBufSize int    `json:"write_buffer_size,omitempty"`

	// quic
	QUICSecurity string `json:"quic_security,omitempty"` // none, aes-128-gcm, chacha20-poly1305
	QUICKey      string `json:"quic_key,omitempty"`
}

// XMux holds xhttp multiplexing parameters. The string fields are Int32Range
// literals: a bare number ("16") or an inclusive range ("16-32") the client
// re-rolls per connection, which is what keeps the traffic shape from being a
// fingerprint.
//
// MaxConcurrency and MaxConnections are ALTERNATIVE strategies -- streams per
// connection versus a fixed connection pool -- and the core refuses a config
// that sets both ("maxConnections cannot be specified together with
// maxConcurrency"); Validate rejects that pairing before it reaches the engine.
//
// There is deliberately no cMaxLifetimeMs: it is not part of the XHTTP xmux
// schema of the pinned Xray, which silently ignores it.
type XMux struct {
	MaxConcurrency   string `json:"max_concurrency,omitempty"`
	MaxConnections   string `json:"max_connections,omitempty"`
	CMaxReuseTimes   string `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTime  string `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs string `json:"h_max_reusable_secs,omitempty"`
	HKeepAlivePeriod int    `json:"h_keep_alive_period,omitempty"`
}

// ECH carries Encrypted Client Hello settings. The config list is the base64
// ECHConfigList; when AutoFetch is set it is resolved from the DNS HTTPS RR.
type ECH struct {
	Enabled    bool   `json:"enabled,omitempty"`
	ConfigList string `json:"config_list,omitempty"`
	AutoFetch  bool   `json:"auto_fetch,omitempty"`
}

// Reality carries REALITY parameters. PrivateKey is server-side only and must
// never appear in an exported client link; PublicKey is the client-side value.
type Reality struct {
	Dest        string   `json:"dest,omitempty"`
	ServerNames []string `json:"server_names,omitempty"`
	PrivateKey  string   `json:"private_key,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortIDs    []string `json:"short_ids,omitempty"`
	ShortID     string   `json:"short_id,omitempty"` // the one selected for a client link
	SpiderX     string   `json:"spider_x,omitempty"`
	Xver        int      `json:"xver,omitempty"`
	// Post-quantum REALITY (ML-DSA-65). Empty means disabled -- which is what
	// interoperable clients need today; see docs/DECISIONS.md ADR-007.
	MLDSA65Seed   string `json:"mldsa65_seed,omitempty"`
	MLDSA65Verify string `json:"mldsa65_verify,omitempty"`
}

// Security is the TLS layer: none, standard TLS, or REALITY.
type Security struct {
	Type SecurityType `json:"type"`

	ServerName      string   `json:"server_name,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	Fingerprint     string   `json:"fingerprint,omitempty"` // uTLS: chrome, firefox, safari…
	AllowInsecure   bool     `json:"allow_insecure,omitempty"`
	MinVersion      string   `json:"min_version,omitempty"`
	MaxVersion      string   `json:"max_version,omitempty"`
	CipherSuites    string   `json:"cipher_suites,omitempty"`
	CertificateFile string   `json:"certificate_file,omitempty"`
	KeyFile         string   `json:"key_file,omitempty"`
	PinSHA256       []string `json:"pin_sha256,omitempty"`

	Reality *Reality `json:"reality,omitempty"`
	ECH     *ECH     `json:"ech,omitempty"`
}

// ValidFingerprints is the uTLS fingerprint set from spec §3.2.
func ValidFingerprints() []string {
	return []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
}

// Multiplex covers both mux.cool (xray) and sing-box mux.
type Multiplex struct {
	Enabled     bool    `json:"enabled,omitempty"`
	Protocol    string  `json:"protocol,omitempty"` // smux, yamux, h2mux (sing-box)
	MaxConns    int     `json:"max_connections,omitempty"`
	MinStreams  int     `json:"min_streams,omitempty"`
	MaxStreams  int     `json:"max_streams,omitempty"`
	Padding     bool    `json:"padding,omitempty"`
	Concurrency int     `json:"concurrency,omitempty"` // mux.cool
	Brutal      *Brutal `json:"brutal,omitempty"`
}

// Brutal is the TCP Brutal congestion control block.
type Brutal struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// Hysteria2Options holds Hysteria2-specific parameters (spec §3.1).
type Hysteria2Options struct {
	UpMbps   int `json:"up_mbps,omitempty"`
	DownMbps int `json:"down_mbps,omitempty"`

	ObfsType     string `json:"obfs_type,omitempty"` // "salamander" or empty
	ObfsPassword string `json:"obfs_password,omitempty"`

	// PortHopping is a range spec such as "20000-50000"; PortHopInterval is in
	// seconds. Both are client-side hints encoded into the link.
	PortHopping     string `json:"port_hopping,omitempty"`
	PortHopInterval int    `json:"port_hop_interval,omitempty"`

	IgnoreClientBandwidth bool `json:"ignore_client_bandwidth,omitempty"`

	// Structured masquerade (sing-box hysteria2 inbound). Legacy MasqueradeType +
	// MasqueradeURL are migrated into Masquerade by Normalize for back-compat.
	Masquerade     *Hy2Masquerade `json:"masquerade,omitempty"`
	MasqueradeType string         `json:"masquerade_type,omitempty"` // legacy: proxy, file, string
	MasqueradeURL  string         `json:"masquerade_url,omitempty"`  // legacy
}

// Hy2Masquerade is the sing-box hysteria2 masquerade object. Type selects which
// fields apply: proxy (URL, RewriteHost), file (Directory), string (StatusCode,
// Headers, Content). Verified against the pinned sing-box.
type Hy2Masquerade struct {
	Type        string            `json:"type,omitempty"` // proxy, file, string
	URL         string            `json:"url,omitempty"`
	RewriteHost bool              `json:"rewrite_host,omitempty"`
	Directory   string            `json:"directory,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Content     string            `json:"content,omitempty"`
}

// TUICOptions holds TUIC v5 parameters.
type TUICOptions struct {
	CongestionControl string `json:"congestion_control,omitempty"` // bbr, cubic, new_reno
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`     // native, quic
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake,omitempty"`
	HeartbeatSeconds  int    `json:"heartbeat,omitempty"`
	DisableSNI        bool   `json:"disable_sni,omitempty"`
}

// AnyTLSOptions holds AnyTLS parameters.
type AnyTLSOptions struct {
	PaddingScheme            []string `json:"padding_scheme,omitempty"`
	IdleSessionCheckInterval int      `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       int      `json:"idle_session_timeout,omitempty"`
	MinIdleSessions          int      `json:"min_idle_sessions,omitempty"`
}

// WireGuardOptions holds a WireGuard SERVER inbound and the single client peer
// the panel provisions for it. The panel runs the server as a sing-box wireguard
// endpoint (the only correct form in sing-box ≥1.13; xray's WG inbound / sing-box's
// old wg outbound are gone). To be a WORKING tunnel the server needs its own
// keypair AND the client's public key as a peer; the client config needs the
// client's private key + the server's public key. The panel mints both keypairs
// so WireGuard works out of the box with any standard/Amnezia client.
type WireGuardOptions struct {
	// Server side (this box). PrivateKey stays server-side; PublicKey goes in the
	// client config. ServerAddress is the server's own tunnel IP (with /prefix).
	PrivateKey    string   `json:"private_key,omitempty"`
	PublicKey     string   `json:"public_key,omitempty"`
	ServerAddress []string `json:"server_address,omitempty"` // e.g. ["10.66.66.1/24"]

	// Client peer (what the exported .conf uses). PeerPublicKey is registered as a
	// peer on the server; PeerPrivateKey + PeerAddress go into the client config.
	PeerPrivateKey string   `json:"peer_private_key,omitempty"`
	PeerPublicKey  string   `json:"peer_public_key,omitempty"`
	PeerAddress    []string `json:"peer_address,omitempty"` // e.g. ["10.66.66.2/32"]

	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"` // client [Peer] AllowedIPs; default 0.0.0.0/0,::/0
	MTU          int      `json:"mtu,omitempty"`
	Keepalive    int      `json:"persistent_keepalive,omitempty"`
	Reserved     []int    `json:"reserved,omitempty"` // 3 bytes, WARP compatible
	Workers      int      `json:"workers,omitempty"`

	// LocalAddress is the tunnel address of whichever side THIS node describes.
	//
	// It is not interchangeable with ServerAddress, and the old comment here
	// saying it "maps to ServerAddress" caused exactly the confusion it sounds
	// like. Every reader treats it as the DIALER's own address: the parser fills
	// it from a wireguard:// link's address=, the URI and Clash exporters write
	// it back out as the client's address, and the xray outbound renders it as
	// the local interface address. Only the inbound create path ever read it as
	// the server's address, which is why an inbound imported from a client link
	// used to take the client's /32 as its own interface address and produce a
	// tunnel whose two ends were not on a common subnet.
	//
	// For an inbound the panel serves, the server's address is ServerAddress and
	// the client's is PeerAddress; both are allocated by the panel.
	LocalAddress []string `json:"local_address,omitempty"`

	// Peers is the per-client peer list the SERVER config renders.
	//
	// PeerPublicKey/PeerAddress above describe exactly ONE client, which made
	// "assign five users to this WireGuard inbound" inexpressible: WireGuard
	// keys a session by public key, so five clients sharing a key take the
	// tunnel from each other in turn rather than sharing it.
	//
	// Populated by the panel when it builds engine configs, not by the operator
	// and not stored on the inbound: peers belong to the (inbound, user) pairing
	// and change as users are assigned. Empty keeps the legacy single-peer
	// behaviour, so an inbound with no assigned users renders exactly as before.
	Peers []WGPeerEntry `json:"peers,omitempty"`
}

// WGPeerEntry is one client's [Peer] block in a server config.
type WGPeerEntry struct {
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"pre_shared_key,omitempty"`
	// AllowedIPs must pin ONE host. Wider than that and a peer receives traffic
	// addressed to its neighbours on the same tunnel.
	AllowedIPs []string `json:"allowed_ips"`
}

// AmneziaWGOptions is a WireGuard config plus AmneziaWG's obfuscation parameters
// (Jc/Jmin/Jmax junk packets, S1/S2 init/response junk sizes, H1..H4 header type
// magics). ForgePanel runs AmneziaWG in KERNEL mode via the amneziawg module and
// awg-quick, so these live on the interface and MUST match between server and
// client. It embeds WireGuardOptions so the base wg-quick fields are reused.
type AmneziaWGOptions struct {
	WireGuardOptions
	Jc   int   `json:"jc,omitempty"`   // junk packet count (1..128)
	Jmin int   `json:"jmin,omitempty"` // junk packet min size
	Jmax int   `json:"jmax,omitempty"` // junk packet max size (Jmin < Jmax <= 1280)
	S1   int   `json:"s1,omitempty"`   // init packet junk size (S1+56 != S2)
	S2   int   `json:"s2,omitempty"`   // response packet junk size
	H1   int64 `json:"h1,omitempty"`   // header magics, distinct and > 4
	H2   int64 `json:"h2,omitempty"`
	H3   int64 `json:"h3,omitempty"`
	H4   int64 `json:"h4,omitempty"`
}

// ShadowTLSOptions wraps a Shadowsocks inbound behind a real TLS handshake.
// ShadowTLS is a camouflage layer, not a proxy: the sing-box shadowtls inbound
// must `detour` to an inner Shadowsocks inbound that carries the actual traffic.
// InnerMethod/InnerPassword are that inner SS's credentials — the panel mints
// them so a ShadowTLS node is a complete, working tunnel out of the box.
type ShadowTLSOptions struct {
	Version       int    `json:"version,omitempty"` // 1, 2, 3
	Password      string `json:"password,omitempty"`
	HandshakeHost string `json:"handshake_host,omitempty"`
	HandshakePort int    `json:"handshake_port,omitempty"`
	StrictMode    bool   `json:"strict_mode,omitempty"`

	InnerMethod   string `json:"inner_method,omitempty"`   // inner Shadowsocks method (SS2022)
	InnerPassword string `json:"inner_password,omitempty"` // inner Shadowsocks PSK
}

// SSHOptions holds SSH transport parameters.
type SSHOptions struct {
	User               string   `json:"user,omitempty"`
	Password           string   `json:"password,omitempty"`
	PrivateKey         string   `json:"private_key,omitempty"`
	PrivateKeyPassword string   `json:"private_key_passphrase,omitempty"`
	HostKeyAlgorithms  []string `json:"host_key_algorithms,omitempty"`
	ClientVersion      string   `json:"client_version,omitempty"`
}

// BrookOptions holds Brook parameters. Brook is supervised as an external
// process only -- never imported or linked (GPL-3.0; see docs/LICENSING.md).
type BrookOptions struct {
	Mode string `json:"mode,omitempty"` // server, wsserver, wssserver, quicserver
	Path string `json:"path,omitempty"`
	// UDPOverTCP is a CLIENT-side setting: it appears in the generated link, not
	// in the server invocation. Checked against the pinned binary —
	// `brook link --udpovertcp` emits `udpovertcp=true` and `brook server` has
	// no such flag.
	UDPOverTCP bool `json:"udp_over_tcp,omitempty"`
}

// ForgeDNSOptions holds DNS-tunnel parameters (spec §5). Adapter selects the
// wire format; Zone is the delegated tunnel domain.
type ForgeDNSOptions struct {
	Adapter string `json:"adapter,omitempty"` // stormdns, masterdns, cottendns
	Zone    string `json:"zone,omitempty"`
	NSHost  string `json:"ns_host,omitempty"`
	Key     string `json:"key,omitempty"`
	RRType  string `json:"rrtype,omitempty"` // TXT, NULL, CNAME, A, AAAA, MX
	// Chunk-size overrides. NOT HONOURED YET, and kept only so a stored config
	// carrying them survives a round trip. The adapter derives its own limits
	// from the wire format (internal/forgedns/adapter), the forgedns:// link
	// carries no field for them, and the tunnel's egress path is still
	// incomplete (FP-DNS-001) — so wiring a tuning override into it now would
	// tune something that does not yet carry traffic. Documented rather than
	// deleted because the values are meaningful and will be honoured once the
	// egress path lands; documented rather than left bare because a field the
	// panel accepts and silently ignores is worse than one it does not offer.
	MaxUpstream   int `json:"max_upstream,omitempty"`
	MaxDownstream int `json:"max_downstream,omitempty"`
	EDNSBuffer    int `json:"edns_buffer,omitempty"`
}

// SSPluginOptions holds a Shadowsocks plugin (SIP003).
type SSPluginOptions struct {
	Name string `json:"name,omitempty"` // v2ray-plugin, obfs-local, shadow-tls
	Opts string `json:"opts,omitempty"`
}

// Node is THE canonical representation. Every renderer, exporter and parser
// operates on this type and nothing else.
type Node struct {
	Tag      string   `json:"tag,omitempty"`
	Remark   string   `json:"remark,omitempty"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	// Country is an optional ISO-3166 alpha-2 code (e.g. "DE") the operator sets
	// per inbound. It feeds {FLAG}/{COUNTRY} in the subscription naming template.
	// It is descriptive metadata only — Normalize never touches it.
	Country string `json:"country,omitempty"`

	// Egress relays this inbound's traffic out through an upstream hop instead
	// of leaving the machine directly, which is what makes a multi-hop chain
	// (client -> entry -> transit -> internet) possible. It is the shape Iranian
	// deployments need: a client reaches a nearby entry, and the traffic exits
	// somewhere else entirely.
	//
	// It holds client URIs for the hops, in any protocol the panel can parse, so
	// a chain is configured with the same links an operator would paste into a
	// client app. Index 0 is dialled by this server and each later hop is
	// reached THROUGH the one before it, so a three-entry chain is
	// client -> entry -> transit -> exit -> internet. Empty means the inbound
	// egresses directly, which is exactly what every existing inbound does.
	//
	// A bare string is still accepted and still emitted for a one-hop chain, so
	// stored inbounds and imported links from before chains existed are
	// unaffected. See internal/protocol/model/egress.go.
	//
	// This is SERVER-side secret material: it carries every upstream hop's
	// credentials, so it must never be exported into a subscription or a client
	// link.
	Egress EgressChain `json:"egress,omitempty"`

	// Domain is the single source of truth an operator sets once; it CASCADES to
	// the SNI, the transport Host / gRPC authority, the exported client address
	// and certificate selection (see ApplyDomainCascade). Every derived field is
	// still individually overridable — the cascade only fills blanks. Empty means
	// "no domain": the inbound is IP-based and the UI steers the operator to
	// REALITY and the other domain-free protocols.
	Domain string `json:"domain,omitempty"`

	// Identity / credentials. Only the fields meaningful for Protocol are set;
	// Normalize clears the others.
	UUID       string `json:"uuid,omitempty"`       // vless, vmess, tuic
	Password   string `json:"password,omitempty"`   // trojan, ss, hy2, tuic, anytls, brook, socks, http
	Username   string `json:"username,omitempty"`   // socks, http
	Method     string `json:"method,omitempty"`     // shadowsocks
	Flow       string `json:"flow,omitempty"`       // vless: "" | xtls-rprx-vision
	Encryption string `json:"encryption,omitempty"` // vless: none | mlkem768…; vmess security
	AlterID    int    `json:"alter_id,omitempty"`   // vmess, always 0 for VMessAEAD

	Transport Transport  `json:"transport"`
	Security  Security   `json:"security"`
	Multiplex *Multiplex `json:"multiplex,omitempty"`

	// Protocol-specific extension blocks.
	Hysteria2 *Hysteria2Options `json:"hysteria2,omitempty"`
	TUIC      *TUICOptions      `json:"tuic,omitempty"`
	AnyTLS    *AnyTLSOptions    `json:"anytls,omitempty"`
	WireGuard *WireGuardOptions `json:"wireguard,omitempty"`
	AmneziaWG *AmneziaWGOptions `json:"amneziawg,omitempty"`
	ShadowTLS *ShadowTLSOptions `json:"shadowtls,omitempty"`
	SSH       *SSHOptions       `json:"ssh,omitempty"`
	Brook     *BrookOptions     `json:"brook,omitempty"`
	ForgeDNS  *ForgeDNSOptions  `json:"forgedns,omitempty"`
	SSPlugin  *SSPluginOptions  `json:"ss_plugin,omitempty"`
}

// ApplyDomainCascade fills every domain-derived field from n.Domain, WITHOUT
// overwriting anything the operator set explicitly — the cascade only fills
// blanks, so a per-field override always wins. It is the mechanism behind
// "set the domain once and everything follows": SNI, the transport Host header
// (WS / httpupgrade / h2) which is also the gRPC/authority the client presents,
// and the client-facing address in exported links.
//
// It deliberately does NOT touch REALITY's ServerNames: those are the borrowed
// destination site, not a domain the operator owns, so a REALITY inbound is
// domain-free by design and the cascade leaves it alone.
//
// Returns true when a domain is present and cascaded, false for the domain-free
// (IP-based) case, which the caller uses to drive the no-domain guidance.
func (n *Node) ApplyDomainCascade() bool {
	d := strings.TrimSpace(n.Domain)
	if d == "" {
		return false
	}
	n.Domain = d

	// SNI follows the domain for real TLS. REALITY borrows someone else's chain,
	// so its serverNames are left untouched.
	if n.Security.Type == SecTLS && n.Security.ServerName == "" {
		n.Security.ServerName = d
	}

	// The transport Host header (and the HTTP/2 & gRPC authority the client
	// presents) follows the domain wherever a Host is meaningful and unset.
	switch n.Transport.Network {
	case NetWS, NetHTTPUpgrade, NetH2, NetGRPC, NetXHTTP:
		if n.Transport.Host == "" {
			n.Transport.Host = d
		}
	}
	return true
}

// EffectiveClientAddress is the address a generated CLIENT link should dial: the
// operator's domain when one is set (so the link rides the CDN/cert), otherwise
// the node's own address. It never returns a bind-all placeholder.
func (n *Node) EffectiveClientAddress() string {
	if d := strings.TrimSpace(n.Domain); d != "" {
		return d
	}
	return n.Address
}

// IsPlaintext reports whether the inbound actually carries NO transport
// security — security "none" on a cleartext transport. The UI uses this to
// refuse to present such an inbound as if it were secure.
func (n *Node) IsPlaintext() bool {
	return n.Security.Type == SecNone && n.Protocol.UsesTransport()
}

// UsesTransport reports whether the protocol layers over the pluggable
// transport/security stack (VLESS/VMess/Trojan and friends) as opposed to
// carrying its own wire protocol (Hysteria2, TUIC, WireGuard, SSH, ForgeDNS…).
func (p Protocol) UsesTransport() bool {
	switch p {
	case ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks, ProtoSOCKS, ProtoHTTP:
		return true
	default:
		return false
	}
}

// IsQUICBased reports whether the protocol runs over QUIC and therefore always
// implies TLS with an h3 ALPN.
func (p Protocol) IsQUICBased() bool {
	return p == ProtoHysteria2 || p == ProtoTUIC
}

// Errors returned by Validate.
var (
	ErrNoAddress     = errors.New("address is required")
	ErrBadPort       = errors.New("port must be in 1..65535")
	ErrNoCredential  = errors.New("credential is required for this protocol")
	ErrUnknownProto  = errors.New("unknown protocol")
	ErrBadMethod     = errors.New("unknown shadowsocks method")
	ErrRealityNoKey  = errors.New("reality requires a public key (client) or private key (server)")
	ErrRealityNoDest = errors.New("reality requires a dest/serverName")
)

// Validate checks protocol-specific invariants. It is intentionally strict:
// Config Doctor (spec §8.6) surfaces these to the user with one-click fixes.
func (n *Node) Validate() error {
	if strings.TrimSpace(n.Address) == "" {
		return ErrNoAddress
	}
	// ForgeDNS rides on DNS and may legitimately use the standard port only.
	if n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("%w: got %d", ErrBadPort, n.Port)
	}
	// Refuse a chain the builders cannot honour. Storing one on, say, a Brook or
	// AmneziaWG inbound used to succeed and then do nothing: the operator saw a
	// configured upstream hop while the traffic left the machine directly. See
	// SupportsEgress for which engines have a routing table to attach it to.
	if !n.Egress.Empty() && !SupportsEgress(n.Protocol) {
		return fmt.Errorf("%s: cannot relay through an upstream hop — %s has no per-inbound "+
			"routing table, so the chain would be stored and then ignored while traffic exits directly",
			n.Protocol, EngineFor(n.Protocol))
	}
	switch n.Protocol {
	case ProtoVLESS:
		if n.UUID == "" {
			return fmt.Errorf("vless: %w", ErrNoCredential)
		}
		if n.Flow != "" && n.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("vless: unsupported flow %q", n.Flow)
		}
	case ProtoVMess:
		if n.UUID == "" {
			return fmt.Errorf("vmess: %w", ErrNoCredential)
		}
	case ProtoTrojan, ProtoAnyTLS, ProtoBrook:
		if n.Password == "" {
			return fmt.Errorf("%s: %w", n.Protocol, ErrNoCredential)
		}
	case ProtoHysteria2:
		if n.Password == "" {
			return fmt.Errorf("hysteria2: %w", ErrNoCredential)
		}
	case ProtoTUIC:
		if n.UUID == "" || n.Password == "" {
			return fmt.Errorf("tuic: %w (needs uuid and password)", ErrNoCredential)
		}
	case ProtoShadowsocks:
		size, is2022 := KeySizeForMethod(n.Method)
		if n.Method == "" {
			return ErrBadMethod
		}
		if !containsStr(AllShadowsocksMethods(), n.Method) {
			return fmt.Errorf("%w: %q", ErrBadMethod, n.Method)
		}
		if n.Method != SSNone && n.Password == "" {
			return fmt.Errorf("shadowsocks: %w", ErrNoCredential)
		}
		if is2022 {
			if err := validateSS2022PSK(n.Password, size); err != nil {
				return err
			}
		}
	case ProtoSOCKS, ProtoHTTP:
		// credentials optional (open proxy is legal, though Config Doctor warns)
	case ProtoWireGuard:
		if n.WireGuard == nil || n.WireGuard.PrivateKey == "" || n.WireGuard.PublicKey == "" {
			return fmt.Errorf("wireguard: %w (needs private and peer public key)", ErrNoCredential)
		}
		if n.WireGuard.MTU != 0 && (n.WireGuard.MTU < 576 || n.WireGuard.MTU > 1500) {
			return fmt.Errorf("wireguard: MTU %d out of range 576..1500", n.WireGuard.MTU)
		}
		if len(n.WireGuard.Reserved) != 0 && len(n.WireGuard.Reserved) != 3 {
			return errors.New("wireguard: reserved must be exactly 3 bytes")
		}
	case ProtoAmneziaWG:
		if n.AmneziaWG == nil || n.AmneziaWG.PrivateKey == "" || n.AmneziaWG.PublicKey == "" {
			return fmt.Errorf("amneziawg: %w (needs private and peer public key)", ErrNoCredential)
		}
		if n.AmneziaWG.Jmax != 0 && n.AmneziaWG.Jmin >= n.AmneziaWG.Jmax {
			return errors.New("amneziawg: Jmin must be less than Jmax")
		}
		if n.AmneziaWG.S1 != 0 && n.AmneziaWG.S2 != 0 && n.AmneziaWG.S1+56 == n.AmneziaWG.S2 {
			return errors.New("amneziawg: S1+56 must not equal S2")
		}
	case ProtoShadowTLS:
		if n.ShadowTLS == nil || n.ShadowTLS.Password == "" {
			return fmt.Errorf("shadowtls: %w", ErrNoCredential)
		}
		if v := n.ShadowTLS.Version; v < 1 || v > 3 {
			return fmt.Errorf("shadowtls: version must be 1..3, got %d", v)
		}
	case ProtoSSH:
		if n.SSH == nil || n.SSH.User == "" {
			return fmt.Errorf("ssh: %w (needs user)", ErrNoCredential)
		}
		if n.SSH.Password == "" && n.SSH.PrivateKey == "" {
			return fmt.Errorf("ssh: %w (needs password or private key)", ErrNoCredential)
		}
	case ProtoForgeDNS:
		if n.ForgeDNS == nil || n.ForgeDNS.Zone == "" {
			return errors.New("forgedns: zone is required")
		}
		if n.ForgeDNS.Adapter == "" {
			return errors.New("forgedns: adapter is required")
		}
	default:
		return fmt.Errorf("%w: %q", ErrUnknownProto, n.Protocol)
	}

	// Transport guards for the Xray family. h2/quic/mKCP were removed in Xray 26
	// and yield an unstartable config (verified against the running core), so
	// reject them with a clear message instead of a cryptic engine failure.
	if n.Protocol.UsesTransport() {
		switch n.Transport.Network {
		case NetH2:
			return errors.New("transport h2 was removed in Xray 26 — use xhttp (or ws/grpc)")
		case NetQUIC:
			return errors.New("transport quic was removed in Xray 26 — use xhttp or a QUIC protocol (hysteria2/tuic)")
		case NetMKCP:
			return errors.New("transport mKCP was removed in Xray 26 — use ws/grpc/xhttp")
		case NetXHTTP:
			// XHTTP has more cross-field rules than every other transport put
			// together, and the core enforces them at config-build time: an
			// invalid combination is not a degraded tunnel, it is an engine that
			// will not start. Catch it here so Config Doctor can say why.
			if err := validateXHTTP(&n.Transport); err != nil {
				return err
			}
		}
	}

	if n.Security.Type == SecReality {
		// REALITY only wraps RAW(tcp), XHTTP and gRPC (Xray: "REALITY only supports
		// RAW, XHTTP and gRPC for now"). Any other transport is rejected by the core.
		switch n.Transport.Network {
		case NetTCP, NetXHTTP, NetGRPC, "":
		default:
			return fmt.Errorf("REALITY only supports tcp, xhttp or grpc transport, not %q", n.Transport.Network)
		}
		r := n.Security.Reality
		if r == nil {
			return ErrRealityNoKey
		}
		if r.PublicKey == "" && r.PrivateKey == "" {
			return ErrRealityNoKey
		}
		if len(r.ServerNames) == 0 && n.Security.ServerName == "" && r.Dest == "" {
			return ErrRealityNoDest
		}
		// REALITY short IDs are hex, at most 8 bytes (16 hex chars).
		for _, sid := range append(append([]string{}, r.ShortIDs...), r.ShortID) {
			if sid == "" {
				continue
			}
			if len(sid) > 16 || len(sid)%2 != 0 || !isHex(sid) {
				return fmt.Errorf("reality: invalid shortId %q (must be even-length hex, <=16 chars)", sid)
			}
		}
	}
	if fp := n.Security.Fingerprint; fp != "" && !containsStr(ValidFingerprints(), fp) {
		return fmt.Errorf("unknown uTLS fingerprint %q", fp)
	}
	return nil
}

// Normalize puts a Node into canonical form: it lowercases enum-ish fields,
// applies protocol defaults, and -- crucially -- zeroes every field that is not
// meaningful for the selected protocol/transport/security. Without this, two
// semantically identical nodes could compare unequal and the round-trip
// property test in spec §15 would be meaningless.
func (n *Node) Normalize() {
	n.Protocol = Protocol(strings.ToLower(string(n.Protocol)))
	n.Address = strings.TrimSpace(n.Address)
	n.Method = strings.ToLower(strings.TrimSpace(n.Method))
	n.Flow = strings.TrimSpace(n.Flow)

	// --- transport ---
	if n.Transport.Network == "" {
		n.Transport.Network = NetTCP
	}
	n.Transport.Network = Network(strings.ToLower(string(n.Transport.Network)))
	// "splithttp" is the legacy name for xhttp; "h2"/"http" are the same net.
	switch string(n.Transport.Network) {
	case "splithttp":
		n.Transport.Network = NetXHTTP
	case "http":
		n.Transport.Network = NetH2
	case "mkcp":
		n.Transport.Network = NetMKCP
	}
	if !n.Protocol.UsesTransport() {
		// Protocols with their own wire format do not carry a pluggable
		// transport; force it to the canonical zero so equality is stable.
		n.Transport = Transport{Network: NetTCP}
	} else {
		n.Transport.clearIrrelevant()
	}

	// --- security ---
	if n.Security.Type == "" {
		n.Security.Type = SecNone
	}
	n.Security.Type = SecurityType(strings.ToLower(string(n.Security.Type)))
	if n.Security.Type == "xtls" { // legacy alias
		n.Security.Type = SecTLS
	}
	// QUIC-based and AnyTLS protocols are TLS-based by definition; a security=none
	// there is invalid and would make the client connect plain while the server
	// serves TLS. Force TLS so the link is coherent. ShadowTLS is deliberately
	// EXCLUDED: it is not a normal TLS inbound — it performs its own TLS-handshake
	// mimicry to `handshake.server`, and sing-box rejects a shadowtls inbound that
	// also carries a top-level `tls` block. ShadowTLS stays security=none.
	if (n.Protocol.IsQUICBased() || n.Protocol == ProtoAnyTLS) && n.Security.Type == SecNone {
		n.Security.Type = SecTLS
	}
	switch n.Security.Type {
	case SecNone:
		srv := n.Security.ServerName
		n.Security = Security{Type: SecNone}
		// A serverName with security=none is meaningless for TLS but some
		// transports use it as the HTTP Host; that lives in Transport.Host.
		_ = srv
	case SecTLS:
		n.Security.Reality = nil
		if n.Security.ECH != nil && !n.Security.ECH.Enabled && n.Security.ECH.ConfigList == "" && !n.Security.ECH.AutoFetch {
			n.Security.ECH = nil
		}
	case SecReality:
		n.Security.ECH = nil // REALITY does its own handshake; ECH does not apply
		n.Security.AllowInsecure = false
		if n.Security.Reality != nil {
			r := n.Security.Reality
			sort.Strings(r.ServerNames)
			sort.Strings(r.ShortIDs)
			if r.SpiderX == "" {
				r.SpiderX = "/"
			}
			// If exactly one serverName exists and no explicit SNI, adopt it.
			if n.Security.ServerName == "" && len(r.ServerNames) == 1 {
				n.Security.ServerName = r.ServerNames[0]
			}
		}
	}
	sort.Strings(n.Security.ALPN)

	// --- protocol-specific ---
	n.clearIrrelevantProtocolBlocks()

	switch n.Protocol {
	case ProtoVMess:
		n.AlterID = 0 // VMessAEAD only
		if n.Encryption == "" {
			n.Encryption = "auto"
		}
	case ProtoVLESS:
		if n.Encryption == "" {
			n.Encryption = "none"
		}
		// Vision requires a TLS-ish layer over raw TCP; it is meaningless over
		// ws/grpc/xhttp, so drop it there rather than emitting a broken link.
		if n.Flow != "" && n.Transport.Network != NetTCP {
			n.Flow = ""
		}
	case ProtoHysteria2:
		if n.Hysteria2 == nil {
			n.Hysteria2 = &Hysteria2Options{}
		}
		if len(n.Security.ALPN) == 0 {
			n.Security.ALPN = []string{"h3"}
		}
		// Migrate the legacy flat masquerade fields into the structured object so
		// old configs and links keep working after the schema change.
		h := n.Hysteria2
		if h.Masquerade == nil && h.MasqueradeType != "" {
			h.Masquerade = &Hy2Masquerade{Type: h.MasqueradeType, URL: h.MasqueradeURL}
		}
		h.MasqueradeType, h.MasqueradeURL = "", ""
	case ProtoTUIC:
		if n.TUIC == nil {
			n.TUIC = &TUICOptions{}
		}
		if n.TUIC.CongestionControl == "" {
			n.TUIC.CongestionControl = "bbr"
		}
		if n.TUIC.UDPRelayMode == "" {
			n.TUIC.UDPRelayMode = "native"
		}
		if len(n.Security.ALPN) == 0 {
			n.Security.ALPN = []string{"h3"}
		}
	case ProtoAnyTLS:
		if n.AnyTLS == nil {
			n.AnyTLS = &AnyTLSOptions{}
		}
	case ProtoWireGuard:
		if n.WireGuard != nil && n.WireGuard.MTU == 0 {
			n.WireGuard.MTU = 1420
		}
	case ProtoAmneziaWG:
		if n.AmneziaWG == nil {
			n.AmneziaWG = &AmneziaWGOptions{}
		}
		a := n.AmneziaWG
		if a.MTU == 0 {
			a.MTU = 1420
		}
		if a.Jc == 0 {
			a.Jc = 8
		}
		if a.Jmin == 0 {
			a.Jmin = 50
		}
		if a.Jmax == 0 {
			a.Jmax = 1000
		}
		if a.S1 == 0 {
			a.S1 = 86
		}
		if a.S2 == 0 {
			a.S2 = 574
		}
		if a.H1 == 0 {
			a.H1 = 1234567
		}
		if a.H2 == 0 {
			a.H2 = 2345678
		}
		if a.H3 == 0 {
			a.H3 = 3456789
		}
		if a.H4 == 0 {
			a.H4 = 4567890
		}
	case ProtoShadowTLS:
		if n.ShadowTLS == nil {
			n.ShadowTLS = &ShadowTLSOptions{}
		}
		if n.ShadowTLS.Version == 0 {
			n.ShadowTLS.Version = 3
		}
		// A v2/v3 shadowtls inbound needs a non-empty user password; never leave it
		// empty (sing-box would reject the whole config). Backfill deterministically.
		if n.ShadowTLS.Password == "" {
			sum := sha256.Sum256([]byte(fmt.Sprintf("forgepanel-shadowtls-hs:%d", n.Port)))
			n.ShadowTLS.Password = base64.RawURLEncoding.EncodeToString(sum[:12])
		}
		// ShadowTLS detours to an inner Shadowsocks that carries the tunnel. Never
		// leave the inner credentials empty — a single inbound with an empty PSK
		// makes sing-box reject the WHOLE config. Backfill deterministically from
		// the handshake password so legacy/hand-crafted nodes stay valid and stable.
		if n.ShadowTLS.InnerMethod == "" {
			n.ShadowTLS.InnerMethod = SS2022AES128
		}
		if n.ShadowTLS.InnerPassword == "" {
			n.ShadowTLS.InnerPassword = deriveInnerPSK(n.ShadowTLS.Password, n.ShadowTLS.InnerMethod)
		}
	case ProtoForgeDNS:
		if n.ForgeDNS != nil {
			n.ForgeDNS.Adapter = strings.ToLower(n.ForgeDNS.Adapter)
			n.ForgeDNS.Zone = strings.ToLower(strings.TrimSuffix(n.ForgeDNS.Zone, "."))
			if n.ForgeDNS.RRType == "" {
				n.ForgeDNS.RRType = "TXT"
			}
			n.ForgeDNS.RRType = strings.ToUpper(n.ForgeDNS.RRType)
			if n.ForgeDNS.EDNSBuffer == 0 {
				n.ForgeDNS.EDNSBuffer = 1232
			}
		}
	}

	if n.Multiplex != nil && !n.Multiplex.Enabled {
		n.Multiplex = nil
	}
}

// clearIrrelevant zeroes transport fields that do not apply to the network.
func (t *Transport) clearIrrelevant() {
	keepHeaderObfs := false
	switch t.Network {
	case NetWS, NetHTTPUpgrade:
		*t = Transport{
			Network: t.Network, Path: t.Path, Host: t.Host,
			Headers: t.Headers, EarlyData: t.EarlyData, EDHeader: t.EDHeader,
		}
	case NetGRPC:
		*t = Transport{
			Network: t.Network, ServiceName: t.ServiceName, MultiMode: t.MultiMode,
			IdleTimeout: t.IdleTimeout, HealthCheckTimeout: t.HealthCheckTimeout,
			InitialWindows: t.InitialWindows, PermitWithout: t.PermitWithout,
			Host: t.Host,
		}
	case NetXHTTP:
		*t = Transport{
			Network: t.Network, Path: t.Path, Host: t.Host, Headers: t.Headers,
			XHTTPMode: t.XHTTPMode, XPaddingB: t.XPaddingB, XMux: t.XMux,
			XPaddingObfsMode: t.XPaddingObfsMode, XPaddingKey: t.XPaddingKey,
			XPaddingHeader: t.XPaddingHeader, XPaddingPlacement: t.XPaddingPlacement,
			XPaddingMethod: t.XPaddingMethod,
			NoGRPCHeader:   t.NoGRPCHeader, NoSSEHeader: t.NoSSEHeader,
			SCMaxEachPostBytes: t.SCMaxEachPostBytes, SCMinPostsIntervalMs: t.SCMinPostsIntervalMs,
			SCMaxBufferedPosts: t.SCMaxBufferedPosts, SCStreamUpServerSecs: t.SCStreamUpServerSecs,
			SessionPlacement: t.SessionPlacement, SessionKey: t.SessionKey,
			SeqPlacement: t.SeqPlacement, SeqKey: t.SeqKey,
			UplinkDataPlacement: t.UplinkDataPlacement, UplinkDataKey: t.UplinkDataKey,
			UplinkHTTPMethod: t.UplinkHTTPMethod, UplinkChunkSize: t.UplinkChunkSize,
			ServerMaxHeaderBytes: t.ServerMaxHeaderBytes, XHTTPDownload: t.XHTTPDownload,
		}
		t.normalizeXHTTP()
	case NetH2:
		*t = Transport{Network: t.Network, Path: t.Path, Host: t.Host, H2Hosts: t.H2Hosts, Headers: t.Headers}
	case NetMKCP:
		keepHeaderObfs = true
		*t = Transport{
			Network: t.Network, Seed: t.Seed, MTU: t.MTU, TTI: t.TTI,
			UplinkCap: t.UplinkCap, DownlinkCap: t.DownlinkCap,
			Congestion: t.Congestion, ReadBufSize: t.ReadBufSize,
			WriteBufSize: t.WriteBufSize, HeaderObfs: t.HeaderObfs,
		}
	case NetQUIC:
		keepHeaderObfs = true
		*t = Transport{
			Network: t.Network, QUICSecurity: t.QUICSecurity, QUICKey: t.QUICKey,
			HeaderObfs: t.HeaderObfs,
		}
	case NetTCP:
		keepHeaderObfs = true
		*t = Transport{Network: t.Network, HeaderObfs: t.HeaderObfs, Host: t.Host, Path: t.Path}
	}
	if !keepHeaderObfs {
		t.HeaderObfs = nil
	}
	if t.HeaderObfs != nil && t.HeaderObfs.Type == "" {
		t.HeaderObfs = nil
	}
	if len(t.Headers) == 0 {
		t.Headers = nil
	}
}

// clearIrrelevantProtocolBlocks nils every extension block that does not belong
// to the node's protocol, and clears credential fields the protocol never uses.
func (n *Node) clearIrrelevantProtocolBlocks() {
	keep := func(p Protocol) bool { return n.Protocol == p }
	if !keep(ProtoHysteria2) {
		n.Hysteria2 = nil
	}
	if !keep(ProtoTUIC) {
		n.TUIC = nil
	}
	if !keep(ProtoAnyTLS) {
		n.AnyTLS = nil
	}
	if !keep(ProtoWireGuard) {
		n.WireGuard = nil
	}
	if !keep(ProtoShadowTLS) {
		n.ShadowTLS = nil
	}
	if !keep(ProtoSSH) {
		n.SSH = nil
	}
	if !keep(ProtoBrook) {
		n.Brook = nil
	} else if n.Brook != nil {
		// Brook's WebSocket modes have a default path, and it has to be written
		// down in ONE place. brook's own server default is /ws, brookArgs
		// substituted it, and the exported link substituted it too — so a node
		// stored with an empty path was served on /ws and linked on /ws while
		// the model said "". Round-tripping that link then produced a node that
		// differed from the one exported, in a field nobody had set. Filling it
		// here makes the model agree with what is actually served.
		switch n.Brook.Mode {
		case "wsserver", "wssserver":
			if strings.TrimSpace(n.Brook.Path) == "" {
				n.Brook.Path = "/ws"
			} else if !strings.HasPrefix(n.Brook.Path, "/") {
				n.Brook.Path = "/" + n.Brook.Path
			}
		case "quicserver":
			// brook quicserver has no --path; carrying one would be a setting
			// that reaches nothing.
			n.Brook.Path = ""
		}
	}
	if !keep(ProtoForgeDNS) {
		n.ForgeDNS = nil
	}
	if !keep(ProtoShadowsocks) {
		n.SSPlugin = nil
		n.Method = ""
	}
	// Credential hygiene: only the fields the protocol actually uses survive.
	switch n.Protocol {
	case ProtoVLESS:
		n.Password, n.Username, n.AlterID = "", "", 0
	case ProtoVMess:
		n.Password, n.Username = "", ""
	case ProtoTrojan, ProtoAnyTLS, ProtoBrook, ProtoHysteria2:
		n.UUID, n.Username, n.Flow, n.Encryption, n.AlterID = "", "", "", "", 0
	case ProtoTUIC:
		n.Username, n.Flow, n.Encryption, n.AlterID = "", "", "", 0
	case ProtoShadowsocks:
		n.UUID, n.Username, n.Flow, n.Encryption, n.AlterID = "", "", "", "", 0
	case ProtoSOCKS, ProtoHTTP:
		n.UUID, n.Flow, n.Encryption, n.AlterID = "", "", "", 0
	case ProtoWireGuard, ProtoSSH, ProtoShadowTLS, ProtoForgeDNS:
		n.UUID, n.Password, n.Username, n.Flow, n.Encryption, n.AlterID = "", "", "", "", "", 0
	}
}

// Clone returns a deep copy, so callers can mutate without aliasing.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	c := *n
	c.Transport = n.Transport.clone()
	c.Security = n.Security.clone()
	if n.Multiplex != nil {
		m := *n.Multiplex
		if n.Multiplex.Brutal != nil {
			b := *n.Multiplex.Brutal
			m.Brutal = &b
		}
		c.Multiplex = &m
	}
	if n.Hysteria2 != nil {
		v := *n.Hysteria2
		c.Hysteria2 = &v
	}
	if n.TUIC != nil {
		v := *n.TUIC
		c.TUIC = &v
	}
	if n.AnyTLS != nil {
		v := *n.AnyTLS
		v.PaddingScheme = append([]string(nil), n.AnyTLS.PaddingScheme...)
		c.AnyTLS = &v
	}
	if n.WireGuard != nil {
		v := *n.WireGuard
		v.LocalAddress = append([]string(nil), n.WireGuard.LocalAddress...)
		v.AllowedIPs = append([]string(nil), n.WireGuard.AllowedIPs...)
		v.Reserved = append([]int(nil), n.WireGuard.Reserved...)
		c.WireGuard = &v
	}
	if n.AmneziaWG != nil {
		v := *n.AmneziaWG
		v.LocalAddress = append([]string(nil), n.AmneziaWG.LocalAddress...)
		v.AllowedIPs = append([]string(nil), n.AmneziaWG.AllowedIPs...)
		v.Reserved = append([]int(nil), n.AmneziaWG.Reserved...)
		c.AmneziaWG = &v
	}
	if n.ShadowTLS != nil {
		v := *n.ShadowTLS
		c.ShadowTLS = &v
	}
	if n.SSH != nil {
		v := *n.SSH
		v.HostKeyAlgorithms = append([]string(nil), n.SSH.HostKeyAlgorithms...)
		c.SSH = &v
	}
	if n.Brook != nil {
		v := *n.Brook
		c.Brook = &v
	}
	if n.ForgeDNS != nil {
		v := *n.ForgeDNS
		c.ForgeDNS = &v
	}
	if n.SSPlugin != nil {
		v := *n.SSPlugin
		c.SSPlugin = &v
	}
	return &c
}

func (t Transport) clone() Transport {
	c := t
	if t.Headers != nil {
		c.Headers = make(map[string]string, len(t.Headers))
		for k, v := range t.Headers {
			c.Headers[k] = v
		}
	}
	c.H2Hosts = append([]string(nil), t.H2Hosts...)
	if t.HeaderObfs != nil {
		h := *t.HeaderObfs
		c.HeaderObfs = &h
	}
	if t.XMux != nil {
		x := *t.XMux
		c.XMux = &x
	}
	c.XHTTPDownload = t.XHTTPDownload.clone()
	return c
}

func (s Security) clone() Security {
	c := s
	c.ALPN = append([]string(nil), s.ALPN...)
	c.PinSHA256 = append([]string(nil), s.PinSHA256...)
	if s.Reality != nil {
		r := *s.Reality
		r.ServerNames = append([]string(nil), s.Reality.ServerNames...)
		r.ShortIDs = append([]string(nil), s.Reality.ShortIDs...)
		c.Reality = &r
	}
	if s.ECH != nil {
		e := *s.ECH
		c.ECH = &e
	}
	return c
}

// SNI returns the effective server name for TLS: the explicit SNI, else the
// transport Host, else the address.
// ExportSNI is the server name a CLIENT should present.
//
// REALITY accepts a ClientHello only if its SNI is one of reality.serverNames,
// so a link built from ServerName when that name is not in the list advertises
// an SNI the server refuses: the client reports "reality verification failed"
// and the inbound looks broken while being perfectly healthy. Measured on a live
// panel — an inbound with server_name=slashdot.org and
// serverNames=[www.cloudflare.com] produced a link that could not connect, and
// the identical client with www.cloudflare.com connected immediately.
//
// An SNI that IS in the list is the operator's own choice and is kept: several
// borrowed names is the normal REALITY setup.
//
// It lives on Security rather than on Node because the URI exporter reaches the
// security block directly and never goes through Node.SNI() — which is exactly
// how the first version of this fix ended up in a function the broken path does
// not call.
func (s Security) ExportSNI() string {
	if s.Type == SecReality && s.Reality != nil {
		names := s.Reality.ServerNames
		if len(names) > 0 && !containsStr(names, s.ServerName) {
			return names[0]
		}
	}
	return s.ServerName
}

func (n *Node) SNI() string {
	// REALITY decides on the SERVER's terms. The inbound accepts a ClientHello
	// only if its SNI is one of reality.serverNames, so a share link built from
	// Security.ServerName when that name is not in the list advertises an SNI
	// the server will refuse — the client reports "reality verification failed"
	// and the inbound looks broken while being perfectly healthy.
	//
	// Measured on a live panel: an imported inbound carried
	// server_name=slashdot.org with serverNames=[www.cloudflare.com]. The link
	// the panel handed out could not connect; the same client with
	// www.cloudflare.com connected immediately.
	//
	// Normalize adopts the single serverName as the SNI when none is set, which
	// covers inbounds the panel creates. It cannot do so when an SNI IS set —
	// that would silently discard an operator's choice — so the export path has
	// to prefer a name the server actually accepts.
	if sni := n.Security.ExportSNI(); sni != "" {
		return sni
	}
	if n.Transport.Host != "" {
		return n.Transport.Host
	}
	return n.Address
}

func containsStr(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
