package api

import (
	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Field describes one form input. Key is a dot-path into the canonical node JSON
// (e.g. "uuid", "security.reality.dest", "hysteria2.obfs_type") so the frontend
// can render every option a protocol supports and build the node generically.
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`              // text, number, bool, textarea, select, iselect (int select), csv ([]string), csvint ([]int)
	Options  []string `json:"options,omitempty"` // for select
	Default  any      `json:"default,omitempty"`
	Keygen   string   `json:"keygen,omitempty"`   // reality|uuid|shortid|ss2022|wireguard|password
	Ph       string   `json:"placeholder,omitempty"`
	Help     string   `json:"help,omitempty"`
}

// ProtoSchema is the complete form schema for one protocol.
type ProtoSchema struct {
	Proto      string  `json:"proto"`
	Label      string  `json:"label"`
	Engine     string  `json:"engine"`
	Fields     []Field `json:"fields"`      // credentials + protocol options
	Transports []string `json:"transports"` // empty => no transport layer
	Securities []string `json:"securities"`
}

// handleSchema returns the full field schema so the UI can render every option
// of every protocol — the single source of truth for "what can be created".
func (s *Server) handleSchema(c *gin.Context) {
	fps := model.ValidFingerprints()
	// Only transports Xray 26 actually supports. h2/quic/mKCP were removed and
	// produce an unstartable config (verified against the running core), so they
	// are not offered — xhttp replaces h2/quic for the CDN/HTTP use cases.
	transports := []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
	securities := []string{"none", "tls", "reality"}

	c.JSON(200, gin.H{
		"protocols":  protocolSchemas(transports, securities),
		"transports": transportFields(),
		"securities": securityFields(fps),
		"fingerprints": fps,
	})
}

func protocolSchemas(transports, securities []string) []ProtoSchema {
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
			{Key: "hysteria2.port_hopping", Label: "Port hopping", Type: "text", Ph: "20000-50000"},
			{Key: "hysteria2.masquerade_type", Label: "Masquerade", Type: "select", Options: []string{"", "proxy", "file", "string"}},
			{Key: "hysteria2.masquerade_url", Label: "Masquerade URL", Type: "text"},
		}},
		{Proto: "tuic", Label: "TUIC", Engine: "sing-box", Securities: []string{"tls"}, Fields: []Field{
			{Key: "uuid", Label: "UUID", Type: "text", Keygen: "uuid"},
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "tuic.congestion_control", Label: "Congestion", Type: "select", Options: []string{"bbr", "cubic", "new_reno"}, Default: "bbr"},
			{Key: "tuic.udp_relay_mode", Label: "UDP relay", Type: "select", Options: []string{"native", "quic"}, Default: "native"},
			{Key: "tuic.zero_rtt_handshake", Label: "Zero-RTT", Type: "bool"},
		}},
		{Proto: "anytls", Label: "AnyTLS", Engine: "sing-box", Securities: []string{"tls"}, Fields: []Field{
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "anytls.idle_session_timeout", Label: "Idle timeout (s)", Type: "number"},
		}},
		{Proto: "shadowtls", Label: "ShadowTLS", Engine: "sing-box", Fields: []Field{
			{Key: "shadowtls.version", Label: "Version", Type: "iselect", Options: []string{"3", "2", "1"}, Default: 3},
			{Key: "shadowtls.password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "shadowtls.handshake_host", Label: "Handshake host", Type: "text", Ph: "www.apple.com", Default: "www.apple.com"},
			{Key: "shadowtls.handshake_port", Label: "Handshake port", Type: "number", Default: 443},
		}},
		{Proto: "wireguard", Label: "WireGuard", Engine: "xray", Fields: []Field{
			{Key: "wireguard.private_key", Label: "Private key", Type: "text", Keygen: "wireguard"},
			{Key: "wireguard.public_key", Label: "Peer public key", Type: "text"},
			{Key: "wireguard.local_address", Label: "Address (comma-sep)", Type: "csv", Ph: "10.0.0.2/32"},
			{Key: "wireguard.mtu", Label: "MTU", Type: "number", Default: 1420},
			{Key: "wireguard.reserved", Label: "Reserved (WARP)", Type: "csvint", Ph: "0,0,0"},
		}},
		// NOTE: SSH is intentionally NOT a creatable inbound. sing-box implements
		// SSH only as an OUTBOUND (routing THROUGH an SSH server); there is no SSH
		// inbound/server in sing-box (that role belongs to sshd). SSH stays in the
		// model for outbound/import/export use, just not in the create-inbound form.
		{Proto: "brook", Label: "Brook", Engine: "brook", Fields: []Field{
			{Key: "brook.mode", Label: "Mode", Type: "select", Options: []string{"server", "wsserver", "wssserver", "quicserver"}, Default: "server", Help: "server=raw TCP/UDP; ws=WebSocket; wss=WebSocket+TLS; quic=QUIC"},
			{Key: "password", Label: "Password", Type: "text", Keygen: "password"},
			{Key: "brook.path", Label: "Path (ws/wss)", Type: "text", Default: "/ws"},
		}},
	}
}

// transportFields returns the extra fields each transport needs.
func transportFields() map[string][]Field {
	return map[string][]Field{
		"tcp": {},
		"ws": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/", Ph: "/ws"},
			{Key: "transport.host", Label: "Host", Type: "text"},
		},
		"httpupgrade": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/"},
			{Key: "transport.host", Label: "Host", Type: "text"},
		},
		"grpc": {
			{Key: "transport.service_name", Label: "Service name", Type: "text", Ph: "grpcsvc"},
			{Key: "transport.multi_mode", Label: "Multi mode", Type: "bool"},
		},
		"xhttp": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/"},
			{Key: "transport.host", Label: "Host", Type: "text"},
			{Key: "transport.xhttp_mode", Label: "Mode", Type: "select", Options: []string{"auto", "packet-up", "stream-up", "stream-one"}, Default: "auto"},
		},
		"h2": {
			{Key: "transport.path", Label: "Path", Type: "text", Default: "/"},
			{Key: "transport.host", Label: "Host", Type: "text"},
		},
		"kcp": {
			{Key: "transport.seed", Label: "Seed", Type: "text"},
		},
		"quic": {},
	}
}

// securityFields returns the fields each security layer needs.
func securityFields(fps []string) map[string][]Field {
	return map[string][]Field{
		"none": {},
		"tls": {
			{Key: "security.server_name", Label: "SNI", Type: "text"},
			{Key: "security.fingerprint", Label: "uTLS fingerprint", Type: "select", Options: fps, Default: "chrome"},
			{Key: "security.alpn", Label: "ALPN (comma-sep)", Type: "csv", Ph: "h2,http/1.1"},
			{Key: "security.allow_insecure", Label: "Allow insecure (auto for self-signed)", Type: "bool"},
		},
		"reality": {
			{Key: "security.reality.dest", Label: "Dest / steal-site", Type: "text", Default: "www.cloudflare.com:443", Help: "avoid microsoft.com; use cloudflare/apple/google"},
			{Key: "security.server_name", Label: "SNI (matches dest)", Type: "text", Default: "www.cloudflare.com"},
			{Key: "security.fingerprint", Label: "uTLS fingerprint", Type: "select", Options: fps, Default: "chrome"},
			{Key: "security.reality.private_key", Label: "Private key", Type: "text", Keygen: "reality", Help: "auto-generated if empty"},
			{Key: "security.reality.public_key", Label: "Public key", Type: "text"},
			{Key: "security.reality.short_id", Label: "Short ID", Type: "text", Keygen: "shortid"},
		},
	}
}
