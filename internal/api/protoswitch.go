package api

// Easy protocol switching.
//
// ROUTES TO REGISTER in Server.routes() (no file here edits server.go):
//
//	POST /api/protocols/switch/preview  ->  s.handleProtocolSwitchPreview  (this file)
//	GET  /api/deploy/compose            ->  s.handleDeployCompose          (deploy_compose.go)
//
// Both are stateless generators: they read the request, compute, and return.
// Neither touches the database, the supervisor, or Docker. The switch preview in
// particular MUST NOT mutate anything -- it exists so an operator can see what a
// protocol change would cost before committing to it.
//
// Why a preview at all: switching protocol is not an edit, it is a rebuild. The
// canonical model (model.Node) allows only the fields its protocol uses, so a
// switch necessarily drops some fields and mints new credentials. Showing that
// up front is the difference between "the panel changed a dropdown" and "every
// client link for this inbound just became invalid".

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// FieldChange describes one field's fate in a protocol switch.
//
// Value is populated ONLY for non-secret fields (remark, address, port, SNI,
// security type, transport). A switch summary is rendered in the UI and logged,
// so credential entries carry a Kind ("uuid", "password", "psk"...) and NEVER a
// value -- that is also why regeneration is reported as a kind, not a secret.
type FieldChange struct {
	Field string `json:"field"`
	Value string `json:"value,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Why   string `json:"why,omitempty"`
}

// PortRequirement is one L4 listener the switched node needs. Range is set
// instead of Port for a Hysteria2 port-hopping span.
type PortRequirement struct {
	Proto string `json:"proto"` // tcp | udp
	Port  int    `json:"port,omitempty"`
	Range string `json:"range,omitempty"`
	Note  string `json:"note,omitempty"`
}

// SwitchSummary is the compatibility report for one protocol switch.
type SwitchSummary struct {
	FromProtocol  string            `json:"from_protocol"`
	ToProtocol    string            `json:"to_protocol"`
	FromEngine    string            `json:"from_engine"`
	ToEngine      string            `json:"to_engine"`
	EngineChanged bool              `json:"engine_changed"`
	Retained      []FieldChange     `json:"retained"`
	Reset         []FieldChange     `json:"reset"`
	Regenerated   []FieldChange     `json:"regenerated"`
	RequiredPorts []PortRequirement `json:"required_ports"`
	Warnings      []string          `json:"warnings,omitempty"`
}

func (s *SwitchSummary) retain(field, value, why string) {
	s.Retained = append(s.Retained, FieldChange{Field: field, Value: value, Why: why})
}

func (s *SwitchSummary) reset(field, why string) {
	s.Reset = append(s.Reset, FieldChange{Field: field, Why: why})
}

// SwitchProtocol rebuilds a node under a different protocol. It is pure: src is
// never modified (it is cloned first), and the returned node is a freshly built
// target node carrying only the fields the target can actually use, completed by
// the same applyCreateDefaults the create endpoint runs and canonicalised by
// Normalize.
//
// The retain/reset rule is deliberately conservative: a field survives only when
// the TARGET protocol (with its resulting transport and security) genuinely uses
// it. Credentials are never carried -- not even between two protocols that share
// a field name -- because a credential is bound to the protocol that minted it.
func SwitchProtocol(src *model.Node, target model.Protocol) (*model.Node, SwitchSummary) {
	target = model.Protocol(strings.ToLower(strings.TrimSpace(string(target))))

	// Clone before touching anything; cur is ours to consume, so handing its
	// sub-structs to out below cannot alias the caller's node.
	cur := &model.Node{}
	if src != nil {
		cur = src.Clone()
	}
	cur.Normalize()

	sum := SwitchSummary{
		FromProtocol: string(cur.Protocol), ToProtocol: string(target),
		FromEngine: render.EngineFor(cur.Protocol), ToEngine: render.EngineFor(target),
	}
	sum.EngineChanged = sum.FromEngine != sum.ToEngine

	// Switching to the protocol the node already speaks is a no-op, not a
	// rebuild: churning its credentials would invalidate every issued client link
	// for nothing. Defaults still run so a half-filled node is completed.
	if target == cur.Protocol && knownProtocol(target) {
		applyCreateDefaults(cur)
		sum.retain("*", "", "the target protocol is unchanged; nothing is reset or regenerated")
		sum.RequiredPorts = requiredPorts(cur)
		sum.Warnings = switchWarnings(cur, cur, &sum)
		return cur, sum
	}

	out := &model.Node{Protocol: target}

	// --- identity: labels describe the inbound, not the wire protocol ---
	out.Tag, out.Remark = cur.Tag, cur.Remark
	if cur.Remark != "" {
		sum.retain("remark", cur.Remark, "a label says nothing about the wire protocol")
	}
	if cur.Tag != "" {
		sum.retain("tag", cur.Tag, "the engine tag identifies the inbound, not its protocol")
	}
	if cur.Address != "" {
		out.Address = cur.Address
		sum.retain("address", cur.Address, "the node still lives on the same host")
	}

	// --- port ---
	switch {
	case cur.Port == 0:
	case target == model.ProtoForgeDNS:
		out.Port = 53
		sum.reset("port", "forgedns answers on the delegated DNS port, not an arbitrary one")
	default:
		out.Port = cur.Port
		sum.retain("port", strconv.Itoa(cur.Port), "same listener port -- but check required_ports: the L4 protocol may change")
	}

	// --- transport ---
	switch {
	case !target.UsesTransport():
		if cur.Protocol.UsesTransport() && cur.Transport.Network != model.NetTCP {
			sum.reset("transport", string(target)+" carries its own wire format; a pluggable stream transport does not apply")
		}
	case !cur.Protocol.UsesTransport():
		// Nothing meaningful to carry over; Normalize will default to tcp.
	case removedNetwork(cur.Transport.Network):
		sum.reset("transport", "transport "+string(cur.Transport.Network)+" was removed from the pinned engine; falling back to tcp")
	default:
		out.Transport = cur.Transport
		sum.retain("transport.network", string(cur.Transport.Network), "the transport layer is orthogonal to the protocol")
	}

	// --- security ---
	applySecurity(cur, out, target, &sum)

	// --- credentials: minted, never copied ---
	for _, f := range credentialFields(cur.Protocol) {
		if !usesCredential(target, f.Field) {
			sum.reset(f.Field, string(target)+" has no "+f.Kind+"; carrying one across protocols would produce an unusable inbound")
		}
	}
	if cur.Flow != "" && target != model.ProtoVLESS {
		sum.reset("flow", "xtls-rprx-vision is a VLESS-only flow")
	}
	for _, blk := range protocolBlocks(cur) {
		if blk != string(target) {
			sum.reset(blk, "protocol-specific options belong to "+blk+" only")
		}
	}

	// applyCreateDefaults is the panel's single source of truth for what a fresh
	// node of each protocol needs (credentials, REALITY material, ciphers). It is
	// reused here rather than duplicated so a switched node is indistinguishable
	// from a freshly created one; it ends with Normalize, which clears whatever
	// the target protocol cannot express.
	applyCreateDefaults(out)

	for _, f := range credentialFields(target) {
		f.Why = "minted fresh for " + string(target) + "; credentials never cross protocols"
		sum.Regenerated = append(sum.Regenerated, f)
	}
	sum.RequiredPorts = requiredPorts(out)
	sum.Warnings = switchWarnings(cur, out, &sum)
	return out, sum
}

// applySecurity decides which TLS layer the target keeps. The SNI and the
// certificate follow the DOMAIN, not the protocol, so they survive any switch
// that ends up TLS-ish. REALITY material survives only when the target keeps
// REALITY (see supportsReality) -- it is bound to the listener's steal-site
// handshake, not to the protocol riding on it.
func applySecurity(cur, out *model.Node, target model.Protocol, sum *SwitchSummary) {
	keepTLSIdentity := func() {
		out.Security.ServerName = cur.Security.ServerName
		out.Security.Fingerprint = cur.Security.Fingerprint
		out.Security.CertificateFile = cur.Security.CertificateFile
		out.Security.KeyFile = cur.Security.KeyFile
		out.Security.AllowInsecure = cur.Security.AllowInsecure
		if cur.Security.ServerName != "" {
			sum.retain("security.server_name", cur.Security.ServerName, "the SNI and its certificate belong to the domain, not the protocol")
		}
		if len(cur.Security.ALPN) > 0 {
			sum.reset("security.alpn", "ALPN is protocol-specific (h3 for QUIC, h2/http1.1 for TLS) and is re-derived")
		}
	}

	switch {
	// TLS-native protocols: Normalize forces security=tls, so keeping the SNI is
	// the only decision left.
	case target.IsQUICBased() || target == model.ProtoAnyTLS:
		out.Security.Type = model.SecTLS
		keepTLSIdentity()
		if cur.Security.Type == model.SecReality {
			sum.reset("security.reality", "REALITY is a TCP stream security; "+string(target)+" does its own TLS handshake")
		}

	case cur.Security.Type == model.SecReality && supportsReality(target, out.Transport.Network):
		out.Security = cur.Security // cur is a local clone; no aliasing with the caller
		sum.retain("security.type", string(model.SecReality), "REALITY is a stream security shared by the V2Ray-family protocols")
		if r := cur.Security.Reality; r != nil && r.Dest != "" {
			sum.retain("security.reality.dest", r.Dest, "the steal-site and its keys belong to the listener, not the protocol")
		}

	case supportsStreamTLS(target) && cur.Security.Type != model.SecNone:
		out.Security.Type = model.SecTLS
		keepTLSIdentity()
		if cur.Security.Type == model.SecReality {
			sum.reset("security.reality", "REALITY is carried forward only for the VLESS/VMess family; this switch falls back to TLS and drops the keypair, shortIds and dest")
		} else {
			sum.retain("security.type", string(model.SecTLS), "the target keeps a pluggable TLS layer")
		}

	default:
		if cur.Security.Type != model.SecNone {
			sum.reset("security", string(target)+" does not carry a pluggable TLS layer")
		}
	}
}

// switchWarnings collects the operational consequences an operator must act on.
func switchWarnings(cur, out *model.Node, sum *SwitchSummary) []string {
	var w []string
	if sum.EngineChanged {
		w = append(w, "engine changes from "+sum.FromEngine+" to "+sum.ToEngine+": the inbound moves to a different core process")
	}
	if l4(cur) != l4(out) {
		w = append(w, "listener changes from "+l4(cur)+" to "+l4(out)+": firewall and NAT rules must be updated")
	}
	// The panel can mint a credential but it cannot invent a DNS delegation, so
	// this is the one gap a switch always hands back to the operator.
	if out.Protocol == model.ProtoForgeDNS && (out.ForgeDNS == nil || out.ForgeDNS.Zone == "") {
		w = append(w, "forgedns needs a delegated zone and an adapter; set forgedns.zone before saving")
	}
	if cur.Protocol != out.Protocol {
		w = append(w, "every existing client link for this inbound stops working: re-issue subscriptions after applying")
	}
	return w
}

// l4 summarises a node's transport-layer protocols, for the "your firewall rule
// is now wrong" warning.
func l4(n *model.Node) string {
	seen := map[string]bool{}
	var parts []string
	for _, p := range requiredPorts(n) {
		if !seen[p.Proto] {
			seen[p.Proto] = true
			parts = append(parts, p.Proto)
		}
	}
	return strings.Join(parts, "+")
}

// requiredPorts reports the L4 listeners a node needs. This is what a firewall,
// a security group or a generated compose file has to open.
func requiredPorts(n *model.Node) []PortRequirement {
	var out []PortRequirement
	add := func(proto, note string) {
		out = append(out, PortRequirement{Proto: proto, Port: n.Port, Note: note})
	}
	switch n.Protocol {
	case model.ProtoHysteria2, model.ProtoTUIC:
		add("udp", "QUIC-based: the listener is UDP only")
	case model.ProtoWireGuard:
		add("udp", "WireGuard is UDP only")
	case model.ProtoForgeDNS:
		add("udp", "DNS queries")
		add("tcp", "DNS-over-TCP fallback for answers that do not fit")
	case model.ProtoShadowsocks:
		add("tcp", "")
		add("udp", "Shadowsocks relays UDP on the same port")
	case model.ProtoSOCKS:
		add("tcp", "")
		add("udp", "UDP ASSOCIATE")
	case model.ProtoBrook:
		mode := ""
		if n.Brook != nil {
			mode = n.Brook.Mode
		}
		switch mode {
		case "quicserver":
			add("udp", "brook quicserver is UDP only")
		case "wsserver", "wssserver":
			add("tcp", "")
		default:
			add("tcp", "")
			add("udp", "brook server relays UDP on the same port")
		}
	default:
		add("tcp", "")
	}
	if n.Protocol == model.ProtoHysteria2 && n.Hysteria2 != nil && n.Hysteria2.PortHopping != "" {
		out = append(out, PortRequirement{
			Proto: "udp", Range: n.Hysteria2.PortHopping,
			Note: "the port-hopping range must reach the listener (in-kernel DNAT, or a published range)",
		})
	}
	return out
}

// credentialFields reports which credential fields a protocol uses, as
// (field, kind) pairs. This is the ONLY place the switch decides what a
// protocol's identity is made of, which is what keeps a uuid from ever being
// written into a password slot.
func credentialFields(p model.Protocol) []FieldChange {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess:
		return []FieldChange{{Field: "uuid", Kind: "uuid"}}
	case model.ProtoTrojan, model.ProtoHysteria2, model.ProtoAnyTLS, model.ProtoBrook:
		return []FieldChange{{Field: "password", Kind: "password"}}
	case model.ProtoTUIC:
		return []FieldChange{{Field: "uuid", Kind: "uuid"}, {Field: "password", Kind: "password"}}
	case model.ProtoShadowsocks:
		return []FieldChange{{Field: "method", Kind: "cipher"}, {Field: "password", Kind: "pre-shared key"}}
	case model.ProtoShadowTLS:
		return []FieldChange{
			{Field: "shadowtls.password", Kind: "password"},
			{Field: "shadowtls.inner_password", Kind: "pre-shared key"},
		}
	case model.ProtoSSH:
		return []FieldChange{{Field: "ssh.user", Kind: "username"}, {Field: "ssh.password", Kind: "password"}}
	case model.ProtoWireGuard:
		return []FieldChange{
			{Field: "wireguard.private_key", Kind: "x25519 keypair"},
			{Field: "wireguard.peer_private_key", Kind: "x25519 peer keypair"},
		}
	default:
		// socks/http take optional credentials, forgedns takes none.
		return nil
	}
}

func usesCredential(p model.Protocol, field string) bool {
	for _, f := range credentialFields(p) {
		if f.Field == field {
			return true
		}
	}
	return false
}

// protocolBlocks names the protocol-specific option blocks a node carries, so
// the summary can say which one is being dropped.
func protocolBlocks(n *model.Node) []string {
	blocks := []struct {
		present bool
		name    model.Protocol
	}{
		{n.Hysteria2 != nil, model.ProtoHysteria2}, {n.TUIC != nil, model.ProtoTUIC},
		{n.AnyTLS != nil, model.ProtoAnyTLS}, {n.WireGuard != nil, model.ProtoWireGuard},
		{n.ShadowTLS != nil, model.ProtoShadowTLS}, {n.SSH != nil, model.ProtoSSH},
		{n.Brook != nil, model.ProtoBrook}, {n.ForgeDNS != nil, model.ProtoForgeDNS},
	}
	var out []string
	for _, b := range blocks {
		if b.present {
			out = append(out, string(b.name))
		}
	}
	return out
}

// supportsStreamTLS reports whether a protocol carries a PLUGGABLE TLS layer in
// its stream settings. Shadowsocks is excluded on purpose: its TLS story is
// ShadowTLS or a SIP003 plugin, not a stream-level tls block.
func supportsStreamTLS(p model.Protocol) bool {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoSOCKS, model.ProtoHTTP:
		return true
	}
	return false
}

// supportsReality reports where a REALITY layer is carried FORWARD by a switch.
// The transport rule mirrors model.Validate (RAW(tcp)/XHTTP/gRPC only). The
// protocol rule is deliberately narrower than what the engine would accept: an
// Xray inbound can technically wrap REALITY around Trojan too, but client
// support for that is patchy, so an automatic switch downgrades to plain TLS and
// tells the operator they can re-enable REALITY by hand. Keeping it silently
// would produce an inbound whose links most clients cannot dial.
func supportsReality(p model.Protocol, net model.Network) bool {
	switch p {
	case model.ProtoVLESS, model.ProtoVMess:
	default:
		return false
	}
	switch net {
	case model.NetTCP, model.NetXHTTP, model.NetGRPC, "":
		return true
	}
	return false
}

// removedNetwork reports transports the pinned Xray no longer has (mirrors the
// guards in model.Validate), so a switch never carries one forward.
func removedNetwork(n model.Network) bool {
	return n == model.NetH2 || n == model.NetQUIC || n == model.NetMKCP
}

func knownProtocol(p model.Protocol) bool {
	for _, k := range model.AllProtocols() {
		if k == p {
			return true
		}
	}
	return false
}

// --- POST /api/protocols/switch/preview -----------------------------------

// SwitchPreviewRequest is the preview payload: the node as it stands today and
// the protocol the operator is considering.
type SwitchPreviewRequest struct {
	Node           *model.Node    `json:"node"`
	TargetProtocol model.Protocol `json:"target_protocol"`
}

// SwitchPreviewResponse pairs the compatibility summary with the node the switch
// would produce. Valid/Error report model.Validate on that node, so the UI can
// disable "apply" for a switch that cannot produce a working inbound.
type SwitchPreviewResponse struct {
	Summary SwitchSummary `json:"summary"`
	Node    *model.Node   `json:"node"`
	Valid   bool          `json:"valid"`
	Error   string        `json:"error,omitempty"`
}

func (s *Server) handleProtocolSwitchPreview(c *gin.Context) {
	var req SwitchPreviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "bad JSON: "+err.Error())
		return
	}
	if req.Node == nil {
		fail(c, 400, "node is required")
		return
	}
	target := model.Protocol(strings.ToLower(strings.TrimSpace(string(req.TargetProtocol))))
	if !knownProtocol(target) {
		fail(c, 400, "unknown target protocol: "+string(req.TargetProtocol))
		return
	}
	preview, sum := SwitchProtocol(req.Node, target)
	resp := SwitchPreviewResponse{Summary: sum, Node: preview, Valid: true}
	if err := preview.Validate(); err != nil {
		resp.Valid, resp.Error = false, err.Error()
	}
	c.JSON(200, resp)
}
