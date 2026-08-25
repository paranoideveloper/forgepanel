package model

// The single authority for "which engine serves this protocol".
//
// This mapping used to exist in three hand-maintained copies —
// render.EngineFor, core.engineFor and the integration harness's Case.Engine —
// each a switch statement, each carrying the comment that it was "kept in sync
// deliberately". They were not in sync:
//
//	protocol   render.EngineFor   core.engineFor   harness
//	forgedns   "forgedns"         ""  (missing)    "unknown" (missing)
//	unknown    "unknown"          ""               "unknown"
//
// A ForgeDNS inbound therefore resolved to a real engine in the renderer and to
// no engine at all in the manager. Drift like that does not announce itself; it
// surfaces as "why did my inbound never start". The copies also justified
// themselves with an import cycle that does not exist — internal/core/engine
// already imports render.
//
// The table lives here, in model, because model is the lowest layer: it defines
// Protocol and imports neither render nor core, so every caller can depend on it
// without a cycle. TestEveryProtocolHasAnEngine makes a new protocol that
// forgets its engine a build failure rather than a runtime mystery.

// Engine identifiers. These strings are load-bearing: they are compared in
// core.Controller, surfaced through the API's protocol metadata, and used as
// docker-compose profile names in internal/deploy.
const (
	EngineXray      = "xray"
	EngineSingBox   = "sing-box"
	EngineAmneziaWG = "amneziawg"
	EngineBrook     = "brook"
	EngineForgeDNS  = "forgedns"
	// EngineUnknown is returned for a protocol with no mapping. It is a
	// deliberate sentinel rather than "": an empty engine reads like "no engine
	// needed" at a call site, which is how the forgedns drift stayed invisible.
	EngineUnknown = "unknown"
)

// engineByProtocol is the authority. Add a protocol here in the same change
// that adds the constant, or the test below fails.
var engineByProtocol = map[Protocol]string{
	// Xray serves the classic TCP-oriented protocol family.
	ProtoVLESS:       EngineXray,
	ProtoVMess:       EngineXray,
	ProtoTrojan:      EngineXray,
	ProtoShadowsocks: EngineXray,
	ProtoSOCKS:       EngineXray,
	ProtoHTTP:        EngineXray,

	// sing-box serves the QUIC/UDP generation and the TLS-camouflage family.
	// WireGuard is here as a sing-box wireguard ENDPOINT — the only correct form
	// in sing-box >= 1.13, and a real standard-interoperable WG server, which
	// xray's WireGuard inbound is not.
	ProtoHysteria2: EngineSingBox,
	ProtoTUIC:      EngineSingBox,
	ProtoAnyTLS:    EngineSingBox,
	ProtoShadowTLS: EngineSingBox,
	ProtoSSH:       EngineSingBox,
	ProtoWireGuard: EngineSingBox,

	// AmneziaWG runs in KERNEL mode via the amneziawg module + awg-quick. It is
	// its own engine and never sing-box: routing it to sing-box would silently
	// select the userspace implementation and lose kernel-speed obfuscation.
	ProtoAmneziaWG: EngineAmneziaWG,

	ProtoBrook:    EngineBrook,
	ProtoForgeDNS: EngineForgeDNS,
}

// EngineFor reports which engine serves a protocol, or EngineUnknown.
func EngineFor(p Protocol) string {
	if e, ok := engineByProtocol[p]; ok {
		return e
	}
	return EngineUnknown
}

// EngineForNode is the node-shaped convenience the core manager wants.
func EngineForNode(n *Node) string {
	if n == nil {
		return EngineUnknown
	}
	return EngineFor(n.Protocol)
}

// ProtocolsForEngine lists the protocols an engine serves, in AllProtocols
// order so output is stable.
func ProtocolsForEngine(engine string) []Protocol {
	var out []Protocol
	for _, p := range AllProtocols() {
		if EngineFor(p) == engine {
			out = append(out, p)
		}
	}
	return out
}

// SupportsEgress reports whether an inbound of this protocol can actually be
// chained through an upstream hop.
//
// This exists because "accepted and ignored" was the real behaviour for most of
// the protocol list. Egress is implemented by writing an extra outbound plus a
// per-inbound routing rule into the engine's own config, so only the two engines
// that HAVE a routing table can honour it:
//
//	xray       yes — outbounds[] + routing.rules[].inboundTag
//	sing-box   yes — outbounds[] + route.rules[].inbound  (except endpoints)
//	amneziawg  no  — a kernel WireGuard device; routing is the peer's allowed-ips
//	brook      no  — one process per inbound, no routing table at all
//	forgedns   no  — a DNS server, not a traffic path
//
// WireGuard is the subtle one: it is a sing-box protocol, but it renders as an
// ENDPOINT rather than an inbound, and an endpoint has no tag for a route rule
// to match. A chain set on it could never apply.
//
// Returning false here is what turns a silent leak into a refusal the operator
// can see: the traffic an operator asked to relay would otherwise have left the
// machine directly, which is the one outcome a chain exists to prevent.
func SupportsEgress(p Protocol) bool {
	if p == ProtoWireGuard {
		return false
	}
	switch EngineFor(p) {
	case EngineXray, EngineSingBox:
		return true
	default:
		return false
	}
}
