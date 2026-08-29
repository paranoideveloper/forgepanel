package api

// Coverage guard: every transport option the MODEL carries must be reachable
// from the form, or be explicitly documented as deliberately not offered.
//
// XHTTP is why this exists. The model carried the complete modern XHTTP surface
// — padding shape, session and sequence carriage, uplink shaping, the sc* flow
// control limits, xmux, and the whole split download leg — and the form exposed
// four fields. Everything else could be set through the API and arrived through
// imported share links, but the panel that owned the inbound could neither show
// it nor change it, and rebuilding the node from the form silently dropped it.
//
// Nothing catches that class of gap: the Go tests pass (the model is correct),
// the Svelte tests pass (the form renders what it was given), and the config the
// core receives is valid. Only a comparison of the two sides finds it.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// schemaKeys collects every Field.Key the schema offers anywhere.
func schemaKeys() map[string]bool {
	out := map[string]bool{}
	add := func(fs []Field) {
		for _, f := range fs {
			out[f.Key] = true
		}
	}
	for _, fs := range transportFields() {
		add(fs)
	}
	for _, fs := range securityFields(model.ValidFingerprints()) {
		add(fs)
	}
	for _, ps := range protocolSchemas([]string{"tcp"}, []string{"none"}) {
		add(ps.Fields)
	}
	add(commonFields())
	return out
}

// jsonTags returns the json tag names of a struct's fields, recursing into
// nested structs with the dot-path the schema uses.
//
// An ANONYMOUS embedded struct is flattened, because that is what encoding/json
// does: AmneziaWGOptions embeds WireGuardOptions, so "amneziawg.allowed_ips" is
// a real key in a stored node. Skipping it — which this did, since an embedded
// field carries no json tag of its own — made every inherited field invisible to
// the guard, which is precisely how AmneziaWG shipped with no control for the
// tunnel address, the preshared key or the keepalive that its exported client
// config writes out.
func jsonTags(t reflect.Type, prefix string) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if f.Anonymous && tag == "" && f.Type.Kind() == reflect.Struct {
			out = append(out, jsonTags(f.Type, prefix)...)
			continue
		}
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, prefix+tag)
	}
	return out
}

// notOffered documents transport options the panel deliberately does not expose.
// Every entry needs a reason: an unexplained one is how this guard gets quietly
// neutered by the next person who wants a green run.
var notOffered = map[string]string{
	// h2, QUIC and mKCP were REMOVED from Xray 26. Offering their knobs would
	// build a config the core refuses to start — verified with `xray run -test`.
	"transport.h2_hosts":          "h2 removed in Xray 26; xhttp replaces it",
	"transport.seed":              "mKCP removed in Xray 26",
	"transport.mtu":               "mKCP removed in Xray 26",
	"transport.tti":               "mKCP removed in Xray 26",
	"transport.uplink_capacity":   "mKCP removed in Xray 26",
	"transport.downlink_capacity": "mKCP removed in Xray 26",
	"transport.congestion":        "mKCP removed in Xray 26",
	"transport.read_buffer_size":  "mKCP removed in Xray 26",
	"transport.write_buffer_size": "mKCP removed in Xray 26",
	// NOT an exemption any more, and the reason it used to carry was simply
	// untrue: tcp is the FIRST transport the form offers, xrayStream renders its
	// http header camouflage, and both share-link exporters carry it. The entry
	// said the feature was "only reachable on transports Xray 26 dropped", which
	// is how a guard designed to catch unreachable options was talked into
	// ignoring the one that really was unreachable. Header has a single field
	// now and it is offered; this line only skips the CONTAINER.
	"transport.header": "container; transport.header.type is the field",

	"transport.quic_security": "QUIC removed in Xray 26",
	"transport.quic_key":      "QUIC removed in Xray 26",

	// Structural, not operator-set.
	"transport.network": "chosen by the Transport selector, not a field",
}

func TestEveryTransportOptionIsReachableFromTheForm(t *testing.T) {
	keys := schemaKeys()
	if len(keys) < 40 {
		t.Fatalf("only %d schema keys found — the scan is broken, not the schema", len(keys))
	}

	var missing []string
	for _, tag := range jsonTags(reflect.TypeOf(model.Transport{}), "transport.") {
		if keys[tag] || notOffered[tag] != "" {
			continue
		}
		// Nested structs are covered by their own dot-path fields below.
		if tag == "transport.xmux" || tag == "transport.download_settings" {
			continue
		}
		missing = append(missing, tag)
	}
	if len(missing) > 0 {
		t.Fatalf("%d transport option(s) exist in the model but have no control in the form, so they "+
			"can be set through the API and then neither seen nor changed in the panel:\n  - %s\n\n"+
			"Add a Field for each, or document it in notOffered with the reason it cannot be offered.",
			len(missing), strings.Join(missing, "\n  - "))
	}
}

// xmux and the split download leg are whole structs the form must cover, and
// they are the two an operator most often needs: connection reuse, and
// "upload through the CDN, download direct".
func TestXMuxAndDownloadLegAreFullyReachable(t *testing.T) {
	keys := schemaKeys()
	for _, c := range []struct {
		typ    reflect.Type
		prefix string
	}{
		{reflect.TypeOf(model.XMux{}), "transport.xmux."},
		{reflect.TypeOf(model.XHTTPDownload{}), "transport.download_settings."},
	} {
		for _, tag := range jsonTags(c.typ, c.prefix) {
			// The download leg's transport and security are whole nested layers;
			// the schema exposes the subset that is meaningful on a second leg,
			// each with its own dot-path key, so the container itself is not a
			// field.
			if tag == "transport.download_settings.transport" || tag == "transport.download_settings.security" {
				continue
			}
			if !keys[tag] {
				t.Errorf("%s has no control in the form", tag)
			}
		}
	}
}

// The download leg is useless without a way to say where it goes and how it is
// protected. These are the keys an operator actually needs to fill in.
func TestDownloadLegExposesItsTransportAndSecurity(t *testing.T) {
	keys := schemaKeys()
	for _, k := range []string{
		"transport.download_settings.address",
		"transport.download_settings.port",
		"transport.download_settings.transport.network",
		"transport.download_settings.security.type",
		"transport.download_settings.security.server_name",
		"transport.download_settings.security.reality.public_key",
	} {
		if !keys[k] {
			t.Errorf("%s has no control in the form", k)
		}
	}
}

// A chain must be offered exactly where it can be honoured. Offering it
// elsewhere tells the operator traffic is relayed when it leaves directly.
func TestChainIsOfferedOnlyWhereItIsHonoured(t *testing.T) {
	for _, ps := range protocolSchemas([]string{"tcp"}, []string{"none"}) {
		want := model.SupportsEgress(model.Protocol(ps.Proto))
		if ps.Chainable != want {
			t.Errorf("%s advertises chainable=%v, but the builder says %v", ps.Proto, ps.Chainable, want)
		}
	}
	// WireGuard renders as a sing-box ENDPOINT, which has no tag for a route
	// rule to match, so a chain on it could never apply.
	for _, ps := range protocolSchemas([]string{"tcp"}, []string{"none"}) {
		if ps.Proto == string(model.ProtoWireGuard) && ps.Chainable {
			t.Errorf("wireguard must not offer a chain: an endpoint cannot be routed per-inbound")
		}
	}
}

// Every select the schema offers must match the values the core accepts. A
// stale option list is a save that fails with a core error the operator cannot
// act on.
func TestXHTTPSelectOptionsMatchTheCore(t *testing.T) {
	byKey := map[string][]string{}
	for _, f := range xhttpFields() {
		if f.Type == "select" {
			byKey[f.Key] = f.Options
		}
	}
	for key, want := range map[string][]string{
		"transport.xhttp_mode":            model.AllXHTTPModes(),
		"transport.x_padding_placement":   model.AllXHTTPPaddingPlacements(),
		"transport.x_padding_method":      model.AllXHTTPPaddingMethods(),
		"transport.session_placement":     model.AllXHTTPPlacements(),
		"transport.seq_placement":         model.AllXHTTPPlacements(),
		"transport.uplink_data_placement": model.AllXHTTPUplinkDataPlacements(),
		"transport.uplink_http_method":    model.AllXHTTPUplinkMethods(),
	} {
		got, ok := byKey[key]
		if !ok {
			t.Errorf("%s is not a select in the schema", key)
			continue
		}
		for _, v := range want {
			found := false
			for _, g := range got {
				if g == v {
					found = true
				}
			}
			if !found {
				t.Errorf("%s does not offer %q, which the core accepts", key, v)
			}
		}
		// And nothing the core would reject.
		for _, g := range got {
			if g == "" {
				continue // the "unset" entry
			}
			found := false
			for _, v := range want {
				if g == v {
					found = true
				}
			}
			if !found {
				t.Errorf("%s offers %q, which the core rejects", key, g)
			}
		}
	}
}

// notOfferedSecurity documents security options the panel deliberately does not
// expose, with the reason. Same contract as notOffered.
var notOfferedSecurity = map[string]string{
	"security.type": "chosen by the Security selector, not a field",
	// Set by the panel's own certificate management, not typed by an operator:
	// pointing an inbound at an arbitrary path would bypass renewal and the
	// inbound would silently start serving an expired certificate.
	"security.certificate_file": "managed by the panel's certificate store",
	"security.key_file":         "managed by the panel's certificate store",
	// Server-side REALITY key material is generated, never typed.
	"security.reality.private_key": "generated by the panel; the keygen button fills it",
	// ML-DSA-65 post-quantum REALITY is disabled by design; interoperable
	// clients cannot use it today. See docs/DECISIONS.md ADR-007.
	"security.reality.mldsa65_seed":   "post-quantum REALITY disabled by design (ADR-007)",
	"security.reality.mldsa65_verify": "post-quantum REALITY disabled by design (ADR-007)",
}

func TestEverySecurityOptionIsReachableFromTheForm(t *testing.T) {
	keys := schemaKeys()
	var missing []string
	check := func(typ reflect.Type, prefix string, skip map[string]bool) {
		for _, tag := range jsonTags(typ, prefix) {
			if keys[tag] || notOfferedSecurity[tag] != "" || skip[tag] {
				continue
			}
			missing = append(missing, tag)
		}
	}
	check(reflect.TypeOf(model.Security{}), "security.", map[string]bool{
		// Nested layers, covered by their own dot-path fields below.
		"security.reality": true, "security.ech": true,
	})
	check(reflect.TypeOf(model.Reality{}), "security.reality.", nil)
	check(reflect.TypeOf(model.ECH{}), "security.ech.", nil)

	if len(missing) > 0 {
		t.Fatalf("%d security option(s) exist in the model but have no control in the form:\n  - %s\n\n"+
			"Add a Field for each, or document it in notOfferedSecurity with the reason.",
			len(missing), strings.Join(missing, "\n  - "))
	}
}

// notOfferedProtocol documents protocol options the panel deliberately does not
// expose, with the reason. Same contract as notOffered.
//
// There was no guard on this side at all, which is how three options an operator
// would reasonably expect to set — AmneziaWG's reserved bytes and tunnel address,
// and Hysteria2's Brutal preset — stayed reachable only through the API for as
// long as they existed. The transport and security layers had a guard each; the
// protocol layer, which has by far the most fields, had none.
var notOfferedProtocol = map[string]string{
	// Provisioned by the panel, never typed. A WireGuard/AmneziaWG tunnel only
	// works if both key pairs and both tunnel addresses agree, so the panel mints
	// them together; letting an operator type one half is how a tunnel ends up
	// with a peer whose key matches nothing.
	"wireguard.peer_private_key": "minted by the panel with its matching public key",
	"wireguard.peer_public_key":  "minted by the panel with its matching private key",
	"wireguard.peer_address":     "allocated by the panel from the tunnel subnet",
	"wireguard.peers":            "derived from the users assigned to the inbound, not stored on it",
	"amneziawg.peer_private_key": "minted by the panel with its matching public key",
	"amneziawg.peer_public_key":  "minted by the panel with its matching private key",
	"amneziawg.peer_address":     "allocated by the panel from the tunnel subnet",
	"amneziawg.peers":            "derived from the users assigned to the inbound, not stored on it",
	"shadowtls.inner_method":     "minted by the panel for the inner Shadowsocks inbound",
	"shadowtls.inner_password":   "minted by the panel for the inner Shadowsocks inbound",

	// Legacy shapes kept only so old stored nodes and old links still load.
	"hysteria2.masquerade_type": "legacy; Normalize migrates it into masquerade.type",
	"hysteria2.masquerade_url":  "legacy; Normalize migrates it into masquerade.url",

	// local_address is the DIALER's own tunnel address: the parser fills it from
	// a wireguard:// link, and the URI/Clash exporters and the xray outbound read
	// it back. On an inbound the panel is the server, so the two addresses that
	// mean anything are server_address and peer_address, and both are offered or
	// allocated. Showing local_address as well would be a third control that
	// changes what a client link says without changing what the server does.
	"wireguard.local_address": "the dialer's own address; an inbound uses server_address/peer_address",
	"amneziawg.local_address": "the dialer's own address; an inbound uses server_address/peer_address",

	// AmneziaWG runs in KERNEL mode through awg-quick, whose config format has
	// no line for either of these. Reserved is a WARP header trick that only the
	// USERSPACE WireGuard implementations in xray and sing-box apply, and Workers
	// is the sing-box endpoint's goroutine count. Offering them on a kernel
	// interface would be two controls that change nothing.
	"amneziawg.reserved": "awg-quick has no Reserved; it is a userspace-only WARP header",
	"amneziawg.workers":  "worker count belongs to the sing-box endpoint, not a kernel interface",

	// Nested structs covered by their own dot-path fields.
	"hysteria2.masquerade": "container; its fields are offered individually",
}

// TestEveryProtocolOptionIsReachableFromTheForm is the protocol-layer twin of
// TestEveryTransportOptionIsReachableFromTheForm.
func TestEveryProtocolOptionIsReachableFromTheForm(t *testing.T) {
	keys := schemaKeys()
	// Only protocols the form can actually create. A protocol no core serves as
	// an inbound has no form to be reachable from, and demanding fields for it
	// would force controls that build an inbound which cannot start.
	served := map[string]bool{}
	for _, ps := range protocolSchemaList([]string{"tcp"}, []string{"none"}) {
		served[ps.Proto] = true
	}

	cases := []struct {
		proto  string
		typ    reflect.Type
		prefix string
	}{
		{"hysteria2", reflect.TypeOf(model.Hysteria2Options{}), "hysteria2."},
		{"hysteria2", reflect.TypeOf(model.Hy2Masquerade{}), "hysteria2.masquerade."},
		{"tuic", reflect.TypeOf(model.TUICOptions{}), "tuic."},
		{"anytls", reflect.TypeOf(model.AnyTLSOptions{}), "anytls."},
		{"wireguard", reflect.TypeOf(model.WireGuardOptions{}), "wireguard."},
		{"amneziawg", reflect.TypeOf(model.AmneziaWGOptions{}), "amneziawg."},
		{"shadowtls", reflect.TypeOf(model.ShadowTLSOptions{}), "shadowtls."},
		{"brook", reflect.TypeOf(model.BrookOptions{}), "brook."},
		{"shadowsocks", reflect.TypeOf(model.SSPluginOptions{}), "ss_plugin."},
	}

	var missing []string
	for _, c := range cases {
		if !served[c.proto] {
			continue
		}
		for _, tag := range jsonTags(c.typ, c.prefix) {
			if keys[tag] || notOfferedProtocol[tag] != "" {
				continue
			}
			missing = append(missing, tag)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d protocol option(s) exist in the model but have no control in the form, so they "+
			"can be set through the API and then neither seen nor changed in the panel:\n  - %s\n\n"+
			"Add a Field for each, or document it in notOfferedProtocol with the reason it cannot be offered.",
			len(missing), strings.Join(missing, "\n  - "))
	}
}

// The schema payload used to advertise field definitions for h2, kcp and quic
// while handleSchema offered none of them, because the offered list and the
// field map were written out separately. model.Validate rejects all three, so
// anything built from those fields was a guaranteed 400 — a form the panel's own
// API refuses. Neither list is wrong on its own; only comparing them finds it.
func TestTheFormOffersExactlyTheTransportsItShipsFieldsFor(t *testing.T) {
	fields := transportFields()
	offered := map[string]bool{}
	for _, n := range offeredTransports() {
		offered[n] = true
		if _, ok := fields[n]; !ok {
			t.Errorf("transport %q is offered but the payload carries no field definitions for it", n)
		}
	}
	for n := range fields {
		if !offered[n] {
			t.Errorf("the payload ships fields for transport %q, which the form never offers", n)
		}
	}
	// And every offered transport must be one the core will actually start.
	for _, n := range offeredTransports() {
		node := &model.Node{
			Protocol: model.ProtoVLESS, Address: "example.com", Port: 443,
			UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.Network(n)},
		}
		node.Normalize()
		if err := node.Validate(); err != nil {
			t.Errorf("the form offers transport %q, which the panel then refuses: %v", n, err)
		}
	}
}
