package core

// Verification coverage for the protocol matrix.
//
// internal/core/matrix_test.go validates generated configs against the REAL
// cores (xray -test / sing-box check), which is the strongest evidence the
// panel has that a config it produces is one a core would actually accept. But
// that matrix only exercised 24 variants across 9 protocols, while the panel
// advertises 15. ShadowTLS, SSH and WireGuard were rendered by the panel and
// never once fed to a core; Brook, AmneziaWG and ForgeDNS cannot be fed to one
// at all.
//
// Two problems with that. The obvious one is missing coverage. The subtler one
// is that nothing distinguished "not covered because nobody got to it" from
// "not coverable, for a real technical reason" — so a protocol could quietly
// join the advertised list with zero verification and no one would notice.
//
// TestValidationCoverageIsComplete closes that: every advertised protocol must
// either be exercised against a real core, or carry an explicit, justified
// exclusion. Adding a protocol without doing one of the two fails the build.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/cert"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// advertisedButUnservable records protocols the panel offers that NO engine can
// actually serve as an inbound. This is a defect list, not an exclusion list:
// every entry is a protocol an operator can select and create, and which will
// then silently never carry traffic.
//
// SSH: verified against sing-box 1.13.2 — `sing-box check` on an inbound of
// type "ssh" fails with `unknown inbound type: ssh`. sing-box implements SSH as
// an OUTBOUND only; there is no SSH inbound in any released version. ForgePanel
// nevertheless lists ProtoSSH in AllProtocols(), maps it to the sing-box engine,
// labels it in /api/protocols and offers it in the create form, so the inbound
// is created and then skipped at render time with "no sing-box inbound here".
// Tracked as a gap; resolving it means either serving SSH through the host's
// own sshd or withdrawing it from the advertised set.
var advertisedButUnservable = map[model.Protocol]string{
	model.ProtoSSH: "sing-box 1.13.2 rejects inbounds of type \"ssh\" (unknown inbound type); " +
		"SSH exists only as a sing-box outbound, so no engine can serve an SSH inbound",
}

// notCoreValidatable records protocols that ARE served, but by something other
// than xray/sing-box, so `xray -test` and `sing-box check` cannot see them.
// These are exclusions with proof, not omissions — the distinction the brief
// demands between "not covered" and "not coverable".
var notCoreValidatable = map[model.Protocol]string{
	model.ProtoAmneziaWG: "runs in kernel mode via the amneziawg module and awg-quick; " +
		"it produces a wg-quick .conf, not an xray or sing-box document, so neither core can parse it",
	model.ProtoBrook: "supervised as an external brook process driven by CLI flags (GPL-3.0, never linked); " +
		"it has no xray/sing-box config document to validate",
	model.ProtoForgeDNS: "served by ForgePanel's own DNS-tunnel engine (internal/forgedns); " +
		"there is no third-party core to hand a config to",
}

// extendedMatrix covers the protocols and transports fullMatrix never fed to a
// core. Ports start above fullMatrix's range so the two can coexist.
func extendedMatrix(t *testing.T) []*model.Node {
	t.Helper()
	uuid := "b831381d-6324-4d53-ad4f-8cda48b30811"
	psk256, err := keygen.SS2022PSK(model.SS2022AES256)
	if err != nil {
		t.Fatalf("ss2022 psk: %v", err)
	}
	wg, err := keygen.WireGuardKeys()
	if err != nil {
		t.Fatalf("wireguard keys: %v", err)
	}
	peer, err := keygen.WireGuardKeys()
	if err != nil {
		t.Fatalf("wireguard peer keys: %v", err)
	}
	tlsSec := func() model.Security {
		return model.Security{Type: model.SecTLS, ServerName: "forgepanel.local"}
	}
	port := 30000
	np := func() int { port++; return port }
	mk := func(remark string, n *model.Node) *model.Node {
		n.Remark = remark
		n.Address = "0.0.0.0"
		n.Port = np()
		n.Normalize()
		return n
	}

	return []*model.Node{
		// --- sing-box protocols that were advertised but never core-validated ---
		mk("shadowtls-v3", &model.Node{Protocol: model.ProtoShadowTLS,
			ShadowTLS: &model.ShadowTLSOptions{
				Version: 3, Password: "stlspw", HandshakeHost: "www.microsoft.com", HandshakePort: 443,
				InnerMethod: string(model.SS2022AES256), InnerPassword: psk256,
			}}),
		mk("wireguard-endpoint", &model.Node{Protocol: model.ProtoWireGuard,
			WireGuard: &model.WireGuardOptions{
				PrivateKey: wg.PrivateKey, PublicKey: wg.PublicKey,
				ServerAddress:  []string{"10.66.66.1/24"},
				PeerPrivateKey: peer.PrivateKey, PeerPublicKey: peer.PublicKey,
				PeerAddress: []string{"10.66.66.2/32"},
				AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
			}}),

		// --- transport combinations the original matrix skipped ---
		mk("vless-tcp-plain", &model.Node{Protocol: model.ProtoVLESS, UUID: uuid,
			Transport: model.Transport{Network: model.NetTCP}}),
		mk("vmess-httpupgrade-tls", &model.Node{Protocol: model.ProtoVMess, UUID: uuid,
			Transport: model.Transport{Network: model.NetHTTPUpgrade, Path: "/hu", Host: "forgepanel.local"},
			Security:  tlsSec()}),
		mk("trojan-xhttp-tls", &model.Node{Protocol: model.ProtoTrojan, Password: "trojanpw",
			Transport: model.Transport{Network: model.NetXHTTP, Path: "/xh", XHTTPMode: "auto"},
			Security:  tlsSec()}),
	}
}

// validateNodes renders each node and runs the real core validator on it,
// returning the per-node verdicts. Shared by the tests below.
func validateNodes(t *testing.T, nodes []*model.Node) (passed []string, failures []string) {
	t.Helper()
	dir := t.TempDir()
	ctrl := NewController(dir, 10199)
	cp, kp, err := cert.EnsureSelfSigned(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	if _, err := ctrl.bins.Ensure(binmgr.EngineXray); err != nil {
		t.Skipf("xray binary unavailable, cannot validate against a real core: %v", err)
	}
	if _, err := ctrl.bins.Ensure(binmgr.EngineSingbox); err != nil {
		t.Skipf("sing-box binary unavailable, cannot validate against a real core: %v", err)
	}
	for _, n := range nodes {
		b, err := engine.BuildMulti([]engine.InboundSpec{{Node: n}}, 10199, cp, kp)
		if err != nil {
			failures = append(failures, n.Remark+": build: "+err.Error())
			continue
		}
		if len(b.Skipped) > 0 {
			failures = append(failures, n.Remark+": SKIPPED: "+b.Skipped[0].Reason)
			continue
		}
		// Validate through the adapter the panel itself dispatches to, so this
		// suite exercises the product's validation path rather than one the
		// test assembles — the difference that let the adapter layer sit
		// unmounted while every test passed.
		res, resErr := ctrl.Registry().ResolveNode(n)
		if resErr != nil {
			failures = append(failures, n.Remark+": no adapter: "+resErr.Error())
			continue
		}
		cfg, genErr := res.Adapter.GenerateConfig([]*model.Node{n})
		if genErr != nil {
			failures = append(failures, n.Remark+" ["+res.Engine+"]: generate: "+genErr.Error())
			continue
		}
		if err := res.Adapter.ValidateConfig(cfg); err != nil {
			failures = append(failures, n.Remark+" ["+res.Engine+"]: "+err.Error())
			continue
		}
		passed = append(passed, n.Remark+" ["+res.Engine+"]")
	}
	return passed, failures
}

// The protocols and transports fullMatrix never validated against a core.
func TestExtendedMatrixValidates(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the engine binaries")
	}
	nodes := extendedMatrix(t)
	passed, failures := validateNodes(t, nodes)
	for _, p := range passed {
		t.Logf("✓ %s valid", p)
	}
	if len(failures) > 0 {
		t.Fatalf("%d/%d extended variants failed real-core validation:\n  - %s",
			len(failures), len(nodes), strings.Join(failures, "\n  - "))
	}
	t.Logf("ALL %d extended variants passed xray -test / sing-box check", len(nodes))
}

// Every advertised protocol must be either core-validated or explicitly, and
// justifiably, excluded. This is the guard that stops a protocol from joining
// the advertised list with no verification behind it.
func TestValidationCoverageIsComplete(t *testing.T) {
	covered := map[model.Protocol]bool{}
	for _, n := range append(fullMatrix(t), extendedMatrix(t)...) {
		covered[n.Protocol] = true
	}
	for _, p := range model.AllProtocols() {
		if covered[p] {
			continue
		}
		if defect, known := advertisedButUnservable[p]; known {
			t.Logf("! %s ADVERTISED BUT UNSERVABLE (tracked defect): %s", p, defect)
			continue
		}
		reason, excluded := notCoreValidatable[p]
		if !excluded {
			t.Errorf("protocol %q is advertised by AllProtocols() but is never validated against a real "+
				"core, and carries no documented exclusion. Add it to extendedMatrix, to "+
				"notCoreValidatable (served by another engine), or to advertisedButUnservable "+
				"(a defect: the panel offers something nothing can serve).", p)
			continue
		}
		if len(reason) < 40 {
			t.Errorf("protocol %q is excluded from core validation with an inadequate reason: %q", p, reason)
		}
		t.Logf("— %s excluded from core validation: %s", p, reason)
	}
	// An exclusion for a protocol that IS covered is stale bookkeeping and will
	// mislead the next reader.
	for p := range notCoreValidatable {
		if covered[p] {
			t.Errorf("protocol %q is listed in notCoreValidatable but IS covered by the matrix; remove the exclusion", p)
		}
	}
}
