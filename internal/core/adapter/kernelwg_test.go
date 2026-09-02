package adapter

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func wgNode(engine string) *model.Node {
	n := &model.Node{
		Protocol: model.ProtoWireGuard, Address: "203.0.113.9", Port: 51820,
		Engine: engine,
		WireGuard: &model.WireGuardOptions{
			PrivateKey: "SRV-PRIV", PublicKey: "SRV-PUB",
			PeerPublicKey: "CLI-PUB", PeerPrivateKey: "CLI-PRIV",
			ServerAddress: []string{"10.66.66.1/24"}, PeerAddress: []string{"10.66.66.2/32"},
			MTU: 1420, Keepalive: 25,
		},
	}
	n.Normalize()
	return n
}

// TestWireGuardDefaultsToSingboxAndOptsIntoTheKernel is the whole contract of
// the per-inbound engine override.
//
// The registry has supported EngineChoice since it was written and nothing set
// the hook, so Node.Engine could be stored and was never consulted. Both halves
// are asserted here: the default is unchanged for every existing inbound, and
// an inbound that names the kernel engine actually reaches it.
func TestWireGuardDefaultsToSingboxAndOptsIntoTheKernel(t *testing.T) {
	r, _, _ := testRegistry(t)
	r.EngineChoice = func(n *model.Node) string { return n.Engine }

	res, err := r.ResolveNode(wgNode(""))
	if err != nil {
		t.Fatalf("default WireGuard does not resolve: %v", err)
	}
	if res.Engine != model.EngineSingBox {
		t.Errorf("default WireGuard went to %q; existing inbounds must not move", res.Engine)
	}
	if res.Overridden {
		t.Error("an inbound with no Engine set is not an override")
	}

	res, err = r.ResolveNode(wgNode(model.EngineKernelWG))
	if err != nil {
		t.Fatalf("WireGuard naming the kernel engine does not resolve: %v", err)
	}
	if res.Engine != model.EngineKernelWG {
		t.Errorf("engine = %q, want the kernel datapath", res.Engine)
	}
	if !res.Overridden {
		t.Error("choosing a non-default core must be reported as an override")
	}
}

// TestKernelEngineRefusesProtocolsItCannotServe: an override is only safe
// because Resolve checks the target engine actually implements the protocol.
// Without it a mistyped choice hands an inbound to a core with no
// implementation, that core rejects its whole config, and every OTHER inbound
// on it stops too.
func TestKernelEngineRefusesProtocolsItCannotServe(t *testing.T) {
	r, _, _ := testRegistry(t)
	r.EngineChoice = func(n *model.Node) string { return n.Engine }

	n := &model.Node{Protocol: model.ProtoVLESS, Address: "a", Port: 443,
		UUID: "11111111-1111-1111-1111-111111111111", Engine: model.EngineKernelWG}
	if _, err := r.ResolveNode(n); err == nil {
		t.Fatal("a VLESS inbound was routed to the kernel WireGuard engine")
	}
}

// TestKernelWGRendersAWgQuickConfig: the kernel adapter must emit a config
// wg-quick can read — and specifically NOT the AmneziaWG one, whose
// obfuscation keys the plain wireguard module rejects.
func TestKernelWGRendersAWgQuickConfig(t *testing.T) {
	a := NewKernelWG(&fakeAWG{})
	cfg, err := a.GenerateConfig([]*model.Node{wgNode(model.EngineKernelWG)})
	if err != nil {
		t.Fatalf("GenerateConfig: %v", err)
	}
	conf := string(cfg)
	for _, want := range []string{"[Interface]", "PrivateKey", "ListenPort", "[Peer]", "AllowedIPs"} {
		if !strings.Contains(conf, want) {
			t.Errorf("rendered config has no %s:\n%s", want, conf)
		}
	}
	// wg-quick fails on any of these; they belong to the amneziawg module only.
	for _, forbidden := range []string{"Jc =", "Jmin =", "H1 =", "S1 =", "HeaderProtectionKey"} {
		if strings.Contains(conf, forbidden) {
			t.Errorf("plain WireGuard config carries the AmneziaWG key %q, which wg-quick rejects:\n%s",
				forbidden, conf)
		}
	}
	// Server-side peers are roaming clients; keepalive belongs in the client conf.
	if strings.Contains(conf, "PersistentKeepalive") {
		t.Errorf("server config sets keepalive on a roaming peer:\n%s", conf)
	}
	if err := a.ValidateConfig(cfg); err != nil {
		t.Errorf("the adapter rejects its own output: %v", err)
	}
}
