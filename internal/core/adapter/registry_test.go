package adapter

import (
	"errors"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

func testRegistry(t *testing.T) (*Registry, *fakeBrook, *fakeAWG) {
	t.Helper()
	brook, awg := &fakeBrook{}, &fakeAWG{}
	r, err := DefaultRegistry(Options{DataDir: t.TempDir(), XrayAPIPort: 10085, Bins: &fakeBins{dir: t.TempDir()}}, brook, awg)
	if err != nil {
		t.Fatalf("DefaultRegistry: %v", err)
	}
	return r, brook, awg
}

// The default registry must cover every protocol the panel can create, so an
// inbound can never be stored, rendered and then silently never started. The
// single exception is ForgeDNS, and it is asserted explicitly rather than
// tolerated: if a future protocol lands with no adapter, this fails and names it.
func TestForgeDNSIsTheOnlyProtocolWithoutAnAdapter(t *testing.T) {
	r, _, _ := testRegistry(t)
	var unadapted []model.Protocol
	for _, p := range model.AllProtocols() {
		if _, err := r.Resolve(p, ""); err != nil {
			unadapted = append(unadapted, p)
		}
	}
	if len(unadapted) != 1 || unadapted[0] != model.ProtoForgeDNS {
		t.Fatalf("protocols with no adapter = %v, want exactly [forgedns] "+
			"(ForgeDNS is a zone-driven DNS service, not an inbound-serving core)", unadapted)
	}
}

// Resolution must agree with the single engine authority. A registry that
// answered anything else would reintroduce the drift model.EngineFor exists to
// prevent, just one layer up.
func TestResolveAgreesWithEngineFor(t *testing.T) {
	r, _, _ := testRegistry(t)
	for _, p := range model.AllProtocols() {
		want := model.EngineFor(p)
		res, err := r.Resolve(p, "")
		if err != nil {
			if want == model.EngineForgeDNS {
				continue
			}
			t.Errorf("Resolve(%s): %v", p, err)
			continue
		}
		if res.Engine != want {
			t.Errorf("Resolve(%s).Engine = %q, want %q", p, res.Engine, want)
		}
		if res.Adapter.Name() != want {
			t.Errorf("Resolve(%s) adapter = %q, want %q", p, res.Adapter.Name(), want)
		}
		if res.Overridden {
			t.Errorf("Resolve(%s) reports an override without one being asked for", p)
		}
	}
}

// This is the FP-ADAPT-002 behaviour: an inbound is matched on BOTH protocol and
// engine, so an engine choice that the chosen core cannot honour is refused
// instead of being handed over and rejected at core startup — which would take
// every other inbound on that core down with it.
func TestResolveRequiresTheEngineToServeTheProtocol(t *testing.T) {
	r, _, _ := testRegistry(t)

	// sing-box is a registered engine, but ForgePanel's sing-box renderer has
	// no VLESS inbound, so routing VLESS there must fail loudly.
	if _, err := r.Resolve(model.ProtoVLESS, model.EngineSingBox); err == nil {
		t.Fatal("routing VLESS to sing-box was accepted; the sing-box renderer has no VLESS inbound, " +
			"so the core would reject the whole config at startup")
	} else {
		var unsup *UnsupportedError
		if !errors.As(err, &unsup) {
			t.Fatalf("error = %v (%T), want *UnsupportedError", err, err)
		}
		if unsup.Engine != model.EngineSingBox || unsup.Protocol != model.ProtoVLESS {
			t.Fatalf("UnsupportedError = %+v, want engine sing-box / protocol vless", unsup)
		}
	}

	// An engine nobody registered is a different failure and must read like one.
	_, err := r.Resolve(model.ProtoVLESS, "hysteria")
	var missing *NoAdapterError
	if !errors.As(err, &missing) {
		t.Fatalf("unregistered engine: error = %v (%T), want *NoAdapterError", err, err)
	}
	if missing.Engine != "hysteria" {
		t.Fatalf("NoAdapterError.Engine = %q, want %q", missing.Engine, "hysteria")
	}

	// And an override that a registered engine CAN honour is accepted, and says
	// so. This is the seam later waves plug alternative cores into.
	alt := &fakeAdapter{name: "alt-core", protos: []model.Protocol{model.ProtoVLESS},
		nets: []model.Network{model.NetTCP}}
	if err := r.Register(alt); err != nil {
		t.Fatal(err)
	}
	res, err := r.Resolve(model.ProtoVLESS, "alt-core")
	if err != nil {
		t.Fatalf("override to a capable engine was refused: %v", err)
	}
	if res.Adapter != CoreAdapter(alt) || !res.Overridden {
		t.Fatalf("Resolve = %+v, want the alt-core adapter with Overridden=true", res)
	}
}

// EngineChoice is what makes "the same protocol on a different core per node"
// possible without a new switch. Without the hook the node still resolves to its
// default engine, which is why wiring it is a no-op until someone sets it.
func TestEngineChoiceHookRedirectsAnInbound(t *testing.T) {
	r, _, _ := testRegistry(t)
	alt := &fakeAdapter{name: "alt-core", protos: []model.Protocol{model.ProtoVLESS},
		nets: []model.Network{model.NetTCP}}
	if err := r.Register(alt); err != nil {
		t.Fatal(err)
	}
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "203.0.113.1", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()

	res, err := r.ResolveNode(n)
	if err != nil {
		t.Fatal(err)
	}
	if res.Engine != model.EngineXray {
		t.Fatalf("with no hook, VLESS resolved to %q, want xray", res.Engine)
	}

	r.EngineChoice = func(*model.Node) string { return "alt-core" }
	res, err = r.ResolveNode(n)
	if err != nil {
		t.Fatal(err)
	}
	if res.Engine != "alt-core" || !res.Overridden {
		t.Fatalf("with the hook set, resolved to %+v, want alt-core with Overridden=true", res)
	}

	// A reload built through the hook must land the inbound on the chosen core
	// and say that it was re-routed, so a mixed node is distinguishable from a
	// default one in the panel.
	plans, bad := r.Partition(specsOf([]*model.Node{n}), testCert, testKey)
	if len(bad) != 0 {
		t.Fatalf("unroutable = %+v, want none", bad)
	}
	for _, ap := range plans {
		want := 0
		if ap.Engine == "alt-core" {
			want = 1
		}
		if len(ap.Plan.Nodes()) != want {
			t.Errorf("%s plan carries %d inbounds, want %d", ap.Engine, len(ap.Plan.Nodes()), want)
		}
		if ap.Overridden != want {
			t.Errorf("%s plan reports %d overridden inbounds, want %d", ap.Engine, ap.Overridden, want)
		}
	}
}

// Resolution matches the transport as well as the protocol. This is what stops
// an engine choice from sending an inbound to a core that renders the protocol
// but cannot carry its transport — the resulting config is one the core refuses
// to load, which takes every other inbound on that core down with it.
//
// The pairing is exercised through an adapter that serves VLESS over a
// restricted transport set, because no core ForgePanel ships today both serves a
// protocol and lacks one of its transports; that combination arrives with the
// first alternative VLESS core.
func TestResolveNodeChecksTheTransport(t *testing.T) {
	r, _, _ := testRegistry(t)
	alt := &fakeAdapter{name: "alt-core", protos: []model.Protocol{model.ProtoVLESS},
		nets: []model.Network{model.NetTCP, model.NetWS}}
	if err := r.Register(alt); err != nil {
		t.Fatal(err)
	}
	r.EngineChoice = func(*model.Node) string { return "alt-core" }

	mk := func(net model.Network, tr model.Transport) *model.Node {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: tr}
		n.Normalize()
		return n
	}
	xh := mk(model.NetXHTTP, model.Transport{Network: model.NetXHTTP, Path: "/xh", XHTTPMode: "auto"})
	if _, err := r.ResolveNode(xh); err == nil {
		t.Fatal("an xhttp inbound was routed to a core that does not carry xhttp")
	} else {
		var unsup *UnsupportedError
		if !errors.As(err, &unsup) || unsup.Network != model.NetXHTTP {
			t.Fatalf("ResolveNode = %v, want an UnsupportedError naming xhttp", err)
		}
	}
	ws := mk(model.NetWS, model.Transport{Network: model.NetWS, Path: "/ws", Host: "a.example.com"})
	if _, err := r.ResolveNode(ws); err != nil {
		t.Fatalf("a ws inbound the core does carry was refused: %v", err)
	}

	// The default route must still accept the xhttp inbound: xray carries it.
	r.EngineChoice = nil
	if _, err := r.ResolveNode(xh); err != nil {
		t.Fatalf("xray refused an xhttp inbound it renders: %v", err)
	}
}

// The declared transport lists are a claim about the renderers, and a claim
// that drifts is worse than none: Supports would reject an inbound the core
// renders fine, or admit one it cannot. This pins each list to what the renderer
// actually accepts, so adding a transport to a renderer without declaring it
// here fails.
func TestDeclaredTransportsMatchTheRenderers(t *testing.T) {
	r, _, _ := testRegistry(t)
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	transportFor := func(net model.Network) model.Transport {
		tr := model.Transport{Network: net, Path: "/p", Host: "a.example.com", ServiceName: "svc"}
		if net == model.NetXHTTP {
			tr.XHTTPMode = "auto"
		}
		return tr
	}
	mk := func(net model.Network) *model.Node {
		n := &model.Node{Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 40000, UUID: uuid,
			Transport: transportFor(net)}
		n.Normalize()
		return n
	}

	cases := []struct {
		engine string
		render func(*model.Node) error
	}{
		{model.EngineXray, func(n *model.Node) error { _, err := render.XrayInbound(n); return err }},
		// sing-box has no VLESS *inbound* renderer, so its transport handling is
		// exercised through the outbound renderer, which runs the same transport
		// mapper. That mapper is the thing this list has to agree with.
		{model.EngineSingBox, func(n *model.Node) error { _, err := render.SingboxOutbound(n); return err }},
	}
	for _, tc := range cases {
		a, ok := r.Lookup(tc.engine)
		if !ok {
			t.Fatalf("%s adapter is not registered", tc.engine)
		}
		for _, net := range model.AllNetworks() {
			declared := containsNetwork(a.SupportedTransports(), net)
			err := tc.render(mk(net))
			if declared && err != nil {
				t.Errorf("%s declares %s but the renderer rejects it: %v", tc.engine, net, err)
			}
			if !declared && err == nil {
				t.Errorf("%s renders %s but does not declare it, so Supports rejects a working inbound", tc.engine, net)
			}
		}
	}
}

// Partition is what a reload is built from: every inbound lands on exactly one
// adapter, nothing is lost, and every adapter is handed a plan even when it is
// empty — an adapter that is skipped when its last inbound is deleted keeps
// serving that inbound forever.
func TestPartitionRoutesEveryInboundAndAlwaysPlansEveryAdapter(t *testing.T) {
	r, _, _ := testRegistry(t)
	nodes := matrixNodes(t)
	plans, bad := r.Partition(specsOf(nodes), testCert, testKey)

	if len(plans) != len(r.Engines()) {
		t.Fatalf("got %d plans for %d adapters; every adapter must get one", len(plans), len(r.Engines()))
	}
	byEngine := map[string]Plan{}
	total := 0
	for _, ap := range plans {
		byEngine[ap.Engine] = ap.Plan
		total += len(ap.Plan.Nodes())
		if ap.Plan.CertPath != testCert || ap.Plan.KeyPath != testKey {
			t.Errorf("%s plan lost the certificate paths", ap.Engine)
		}
	}
	if want := len(nodes) - 1; total != want { // forgedns is unroutable by design
		t.Errorf("plans carry %d inbounds, want %d", total, want)
	}
	if len(bad) != 1 || bad[0].Node.Protocol != model.ProtoForgeDNS {
		t.Fatalf("unroutable = %+v, want exactly the forgedns inbound", bad)
	}

	for _, n := range nodes {
		if n.Protocol == model.ProtoForgeDNS {
			continue
		}
		eng := model.EngineFor(n.Protocol)
		found := false
		for _, got := range byEngine[eng].Nodes() {
			if got == n {
				found = true
			}
		}
		if !found {
			t.Errorf("%s (%s) did not land in the %s plan", n.Remark, n.Protocol, eng)
		}
	}

	// Now drop every inbound and confirm each adapter is still handed a plan,
	// empty, so it knows to stop.
	plans, _ = r.Partition(nil, testCert, testKey)
	if len(plans) != len(r.Engines()) {
		t.Fatalf("empty reload produced %d plans, want one per adapter", len(plans))
	}
	for _, ap := range plans {
		if !ap.Plan.Empty() {
			t.Errorf("%s got a non-empty plan from an empty reload", ap.Engine)
		}
	}
}

// A nil inbound reaches the renderers as a nil pointer dereference. The registry
// drops it as unroutable so one corrupt row cannot take the reload down for
// every other inbound.
func TestPartitionSurvivesANilInbound(t *testing.T) {
	r, _, _ := testRegistry(t)
	nodes := matrixNodes(t)
	specs := append([]engine.InboundSpec{{Node: nil}}, specsOf(nodes)...)
	plans, bad := r.Partition(specs, testCert, testKey)
	if len(bad) != 2 { // the nil spec plus the forgedns inbound
		t.Fatalf("unroutable = %d entries, want 2 (nil spec + forgedns)", len(bad))
	}
	total := 0
	for _, ap := range plans {
		total += len(ap.Plan.Nodes())
	}
	if want := len(nodes) - 1; total != want {
		t.Fatalf("a nil spec cost %d inbounds their plan", want-total)
	}
}

func TestRegisterRejectsUnusableAdapters(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Error("a nil adapter was registered")
	}
	if err := r.Register(&fakeAdapter{name: "", protos: []model.Protocol{model.ProtoVLESS}}); err == nil {
		t.Error("an adapter with no name was registered; it could never be looked up")
	}
	if err := r.Register(&fakeAdapter{name: "empty"}); err == nil {
		t.Error("an adapter serving no protocol was registered; nothing could ever route to it")
	}
	a := &fakeAdapter{name: "dup", protos: []model.Protocol{model.ProtoVLESS}}
	if err := r.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(&fakeAdapter{name: "dup", protos: []model.Protocol{model.ProtoVMess}}); err == nil {
		t.Error("a second adapter claimed an engine name already taken; one of them would be unreachable")
	}
}

// Registration order is the order a reload drives the cores in. An unstable
// order turns an intermittent reload failure into one nobody can reproduce.
func TestRegistrationOrderIsPreserved(t *testing.T) {
	r, _, _ := testRegistry(t)
	want := []string{model.EngineXray, model.EngineSingBox, model.EngineBrook, model.EngineAmneziaWG}
	got := r.Engines()
	if len(got) != len(want) {
		t.Fatalf("engines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("engines = %v, want %v", got, want)
		}
	}
	for i := 0; i < 5; i++ {
		plans, _ := r.Partition(specsOf(matrixNodes(t)), testCert, testKey)
		for j, ap := range plans {
			if ap.Engine != want[j] {
				t.Fatalf("Partition order = %v at index %d, want %v", ap.Engine, j, want[j])
			}
		}
	}
}

func TestDefaultRegistryRefusesMissingRunners(t *testing.T) {
	opts := Options{DataDir: t.TempDir()}
	if _, err := DefaultRegistry(opts, nil, &fakeAWG{}); err == nil {
		t.Error("registry built without a Brook runner; brook inbounds would resolve to nothing")
	}
	if _, err := DefaultRegistry(opts, &fakeBrook{}, nil); err == nil {
		t.Error("registry built without an AmneziaWG runner; awg inbounds would resolve to nothing")
	}
}

// Every adapter whose protocols use the transport stack must declare which
// transports it carries, or Supports silently rejects everything.
func TestAdaptersDeclareTransportsWhenTheirProtocolsUseThem(t *testing.T) {
	r, _, _ := testRegistry(t)
	for _, a := range r.All() {
		usesTransport := false
		for _, p := range a.SupportedProtocols() {
			if p.UsesTransport() {
				usesTransport = true
			}
		}
		if usesTransport && len(a.SupportedTransports()) == 0 {
			t.Errorf("adapter %s serves transport-using protocols but declares no transports", a.Name())
		}
	}
}
