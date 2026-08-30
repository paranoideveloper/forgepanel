package adapter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// This is the load-bearing claim of the whole refactor: splitting a reload
// across adapters produces exactly the bytes the controller produces today from
// one undivided call. If a partitioned render ever differs from the whole-list
// render, adopting the registry silently changes what every core serves.
func TestPartitionedConfigsAreByteIdenticalToTheWholeListRender(t *testing.T) {
	const apiPort = 10085
	nodes := matrixNodes(t)
	specs := specsOf(nodes)
	// A couple of bound users, because per-user client expansion is where the
	// two renders would be most likely to diverge.
	for i := range specs {
		switch specs[i].Node.Protocol {
		case model.ProtoVLESS, model.ProtoVMess:
			specs[i].Clients = []engine.ClientCred{
				{Email: "alice@example.com", UUID: "5e1a1f37-4d3a-4b52-9f2c-0f9a2f4d1c11"},
				{Email: "bob@example.com", UUID: "9c4d6d1e-2c9e-4f31-9a58-2c7d3d0e51aa"},
			}
		case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoAnyTLS:
			specs[i].Clients = []engine.ClientCred{{Email: "carol@example.com", Password: "carolpw"}}
		}
	}

	whole, err := engine.BuildMulti(specs, apiPort, testCert, testKey)
	if err != nil {
		t.Fatalf("whole-list render: %v", err)
	}

	opts := Options{DataDir: t.TempDir(), XrayAPIPort: apiPort, Bins: &fakeBins{dir: t.TempDir()}}
	r, err := DefaultRegistry(opts, &fakeBrook{}, &fakeAWG{})
	if err != nil {
		t.Fatal(err)
	}
	plans, _ := r.Partition(specs, testCert, testKey)

	want := map[string][]byte{model.EngineXray: whole.Xray, model.EngineSingBox: whole.Singbox}
	wantN := map[string]int{model.EngineXray: whole.XrayN, model.EngineSingBox: whole.SingboxN}
	seen := 0
	for _, ap := range plans {
		gen, ok := ap.Adapter.(MultiUserGenerator)
		if !ok {
			continue
		}
		seen++
		cfg, served, _, err := gen.GenerateMultiUser(ap.Plan.Specs, ap.Plan.CertPath, ap.Plan.KeyPath)
		if err != nil {
			t.Fatalf("%s: %v", ap.Engine, err)
		}
		name := ap.Engine
		if served != wantN[name] {
			t.Errorf("%s served %d inbounds, whole-list render served %d", name, served, wantN[name])
		}
		if !bytes.Equal(cfg, want[name]) {
			t.Errorf("%s config differs from the whole-list render:\n--- partitioned ---\n%s\n--- whole ---\n%s",
				name, cfg, want[name])
		}
	}
	if seen != 2 {
		t.Fatalf("%d adapters implement MultiUserGenerator, want 2 (xray, sing-box)", seen)
	}
}

// Brook and AmneziaWG have a single per-inbound secret and no notion of a user
// list, so they must NOT advertise the multi-user capability — a caller that
// type-asserts and gets a yes would expect per-user credentials it will not get.
func TestOnlyTheMultiUserCoresAdvertiseMultiUser(t *testing.T) {
	r, _, _ := testRegistry(t)
	want := map[string]bool{model.EngineXray: true, model.EngineSingBox: true}
	for _, a := range r.All() {
		_, ok := a.(MultiUserGenerator)
		if ok != want[a.Name()] {
			t.Errorf("%s implements MultiUserGenerator = %v, want %v", a.Name(), ok, want[a.Name()])
		}
	}
}

// A plan with no inbounds for a core must not fetch that core's binary. Without
// this, creating the first Hysteria2 inbound on a panel would also download
// Xray, and a panel behind a blocked GitHub would fail a reload over a core it
// does not use.
func TestApplyDoesNotFetchACoreWithNoInbounds(t *testing.T) {
	bins := &fakeBins{dir: t.TempDir()}
	opts := Options{DataDir: t.TempDir(), XrayAPIPort: 10085, Bins: bins}
	a := NewXray(opts)
	if err := a.Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("empty plan: %v", err)
	}
	if calls := bins.calls(); len(calls) != 0 {
		t.Fatalf("an empty plan resolved binaries %v", calls)
	}
	h, _ := a.HealthCheck(context.Background())
	if h.State != StateStopped {
		t.Fatalf("state after an empty plan = %q, want stopped", h.State)
	}
}

// A core that cannot be fetched must fail the apply with the reason, not start
// nothing and report healthy. This is the common failure on a panel behind a
// blocked GitHub, and it has to name the binary.
func TestApplyReportsABinaryThatCannotBeResolved(t *testing.T) {
	bins := &fakeBins{dir: t.TempDir(), err: errors.New("GET https://github.com/...: status 403")}
	a := NewXray(Options{DataDir: t.TempDir(), XrayAPIPort: 10085, Bins: bins})
	nodes := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)
	err := a.Apply(context.Background(), Plan{Specs: specsOf(nodes), CertPath: testCert, KeyPath: testKey})
	if err == nil {
		t.Fatal("apply succeeded with no core binary")
	}
	if !strings.Contains(err.Error(), "xray binary") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %q, want it to name the xray binary and the underlying cause", err)
	}
}

// The core's own validator is the gate. An adapter that applied a config the
// core rejects would take the engine down on a bad edit, which is exactly what
// the supervisor was built to prevent.
func TestApplyRefusesAConfigTheCoreRejects(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), rejectingCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins})

	nodes := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)
	err := a.Apply(context.Background(), Plan{Specs: specsOf(nodes), CertPath: testCert, KeyPath: testKey})
	if err == nil {
		t.Fatal("a config the core rejected was applied")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "engines", "xray.json")); statErr == nil {
		t.Error("the rejected config was written into place; a bad edit would survive a restart")
	}
	h, _ := a.HealthCheck(context.Background())
	if h.State != StateInvalid {
		t.Fatalf("state after a rejected config = %q, want invalid_config", h.State)
	}
	if h.LastError == "" {
		t.Error("a rejected config reported no reason")
	}
}

// End to end through the real supervisor: apply, run, report healthy, stop.
func TestApplyRunsAndStopsTheCore(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins})
	ctx := context.Background()
	t.Cleanup(func() { _ = a.Stop(ctx) })

	nodes := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)
	plan := Plan{Specs: specsOf(nodes), CertPath: testCert, KeyPath: testKey}
	if err := a.Apply(ctx, plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if calls := bins.calls(); len(calls) == 0 || calls[0] != binmgr.EngineXray {
		t.Fatalf("apply resolved %v, want the xray binary", calls)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "engines", "xray.json"))
	if err != nil {
		t.Fatalf("the applied config was not written: %v", err)
	}
	if !bytes.Contains(cfg, []byte(`"port": 30001`)) {
		t.Errorf("the applied config does not carry the inbound:\n%s", cfg)
	}

	waitFor(t, func() bool {
		h, _ := a.HealthCheck(ctx)
		return h.State == StateRunning && h.Running && h.PID > 0
	}, "core did not reach running")

	if err := a.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	h, _ := a.HealthCheck(ctx)
	if h.State != StateStopped {
		t.Fatalf("state after stop = %q, want stopped", h.State)
	}
}

// Deleting the last inbound of a core must stop it. A core left running serves
// inbounds the panel no longer knows about, and the panel shows nothing.
func TestApplyingAnEmptyPlanStopsARunningCore(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins})
	ctx := context.Background()
	t.Cleanup(func() { _ = a.Stop(ctx) })

	nodes := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)
	if err := a.Apply(ctx, Plan{Specs: specsOf(nodes), CertPath: testCert, KeyPath: testKey}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		h, _ := a.HealthCheck(ctx)
		return h.State == StateRunning
	}, "core did not reach running")

	if err := a.Apply(ctx, Plan{CertPath: testCert, KeyPath: testKey}); err != nil {
		t.Fatalf("empty plan: %v", err)
	}
	h, _ := a.HealthCheck(ctx)
	if h.State != StateStopped {
		t.Fatalf("state after the last inbound was deleted = %q, want stopped", h.State)
	}
}

// Reload re-renders the LAST plan. A reload that reused the config already on
// disk would silently ignore an edit to a user's credentials.
func TestReloadRerendersTheLastPlan(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins})
	ctx := context.Background()
	t.Cleanup(func() { _ = a.Stop(ctx) })

	node := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)[0]
	plan := Plan{Specs: []engine.InboundSpec{{Node: node,
		Clients: []engine.ClientCred{{Email: "alice@example.com", UUID: "5e1a1f37-4d3a-4b52-9f2c-0f9a2f4d1c11"}}}},
		CertPath: testCert, KeyPath: testKey}
	if err := a.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}

	// Mutate the inbound the plan points at, the way an edit in the panel would,
	// then reload without re-applying.
	node.Port = 40001
	if err := a.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "engines", "xray.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cfg, []byte(`"port": 30001`)) {
		t.Error("reload kept the old listen port; the edit never reached the core")
	}
	if !bytes.Contains(cfg, []byte(`"port": 40001`)) {
		t.Errorf("reload did not re-render the edited inbound:\n%s", cfg)
	}
	if !bytes.Contains(cfg, []byte("alice@example.com")) {
		t.Error("reload dropped the bound user")
	}
}

// Lifecycle calls on an adapter nothing has been applied to must be no-ops, not
// errors: a panel with no inbound of this kind has nothing to run, and that is
// a normal state.
func TestLifecycleOnAnUnusedAdapterIsANoOp(t *testing.T) {
	bins := &fakeBins{dir: t.TempDir()}
	a := NewSingbox(Options{DataDir: t.TempDir(), Bins: bins})
	ctx := context.Background()
	for name, fn := range map[string]func(context.Context) error{
		"start": a.Start, "stop": a.Stop, "restart": a.Restart,
	} {
		if err := fn(ctx); err != nil {
			t.Errorf("%s on an unused adapter: %v", name, err)
		}
	}
	if calls := bins.calls(); len(calls) != 0 {
		t.Errorf("lifecycle calls on an unused adapter resolved binaries %v", calls)
	}
}

// A cancelled context must stop a reload before it restarts anything. A reload
// that ignored cancellation would bounce every core during a shutdown.
func TestApplyHonoursACancelledContext(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	nodes := nodesWithProtocol(matrixNodes(t), model.ProtoVLESS)
	err := a.Apply(ctx, Plan{Specs: specsOf(nodes), CertPath: testCert, KeyPath: testKey})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("apply with a cancelled context = %v, want context.Canceled", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "engines", "xray.json")); statErr == nil {
		t.Error("a cancelled apply still wrote a config into place")
	}
}

func TestDetectReportsInstalledAndVersion(t *testing.T) {
	dir := t.TempDir()
	bins := &fakeBins{dir: filepath.Join(dir, "bin")}
	a := NewSingbox(Options{DataDir: dir, Bins: bins})

	installed, ver, err := a.Detect()
	if err != nil || installed || ver != "" {
		t.Fatalf("Detect on a fresh panel = (%v, %q, %v), want (false, \"\", nil): a missing core is a state, not an error",
			installed, ver, err)
	}

	writeFakeCore(t, bins.Path(binmgr.EngineSingbox), fakeCore)
	installed, ver, err = a.Detect()
	if err != nil || !installed || ver != "fake-core 9.9.9" {
		t.Fatalf("Detect after install = (%v, %q, %v), want (true, \"fake-core 9.9.9\", nil)", installed, ver, err)
	}

	// A present-but-unrunnable binary is installed AND broken, and the two have
	// to be told apart: one needs a download, the other needs the cache cleared.
	if err := os.Chmod(bins.Path(binmgr.EngineSingbox), 0o644); err != nil {
		t.Fatal(err)
	}
	installed, ver, err = a.Detect()
	if !installed || err == nil || ver != "" {
		t.Fatalf("Detect on a non-executable binary = (%v, %q, %v), want (true, \"\", error)", installed, ver, err)
	}
}

// The two engines must keep writing to the paths the supervisor has always
// used. Renaming a config path orphans the config of every panel that upgrades.
func TestConfigPathsAreUnchanged(t *testing.T) {
	dir := t.TempDir()
	opts := Options{DataDir: dir, Bins: &fakeBins{dir: dir}}
	for _, tc := range []struct {
		adapter        CoreAdapter
		want, wantCand string
	}{
		{NewXray(opts), filepath.Join(dir, "engines", "xray.json"), filepath.Join(dir, "engines", "xray.candidate.json")},
		{NewSingbox(opts), filepath.Join(dir, "engines", "singbox.json"), filepath.Join(dir, "engines", "singbox.candidate.json")},
	} {
		s := tc.adapter.(*supervised)
		if got := s.configPath(); got != tc.want {
			t.Errorf("%s config path = %q, want %q", s.name, got, tc.want)
		}
		if got := s.candidatePath(); got != tc.wantCand {
			t.Errorf("%s candidate path = %q, want %q", s.name, got, tc.wantCand)
		}
	}
}

// Every supervisor state must map to a state the panel renders. A supervisor
// state added without a decision here would surface as "unavailable", which
// reads like a missing kernel module rather than a new lifecycle state.
func TestEverySupervisorStateMaps(t *testing.T) {
	want := map[supervisor.State]State{
		supervisor.StateStopped:      StateStopped,
		supervisor.StateRunning:      StateRunning,
		supervisor.StateCrashed:      StateCrashed,
		supervisor.StateInvalid:      StateInvalid,
		supervisor.StateUnresponsive: StateUnresponsive,
	}
	for from, to := range want {
		if got := mapSupervisorState(from); got != to {
			t.Errorf("mapSupervisorState(%q) = %q, want %q", from, got, to)
		}
	}
	if got := mapSupervisorState(supervisor.State("something-new")); got != StateUnavailable {
		t.Errorf("an unmapped supervisor state gave %q, want %q", got, StateUnavailable)
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(msg)
}

// The probe the registry supplies must actually reach the supervisor.
//
// Options.Probe is proved populated by a guard in internal/core, and the
// supervisor is proved to run a probe it is given by a test that builds
// EngineSpec directly. The one line joining them is spec(), and nothing covered
// it: setting Probe to nil there left the whole core and api suites green, so
// the feature could have shipped with liveness probing configured, tested at
// both ends, and never actually running.
func TestTheProbeFromTheRegistryReachesTheSupervisorSpec(t *testing.T) {
	called := false
	probe := func(context.Context) error { called = true; return nil }

	a := &supervised{
		name: "xray",
		opts: Options{Probe: map[string]func(context.Context) error{"xray": probe}},
		bins: binmgr.New(t.TempDir()),
	}
	spec := a.spec()
	if spec.Probe == nil {
		t.Fatal("spec() dropped the registry's probe: the supervisor would never probe this core")
	}
	if err := spec.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("spec() carried a probe that is not the one the registry supplied")
	}

	// A core the registry has no probe for must carry none rather than another
	// core's — the map is keyed by engine name for that reason.
	b := &supervised{
		name: "sing-box",
		opts: Options{Probe: map[string]func(context.Context) error{"xray": probe}},
		bins: binmgr.New(t.TempDir()),
	}
	if b.spec().Probe != nil {
		t.Error("an unprobed core was given another core's probe")
	}
}
