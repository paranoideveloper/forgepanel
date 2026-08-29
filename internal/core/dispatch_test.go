package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// These drive ReloadSpecs itself — the function the adapter registry replaced.
//
// The existing matrix and connectivity suites build configs with
// engine.BuildMulti and start raw processes, so they prove the CONFIGS are
// unchanged but never exercise the dispatch that decides which core is started,
// stopped or left alone. That is precisely the code this refactor rewrote, and
// precisely the code that had no test — which is how the adapter layer could be
// written, tested and never mounted without anything noticing.

func dispatchNode(p model.Protocol, port int, remark string) *model.Node {
	n := &model.Node{
		Protocol: p, Address: "127.0.0.1", Port: port, Remark: remark,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Password: "hunter2hunter2",
	}
	switch p {
	case model.ProtoHysteria2, model.ProtoTUIC, model.ProtoAnyTLS:
		n.Security = model.Security{Type: model.SecTLS, ServerName: "example.com"}
	}
	n.Normalize()
	return n
}

func specWithUser(n *model.Node) engine.InboundSpec {
	return engine.InboundSpec{Node: n, Clients: []engine.ClientCred{
		{Email: "u1", UUID: "11111111-2222-4333-8444-555555555555", Password: "pw1"},
	}}
}

// A reload must actually start the cores an inbound needs, and Status must
// report them. This is the whole contract of the dispatch.
func TestReloadStartsTheCoresAnInboundNeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the engine binaries")
	}
	ctrl := NewController(t.TempDir(), 10098)
	if ctrl.Registry() == nil {
		t.Fatalf("controller has no adapter registry: %v", ctrl.regErr)
	}

	xrayPort, sbPort := freePort(t), freePort(t)
	specs := []engine.InboundSpec{
		specWithUser(dispatchNode(model.ProtoVLESS, xrayPort, "x1")),
		specWithUser(dispatchNode(model.ProtoHysteria2, sbPort, "s1")),
	}

	bundle, err := ctrl.ReloadSpecs(specs)
	if err != nil {
		t.Fatalf("ReloadSpecs: %v", err)
	}
	if len(bundle.Skipped) > 0 {
		t.Fatalf("inbounds were skipped: %+v", bundle.Skipped)
	}
	if bundle.XrayN != 1 || bundle.SingboxN != 1 {
		t.Fatalf("expected one inbound per core, got xray=%d singbox=%d", bundle.XrayN, bundle.SingboxN)
	}
	t.Cleanup(ctrl.StopAll)

	// Both cores must be reported, and must actually be running.
	waitFor(t, 20*time.Second, func() error {
		st := ctrl.Status()
		if len(st) != 2 {
			return fmt.Errorf("Status() reported %d engines, want 2", len(st))
		}
		for _, e := range st {
			if e.State != "running" {
				return fmt.Errorf("%s is %q (%s)", e.Engine, e.State, e.LastError)
			}
		}
		return nil
	})

	// And the ports must be open, which is the only proof the cores did more
	// than report a state.
	waitFor(t, 20*time.Second, func() error {
		for _, p := range []int{xrayPort} { // TCP only; hysteria2 is UDP
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 2*time.Second)
			if err != nil {
				return fmt.Errorf("port %d not listening: %w", p, err)
			}
			_ = c.Close()
		}
		return nil
	})
}

// Removing an inbound must actually stop its core. An adapter that is not told
// its plan is now empty keeps serving inbounds the panel has forgotten — the
// exact failure the old hand-written dispatch produced whenever a core was
// missing from one of its four separate enumerations.
func TestReloadStopsACoreWhoseLastInboundWasRemoved(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the engine binaries")
	}
	ctrl := NewController(t.TempDir(), 10096)
	t.Cleanup(ctrl.StopAll)

	port := freePort(t)
	if _, err := ctrl.ReloadSpecs([]engine.InboundSpec{
		specWithUser(dispatchNode(model.ProtoVLESS, port, "gone-soon")),
	}); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	waitFor(t, 20*time.Second, func() error {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			return err
		}
		_ = c.Close()
		return nil
	})

	// Now reload with nothing at all.
	if _, err := ctrl.ReloadSpecs(nil); err != nil {
		t.Fatalf("empty reload: %v", err)
	}
	waitFor(t, 20*time.Second, func() error {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = c.Close()
			return fmt.Errorf("port %d is still listening after its inbound was removed", port)
		}
		return nil
	})
	if st := ctrl.Status(); len(st) != 0 {
		t.Fatalf("Status() still reports %d engines after everything was removed: %+v", len(st), st)
	}
}

// An inbound no core can serve must be REPORTED, not silently dropped. The old
// dispatch skipped anything its switch did not recognise, so the inbound simply
// vanished from the generated config with nothing to explain it.
func TestUnroutableInboundIsReportedRatherThanDropped(t *testing.T) {
	ctrl := NewController(t.TempDir(), 10095)
	t.Cleanup(ctrl.StopAll)

	// ForgeDNS is a real protocol in the model and deliberately has no
	// inbound-serving adapter: it is an authoritative DNS service, not a proxy
	// core.
	n := &model.Node{Protocol: model.ProtoForgeDNS, Address: "127.0.0.1", Port: 5399, Remark: "dns-zone"}
	n.Normalize()

	bundle, err := ctrl.ReloadSpecs([]engine.InboundSpec{{Node: n}})
	if err != nil {
		t.Fatalf("an unroutable inbound must not fail the whole reload: %v", err)
	}
	found := false
	for _, s := range bundle.Skipped {
		if s.Remark == "dns-zone" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unroutable inbound was dropped silently; skipped = %+v", bundle.Skipped)
	}
}

// Every registered adapter must be told its plan, including the empty ones.
// Handing out only the non-empty plans is how a deleted inbound stays alive.
func TestEveryAdapterIsGivenAPlanIncludingEmptyOnes(t *testing.T) {
	ctrl := NewController(t.TempDir(), 10094)
	reg := ctrl.Registry()
	if reg == nil {
		t.Fatalf("no registry: %v", ctrl.regErr)
	}
	plans, _ := reg.Partition(nil, "", "")
	if len(plans) != len(reg.All()) {
		t.Fatalf("Partition returned %d plans for %d adapters", len(plans), len(reg.All()))
	}
	for _, ap := range plans {
		if !ap.Plan.Empty() {
			t.Errorf("%s got a non-empty plan from no specs", ap.Engine)
		}
	}
}

// waitFor retries until cond succeeds or the deadline passes, reporting the last
// failure. Engines take a moment to bind; a fixed sleep is either flaky or slow.
func waitFor(t *testing.T, d time.Duration, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		if last = cond(); last == nil {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("condition never held within %s: %v", d, last)
}

// An inbound the DISPATCHER serves must not be reported as not serving.
//
// BuildMulti knows Xray and sing-box and marks everything else "no supervised
// engine" — which is every protocol with a dedicated engine. The dispatcher then
// starts those from the adapter registry, and the stale mark was never removed,
// so a Brook inbound ran, carried traffic, and told the operator it was dead. On
// every install, not only behind a platform edge.
func TestAnInboundTheDispatcherServesIsNotReportedAsSkipped(t *testing.T) {
	dir := t.TempDir()
	ctrl := NewController(dir, 10093)
	t.Cleanup(func() { ctrl.StopAll() })

	brook := &model.Node{
		Remark: "brook-ws", Protocol: model.ProtoBrook,
		Address: "127.0.0.1", Port: 39901, Password: "pw",
		Brook: &model.BrookOptions{Mode: "wsserver", Path: "/tunnel"},
	}
	bundle, _ := ctrl.ReloadSpecs([]engine.InboundSpec{{Node: brook}})
	if bundle == nil {
		t.Fatal("no bundle")
	}
	for _, sk := range bundle.Skipped {
		if sk.Remark == "brook-ws" && sk.Reason == engine.ReasonNoSupervisedEngine {
			t.Fatalf("a Brook inbound the dispatcher serves is reported as %q — a false "+
				"not-serving entry is how the real ones stop being read", sk.Reason)
		}
	}
}

// A genuine skip must survive. Clearing the mark too eagerly would hide the
// inbounds that really are unservable, which is the failure the column exists
// to prevent.
func TestAGenuinelyUnservableInboundKeepsItsSkip(t *testing.T) {
	dir := t.TempDir()
	ctrl := NewController(dir, 10092)
	t.Cleanup(func() { ctrl.StopAll() })

	// SSH has no server side in any core here.
	ssh := &model.Node{Remark: "ssh1", Protocol: model.ProtoSSH,
		Address: "127.0.0.1", Port: 39902, Password: "pw"}
	bundle, _ := ctrl.ReloadSpecs([]engine.InboundSpec{{Node: ssh}})
	if bundle == nil {
		t.Fatal("no bundle")
	}
	var found bool
	for _, sk := range bundle.Skipped {
		if sk.Remark == "ssh1" {
			found = true
		}
	}
	if !found {
		t.Error("an inbound no core can serve lost its skip entry")
	}
}
