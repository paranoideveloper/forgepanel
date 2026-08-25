package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func brookNode() *model.Node {
	n := &model.Node{Remark: "brook", Protocol: model.ProtoBrook, Address: "203.0.113.15", Port: 30017,
		Password: "brookpw", Brook: &model.BrookOptions{Mode: "wssserver", Path: "/b"}}
	n.Normalize()
	return n
}

func newBrookAdapter(t *testing.T) (CoreAdapter, *fakeBrook) {
	t.Helper()
	run := &fakeBrook{}
	return NewBrook(Options{DataDir: t.TempDir(), Bins: &fakeBins{dir: t.TempDir()}}, run), run
}

// The descriptor is what the panel's generated-config drawer shows. Brook's
// password IS the inbound's whole credential, so the descriptor must report
// only that one is set — never the value.
func TestBrookDescriptorNeverCarriesThePassword(t *testing.T) {
	a, _ := newBrookAdapter(t)
	cfg, err := a.GenerateConfig([]*model.Node{brookNode()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "brookpw") {
		t.Fatalf("the Brook descriptor leaked the inbound password:\n%s", cfg)
	}
	var got []BrookInbound
	if err := json.Unmarshal(cfg, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("descriptor has %d entries, want 1", len(got))
	}
	want := BrookInbound{Port: 30017, Mode: "wssserver", Path: "/b", SNI: "203.0.113.15", HasPassword: true}
	if got[0] != want {
		t.Fatalf("descriptor = %+v, want %+v", got[0], want)
	}
}

// A Brook inbound with no mode is a `brook server`, matching the runner's own
// default. If the descriptor and the runner disagreed, the Doctor would validate
// a different process than the one that runs.
func TestBrookDescriptorDefaultsMatchTheRunner(t *testing.T) {
	a, _ := newBrookAdapter(t)
	n := &model.Node{Protocol: model.ProtoBrook, Address: "203.0.113.15", Port: 9000, Password: "pw"}
	n.Normalize()
	cfg, err := a.GenerateConfig([]*model.Node{n})
	if err != nil {
		t.Fatal(err)
	}
	var got []BrookInbound
	if err := json.Unmarshal(cfg, &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Mode != "server" {
		t.Errorf("default mode = %q, want %q", got[0].Mode, "server")
	}
	if got[0].Path != "/ws" {
		t.Errorf("default path = %q, want %q", got[0].Path, "/ws")
	}
	if got[0].SNI != "203.0.113.15" {
		t.Errorf("SNI fell back to %q, want the inbound address", got[0].SNI)
	}
}

// Brook has no `check` subcommand, so this validator is the only thing standing
// between a mistyped inbound and a process that exits on every start. Each case
// is a way Brook dies immediately.
func TestBrookValidateCatchesUnstartableInbounds(t *testing.T) {
	a, _ := newBrookAdapter(t)
	cases := []struct {
		name string
		in   []BrookInbound
		want string
	}{
		{"unknown mode", []BrookInbound{{Port: 1080, Mode: "socks5server", HasPassword: true}}, "unknown mode"},
		{"no password", []BrookInbound{{Port: 1080, Mode: "server"}}, "no password"},
		{"port zero", []BrookInbound{{Port: 0, Mode: "server", HasPassword: true}}, "out of range"},
		{"port too high", []BrookInbound{{Port: 70000, Mode: "server", HasPassword: true}}, "out of range"},
		{"duplicate port", []BrookInbound{
			{Port: 1080, Mode: "server", HasPassword: true},
			{Port: 1080, Mode: "wsserver", HasPassword: true},
		}, "claimed by two inbounds"},
		{"wss without a domain", []BrookInbound{{Port: 443, Mode: "wssserver", HasPassword: true}}, "needs a server name"},
		{"quic without a domain", []BrookInbound{{Port: 443, Mode: "quicserver", HasPassword: true}}, "needs a server name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			err = a.ValidateConfig(raw)
			if err == nil {
				t.Fatalf("accepted a Brook inbound that cannot start (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}

	ok, err := a.GenerateConfig([]*model.Node{brookNode()})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateConfig(ok); err != nil {
		t.Fatalf("a valid inbound was rejected: %v", err)
	}
	if err := a.ValidateConfig([]byte("not json")); err == nil {
		t.Error("garbage was accepted as a Brook config")
	}
}

// The adapter must hand the reconciler exactly the inbounds and certificate
// paths it was planned with — Brook terminates TLS itself in wss/quic mode, so
// a dropped certificate path is an inbound that cannot serve.
func TestBrookApplyPassesThePlanThrough(t *testing.T) {
	a, run := newBrookAdapter(t)
	n := brookNode()
	plan := Plan{Specs: specsOf([]*model.Node{n}), CertPath: testCert, KeyPath: testKey}
	if err := a.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	got := run.lastSync()
	if len(got) != 1 || got[0] != n {
		t.Fatalf("reconciler received %v, want the planned inbound", got)
	}
	if run.cert != testCert || run.key != testKey {
		t.Fatalf("reconciler received cert %q/%q, want %q/%q", run.cert, run.key, testCert, testKey)
	}

	// A reconciler failure — Brook's binary missing, a port already bound — must
	// reach the caller. Swallowing it would report a successful reload for a
	// core that never came up.
	run.err = errors.New("brook start :30017: address already in use")
	if err := a.Apply(context.Background(), plan); err == nil {
		t.Fatal("a failed Brook reconcile was reported as a successful apply")
	}
}

// Reload re-reconciles the last plan rather than clearing it. A reload that
// forgot the plan would tear down every Brook inbound on the next scheduler tick.
func TestBrookReloadReusesTheLastPlan(t *testing.T) {
	a, run := newBrookAdapter(t)
	n := brookNode()
	if err := a.Apply(context.Background(), Plan{Specs: specsOf([]*model.Node{n}), CertPath: testCert, KeyPath: testKey}); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.syncCount() != 2 {
		t.Fatalf("reconciler saw %d syncs, want 2", run.syncCount())
	}
	if got := run.lastSync(); len(got) != 1 || got[0] != n {
		t.Fatalf("reload reconciled %v, want the last plan's inbound", got)
	}

	if err := a.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.stops != 1 {
		t.Fatalf("restart stopped %d times, want 1", run.stops)
	}
	if got := run.lastSync(); len(got) != 1 {
		t.Fatal("restart did not bring the inbounds back up")
	}
}

func TestBrookHealthReportsTheProcessTable(t *testing.T) {
	a, run := newBrookAdapter(t)
	h, err := a.HealthCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.State != StateStopped || h.Running {
		t.Fatalf("health with no processes = %+v, want stopped", h)
	}
	run.statuses = []map[string]any{{"engine": "brook", "mode": "wssserver", "port": 30017, "pid": 4242}}
	h, _ = a.HealthCheck(context.Background())
	if h.State != StateRunning || !h.Running {
		t.Fatalf("health with a live process = %+v, want running", h)
	}
	procs, _ := h.Details["processes"].([]map[string]any)
	if len(procs) != 1 || procs[0]["pid"] != 4242 {
		t.Fatalf("health details = %+v, want the process table", h.Details)
	}
}

// The Brook adapter must refuse an inbound of another protocol rather than
// describing it as a Brook server, which is how a misrouted inbound would end
// up started with the wrong argv.
func TestBrookRefusesForeignProtocols(t *testing.T) {
	a, _ := newBrookAdapter(t)
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "203.0.113.1", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	if _, err := a.GenerateConfig([]*model.Node{n}); err == nil {
		t.Fatal("the Brook adapter described a VLESS inbound as a Brook server")
	}
	if err := a.Supports(n); err == nil {
		t.Fatal("the Brook adapter claims to support VLESS")
	}
}
