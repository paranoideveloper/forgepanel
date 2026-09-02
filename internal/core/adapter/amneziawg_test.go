package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func awgNode(port int) *model.Node {
	n := &model.Node{Remark: "awg", Protocol: model.ProtoAmneziaWG, Address: "203.0.113.14", Port: port,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "sk", PublicKey: "pk", PeerPrivateKey: "csk", PeerPublicKey: "cpk",
			ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"}}}}
	n.Normalize()
	return n
}

// The adapter must render the SAME config the reconciler writes to disk, from
// the same exporter. A second rendering path here would drift from the one that
// actually runs, and the Doctor would validate a config nobody uses.
func TestAWGConfigComesFromTheSameExporterTheReconcilerUses(t *testing.T) {
	a := NewAmneziaWG(&fakeAWG{})
	n := awgNode(51820)
	cfg, err := a.GenerateConfig([]*model.Node{n})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(cfg, &got); err != nil {
		t.Fatal(err)
	}
	want, err := export.AmneziaWGServerConf(n, []*model.Node{n})
	if err != nil {
		t.Fatal(err)
	}
	if got["51820"] != want {
		t.Fatalf("rendered config differs from the exporter the reconciler uses:\n--- adapter ---\n%s\n--- exporter ---\n%s",
			got["51820"], want)
	}
	if err := a.ValidateConfig(cfg); err != nil {
		t.Fatalf("the adapter's own config failed its own validator: %v", err)
	}
}

// Two AmneziaWG inbounds on one port would derive the same interface name and
// silently overwrite each other's config.
func TestAWGRejectsTwoInboundsOnOnePort(t *testing.T) {
	a := NewAmneziaWG(&fakeAWG{})
	_, err := a.GenerateConfig([]*model.Node{awgNode(51820), awgNode(51820)})
	if err == nil || !strings.Contains(err.Error(), "claimed by two inbounds") {
		t.Fatalf("error = %v, want a port-collision error", err)
	}
}

// awg-quick refuses a config without these fields, and a refused interface
// never comes up — reported here rather than discovered as a dead tunnel.
func TestAWGValidateCatchesUnusableConfigs(t *testing.T) {
	a := NewAmneziaWG(&fakeAWG{})
	cases := []struct {
		name, conf, key, want string
	}{
		{"no interface section", "PrivateKey = sk\nListenPort = 51820\n", "51820", "no [Interface]"},
		{"no private key", "[Interface]\nAddress = 10.67.67.1/24\nListenPort = 51820\n", "51820", "no PrivateKey"},
		{"no listen port", "[Interface]\nPrivateKey = sk\nAddress = 10.67.67.1/24\n", "51820", "no ListenPort"},
		{"port mismatch", "[Interface]\nPrivateKey = sk\nListenPort = 51999\n", "51820", "listens on 51999"},
		{"key is not a port", "[Interface]\nPrivateKey = sk\nListenPort = 51820\n", "awg0", "is not a listen port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{tc.key: tc.conf})
			if err != nil {
				t.Fatal(err)
			}
			err = a.ValidateConfig(raw)
			if err == nil {
				t.Fatalf("accepted a config awg-quick would refuse (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
	if err := a.ValidateConfig([]byte("[]")); err == nil {
		t.Error("a JSON array was accepted as a port->conf map")
	}
}

// A host with no amneziawg kernel module has not crashed — the capability was
// never there. Reporting it as crashed sends the operator to read a log that
// does not exist instead of installing a package.
func TestAWGHealthDistinguishesMissingKernelFromCrashed(t *testing.T) {
	run := &fakeAWG{
		kernel:   map[string]any{"kernel_ready": false, "tools_installed": false, "last_error": "awg/awg-quick tools not installed"},
		statuses: []map[string]any{{"engine": "amneziawg", "interface": "awg51820", "up": false}},
	}
	a := NewAmneziaWG(run)
	h, err := a.HealthCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.State != StateUnavailable {
		t.Fatalf("state with no kernel module = %q, want %q", h.State, StateUnavailable)
	}
	if h.LastError == "" {
		t.Error("the missing-tools reason was not surfaced")
	}

	run.kernel = map[string]any{"kernel_ready": true, "tools_installed": true, "module_loaded": true, "last_error": ""}
	run.statuses = []map[string]any{{"engine": "amneziawg", "interface": "awg51820", "up": true}}
	h, _ = a.HealthCheck(context.Background())
	if h.State != StateRunning || !h.Running {
		t.Fatalf("state with a live interface = %+v, want running", h)
	}

	run.statuses = []map[string]any{{"engine": "amneziawg", "interface": "awg51820", "up": false}}
	h, _ = a.HealthCheck(context.Background())
	if h.State != StateStopped {
		t.Fatalf("state with a ready kernel and a down interface = %q, want stopped", h.State)
	}
}

// A missing kernel module must not fail the reload — the reconciler records it
// and returns nil, because every other inbound on the panel would otherwise go
// down with it. An error it does return is a real one and must reach the caller.
func TestAWGApplyToleratesAMissingKernelButNotARealFailure(t *testing.T) {
	run := &fakeAWG{}
	a := NewAmneziaWG(run)
	n := awgNode(51820)
	if err := a.Apply(context.Background(), Plan{Specs: specsOf([]*model.Node{n})}); err != nil {
		t.Fatalf("apply on a host with no kernel module: %v", err)
	}
	if got := run.lastSync(); len(got) != 1 || got[0] != n {
		t.Fatalf("reconciler received %v, want the planned inbound", got)
	}
	if err := a.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := run.lastSync(); len(got) != 1 {
		t.Fatal("reload lost the last plan")
	}
	if err := a.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if run.stops != 1 {
		t.Fatalf("stops = %d, want 1", run.stops)
	}

	run.err = errors.New("amneziawg: cannot write /var/lib/forgepanel/amneziawg")
	if err := a.Apply(context.Background(), Plan{Specs: specsOf([]*model.Node{n})}); err == nil {
		t.Fatal("a real reconciler failure was reported as a successful apply")
	}
}

// AmneziaWG carries none of the model's transport stack, and saying otherwise
// would put a transport in front of an operator that the interface cannot use.
func TestAWGDeclaresNoTransports(t *testing.T) {
	a := NewAmneziaWG(&fakeAWG{})
	if got := a.SupportedTransports(); len(got) != 0 {
		t.Fatalf("SupportedTransports = %v, want none: AmneziaWG is a raw UDP kernel interface", got)
	}
	// It must still accept its own inbound: the transport check applies only to
	// protocols that use the transport stack.
	if err := a.Supports(awgNode(51820)); err != nil {
		t.Fatalf("the AmneziaWG adapter refused an AmneziaWG inbound: %v", err)
	}
}
