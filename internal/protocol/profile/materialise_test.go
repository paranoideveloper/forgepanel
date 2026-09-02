package profile

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Serving one definition from ten nodes meant ten hand-made inbounds, and every
// rotation had to be repeated ten times correctly. The tenth is where the
// mistake lives, and a mismatched inbound fails only for its own users.

func template(t *testing.T) *model.Node {
	t.Helper()
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "template",
		Flow: "xtls-rprx-vision",
	}
	n.Security = model.Security{
		Type: model.SecReality, ServerName: "www.cloudflare.com", Fingerprint: "chrome",
		Reality: &model.Reality{
			Dest:        "www.cloudflare.com:443",
			ServerNames: []string{"www.cloudflare.com"},
			PrivateKey:  "wJm5tPqR3kL8vXnE2sYb6hGdF9cA1zQ4uT7iO0pN5mI",
			PublicKey:   "xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU",
			ShortIDs:    []string{"0123abcd"},
		},
	}
	n.Normalize()
	return n
}

func TestSharedFieldsCannotDrift(t *testing.T) {
	tpl := template(t)
	a, err := Materialise(tpl, "eu-vless", Binding{NodeID: 1, NodeName: "de", Port: 8443, PublicHost: "de.example"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Materialise(tpl, "eu-vless", Binding{NodeID: 2, NodeName: "nl", Port: 9443, PublicHost: "nl.example"})
	if err != nil {
		t.Fatal(err)
	}

	// The whole point: the credential and the security settings are identical on
	// every node, by construction rather than by the operator being careful.
	if a.UUID != b.UUID || a.UUID != tpl.UUID {
		t.Fatalf("the credential differs between nodes: %s vs %s", a.UUID, b.UUID)
	}
	if a.Security.ServerName != b.Security.ServerName || a.Flow != b.Flow {
		t.Fatal("security or flow drifted between materialised nodes")
	}
	// The REALITY key material especially: one node with a different private key
	// silently fails for every client handed the shared public key.
	if a.Security.Reality == nil || b.Security.Reality == nil ||
		a.Security.Reality.PrivateKey != b.Security.Reality.PrivateKey {
		t.Fatal("the REALITY key material drifted between nodes")
	}
	// And the per-node parts genuinely differ. The public host lands on Domain,
	// not Address: Address is the LISTEN address and a hostname there makes the
	// core refuse the inbound outright.
	if a.Port == b.Port || a.Domain == b.Domain {
		t.Fatalf("the per-node fields did not differ: %d/%s vs %d/%s",
			a.Port, a.Domain, b.Port, b.Domain)
	}
	if a.Address != "0.0.0.0" || b.Address != "0.0.0.0" {
		t.Fatalf("the public host leaked into the listen address: %q / %q", a.Address, b.Address)
	}
}

func TestTheTemplateIsNeverMutated(t *testing.T) {
	tpl := template(t)
	beforePort, beforeAddr := tpl.Port, tpl.Address

	_, _ = Materialise(tpl, "p", Binding{NodeID: 1, NodeName: "a", Port: 1111, PublicHost: "a.example"})
	_, _ = Materialise(tpl, "p", Binding{NodeID: 2, NodeName: "b", Port: 2222, PublicHost: "b.example"})

	// A shared mutation would make every later binding inherit the previous
	// one's port — and the bug would only show on the second node onwards.
	if tpl.Port != beforePort || tpl.Address != beforeAddr {
		t.Fatalf("the template was mutated: port %d→%d, address %s→%s",
			beforePort, tpl.Port, beforeAddr, tpl.Address)
	}
	second, err := Materialise(tpl, "p", Binding{NodeID: 3, NodeName: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Port != beforePort {
		t.Fatalf("a binding with no port inherited %d instead of the template's %d",
			second.Port, beforePort)
	}
}

func TestMaterialisedInboundsGetDistinctTagsInTheBuiltConfig(t *testing.T) {
	tpl := template(t)
	// A template carrying an explicit tag is the dangerous case: inherited
	// unchanged, every materialised row would share it.
	tpl.Tag = "shared-tag"

	a, _ := Materialise(tpl, "p", Binding{NodeID: 1, NodeName: "de", Port: 8443})
	b, _ := Materialise(tpl, "p", Binding{NodeID: 2, NodeName: "nl", Port: 9443})

	// Tags are assigned by the engine from the port, not by Normalize, so the
	// property is checked where it actually matters: in the generated config.
	// The core indexes by tag, routing rules target it, and traffic counters are
	// keyed on it — two rows sharing one silently merge their accounting.
	bundle, err := engine.BuildMulti([]engine.InboundSpec{
		{Node: a, Clients: []engine.ClientCred{{UUID: "11111111-1111-1111-1111-111111111111", Email: "u.1"}}},
		{Node: b, Clients: []engine.ClientCred{{UUID: "11111111-1111-1111-1111-111111111111", Email: "u.1"}}},
	}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.XrayN != 2 {
		t.Fatalf("only %d of 2 rows reached the config: %+v", bundle.XrayN, bundle.Skipped)
	}
	// Only INBOUND tags. A naive scan of the whole document also counts the api
	// outbound and the routing rule, which legitimately repeat the api tag.
	var doc struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(bundle.Xray, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, in := range doc.Inbounds {
		seen[in.Tag]++
	}
	for tag, n := range seen {
		if n > 1 {
			t.Fatalf("inbound tag %q appears %d times; those rows would merge their accounting", tag, n)
		}
	}
}

func TestEachRowSaysWhichNodeItServes(t *testing.T) {
	tpl := template(t)
	n, _ := Materialise(tpl, "eu-vless", Binding{NodeID: 7, NodeName: "frankfurt", Port: 443})
	// Without this the inbound list is ten identical rows and the operator
	// cannot tell which one is misbehaving.
	if !strings.Contains(n.Remark, "eu-vless") || !strings.Contains(n.Remark, "frankfurt") {
		t.Fatalf("remark = %q, want it to name both the profile and the node", n.Remark)
	}
}

func TestAnUnnamedNodeStillGetsADistinctRemark(t *testing.T) {
	tpl := template(t)
	a, _ := Materialise(tpl, "p", Binding{NodeID: 1, Port: 1})
	b, _ := Materialise(tpl, "p", Binding{NodeID: 2, Port: 2})
	if a.Remark == b.Remark {
		t.Fatalf("two nodes with no name got the same remark %q", a.Remark)
	}
}

func TestAProfileWithNoUsablePortIsRefused(t *testing.T) {
	tpl := template(t)
	tpl.Port = 0
	// Rendering this would produce an inbound the core refuses, and the failure
	// would surface as an engine error rather than as a profile problem.
	if _, err := Materialise(tpl, "broken", Binding{NodeID: 1, NodeName: "de"}); err == nil {
		t.Fatal("a profile with no port was materialised")
	}
	if _, err := Materialise(tpl, "broken", Binding{NodeID: 1, NodeName: "de", Port: 70000}); err == nil {
		t.Fatal("an out-of-range port was accepted")
	}
}

func TestANilTemplateIsAnError(t *testing.T) {
	if _, err := Materialise(nil, "p", Binding{NodeID: 1}); err == nil {
		t.Fatal("a nil template produced an inbound")
	}
}

// TestMaterialisedFleetIsAcceptedByTheRealCore is the one that matters: a
// profile is only useful if the ten rows it produces are ten rows the core will
// actually serve, on one machine, at once.
func TestMaterialisedFleetIsAcceptedByTheRealCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	tpl := template(t)
	var specs []engine.InboundSpec
	for i := 1; i <= 10; i++ {
		n, err := Materialise(tpl, "fleet", Binding{
			NodeID: uint(i), NodeName: "n" + string(rune('a'+i-1)),
			Port: 20000 + i, PublicHost: "n.example",
		})
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, engine.InboundSpec{Node: n, Clients: []engine.ClientCred{
			{UUID: "11111111-1111-1111-1111-111111111111", Email: "u.1"}}})
	}

	b, err := engine.BuildMulti(specs, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if b.XrayN != 10 {
		t.Fatalf("only %d of 10 materialised inbounds reached the config; the rest were skipped: %+v",
			b.XrayN, b.Skipped)
	}
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("the core rejected a materialised fleet: %v\n%s", err, out)
	}
}

func TestAHostnameAsTheListenAddressIsRefusedWithTheFix(t *testing.T) {
	tpl := template(t)
	tpl.Address = "vpn.example.com"

	_, err := Materialise(tpl, "misconfigured", Binding{NodeID: 1, NodeName: "de", Port: 8443})
	if err == nil {
		t.Fatal("a hostname listen address was accepted; the core would refuse every " +
			"materialised row with \"unable to listen on domain address\"")
	}
	// The message has to name the fix. This mistake is easy to make precisely
	// because the field is called Address, and the core's own error does not say
	// what to do about it.
	if !strings.Contains(err.Error(), "0.0.0.0") || !strings.Contains(err.Error(), "binding") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
}

func TestBindableAddressesAreAccepted(t *testing.T) {
	// "" is deliberately absent: the model's own Validate requires an address and
	// rejects it with "address is required", which is already a clear message.
	for _, addr := range []string{"0.0.0.0", "::", "[::]", "127.0.0.1", "10.0.0.5", "localhost"} {
		tpl := template(t)
		tpl.Address = addr
		if _, err := Materialise(tpl, "p", Binding{NodeID: 1, NodeName: "n", Port: 8443}); err != nil {
			t.Errorf("listen address %q was refused: %v", addr, err)
		}
	}
}
