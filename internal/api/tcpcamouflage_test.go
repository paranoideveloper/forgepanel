package api

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TCP's HTTP header camouflage was built on every side except the one an
// operator touches: xrayStream renders it, both share-link exporters carry it,
// the Clash exporter maps it, and the parser reads it back from an imported
// link — while transportFields()["tcp"] was an empty slice, so no control for
// any of it has ever existed in the panel.
//
// These keys are the exact dot-paths the form writes into the node, so the test
// fails if the fields are dropped OR if one is renamed out of alignment with the
// model, which is the way this kind of wiring usually rots.
func TestTCPCamouflageIsReachableFromTheForm(t *testing.T) {
	want := []string{"transport.header.type", "transport.path", "transport.host"}
	have := map[string]Field{}
	for _, f := range transportFields()["tcp"] {
		have[f.Key] = f
	}
	for _, k := range want {
		if _, ok := have[k]; !ok {
			t.Errorf("the tcp transport form has no control for %q", k)
		}
	}
	// "http" must be offered: it is the only header type xrayStream renders, and
	// a select without it makes the whole feature unreachable even with the
	// field present.
	opts := have["transport.header.type"].Options
	found := false
	for _, o := range opts {
		if o == "http" {
			found = true
		}
	}
	if !found {
		t.Errorf("header type offers %v, which cannot express the one type the renderer honours", opts)
	}
}

// What the form writes must survive into the config the core is handed. This
// walks the real path — the dot-paths the frontend sets, through the model's own
// JSON decoding, through Normalize (which clears transport fields it considers
// irrelevant to the network, and used to be where a tcp Path could vanish), into
// the rendered engine config.
func TestTCPCamouflageSurvivesFromFormKeysToTheEngineConfig(t *testing.T) {
	raw := []byte(`{
		"protocol": "vless", "address": "0.0.0.0", "port": 8443,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"transport": {"network": "tcp", "header": {"type": "http"},
			"path": "/camo", "host": "www.example.com"}
	}`)
	var n model.Node
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	n.Normalize()
	if n.Transport.HeaderObfs == nil || n.Transport.HeaderObfs.Type != "http" {
		t.Fatalf("Normalize dropped the camouflage header: %+v", n.Transport)
	}
	if n.Transport.Path != "/camo" || n.Transport.Host != "www.example.com" {
		t.Fatalf("Normalize dropped the camouflage path/host: %+v", n.Transport)
	}

	b, err := engine.BuildMulti([]engine.InboundSpec{{Node: &n, Clients: []engine.ClientCred{
		{UUID: "11111111-1111-1111-1111-111111111111", Email: job.UserEmail(1)}}}}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Port           int `json:"port"`
			StreamSettings struct {
				TCPSettings struct {
					Header struct {
						Type    string `json:"type"`
						Request struct {
							Path    []string            `json:"path"`
							Headers map[string][]string `json:"headers"`
						} `json:"request"`
					} `json:"header"`
				} `json:"tcpSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(b.Xray, &cfg); err != nil {
		t.Fatal(err)
	}
	// By port, not by index: the first inbound in a rendered config is the
	// api dokodemo-door, so an index would assert against the wrong one and pass
	// or fail for reasons unrelated to the camouflage.
	idx := -1
	for i, in := range cfg.Inbounds {
		if in.Port == 8443 {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("the inbound was not rendered at all: %s", b.Xray)
	}
	h := cfg.Inbounds[idx].StreamSettings.TCPSettings.Header
	if h.Type != "http" {
		t.Fatalf("rendered header = %+v, want the http camouflage", h)
	}
	if len(h.Request.Path) != 1 || h.Request.Path[0] != "/camo" {
		t.Errorf("rendered path = %v, want [/camo]", h.Request.Path)
	}
	if got := h.Request.Headers["Host"]; len(got) != 1 || got[0] != "www.example.com" {
		t.Errorf("rendered Host = %v, want [www.example.com]", got)
	}
}

// And the core has to accept it. The path is the one part of this the SERVER
// actually enforces — measured against Xray 26.2.6 by running a real client and
// server: a client whose path differs cannot connect at all, while a client
// whose Host header or request method differ connects fine. That asymmetry is
// what the field help tells the operator, so it is worth a config the core has
// confirmed it will start.
func TestTCPCamouflageIsAcceptedByTheRealCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 8443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "tcp-camouflage",
		Transport: model.Transport{Network: model.NetTCP, Path: "/camo",
			Host: "www.example.com", HeaderObfs: &model.Header{Type: "http"}},
	}
	n.Normalize()
	b, err := engine.BuildMulti([]engine.InboundSpec{{Node: n, Clients: []engine.ClientCred{
		{UUID: "11111111-1111-1111-1111-111111111111", Email: job.UserEmail(1)}}}}, 10085, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Without this the test is vacuous: a config with no camouflage at all is
	// also a config the core happily accepts, so "the core said yes" would prove
	// nothing about the feature under test.
	if !strings.Contains(string(b.Xray), `"tcpSettings"`) {
		t.Fatalf("nothing to validate — the config carries no tcpSettings:\n%s", b.Xray)
	}
	path := filepath.Join(t.TempDir(), "camo.json")
	if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("the core refuses the camouflage config the form now builds:\n%s", out)
	}
}
