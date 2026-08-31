package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// testPresetCtx is the wizard context a real run would assemble: a panel
// domain, a proxied CDN host, the box's public address and one shared REALITY
// keypair. Every plan is built against it so the catalogue is exercised in the
// shape it actually ships in.
func testPresetCtx(t *testing.T) *presetWizardCtx {
	t.Helper()
	kp, err := keygen.RealityKeys()
	if err != nil {
		t.Fatalf("reality keypair: %v", err)
	}
	return &presetWizardCtx{
		domain:   "panel.example.org",
		cdnHost:  "edge-2f9c1a.example.org",
		serverIP: "203.0.113.9",
		reality: &model.Reality{
			PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey,
			ShortIDs: []string{"0123456789abcdef"},
			Dest:     realityDest, ServerNames: []string{borrowedSNIs[0]},
		},
	}
}

// buildCatalogue returns every plan built and defaulted, keyed by remark.
func buildCatalogue(t *testing.T) map[string]*model.Node {
	t.Helper()
	w := testPresetCtx(t)
	out := map[string]*model.Node{}
	for i := range wizardPresetPlans() {
		p := wizardPresetPlans()[i]
		n := p.build(&p, w)
		n.Address = w.serverIP
		applyCreateDefaults(n)
		n.Normalize()
		out[p.remark] = n
	}
	return out
}

// TestPresetCatalogueEveryPlanIsSelfConsistent is the cheap gate: every plan in
// the catalogue must survive its own model validation once defaults are
// applied. A plan that cannot pass Validate() is one the wizard would refuse to
// store, so it would ship as a button that always errors.
func TestPresetCatalogueEveryPlanIsSelfConsistent(t *testing.T) {
	cat := buildCatalogue(t)
	if len(cat) < 13 {
		t.Fatalf("catalogue shrank to %d plans; presets were removed without updating this test", len(cat))
	}
	for remark, n := range cat {
		if err := n.Validate(); err != nil {
			t.Errorf("preset %q does not validate: %v", remark, err)
		}
		if n.Port == 0 {
			t.Errorf("preset %q has no port", remark)
		}
	}
}

// TestPresetCataloguePortsAreUnique: the wizard creates the whole catalogue in
// one pass. Two plans sharing a port means the second inbound binds over the
// first and one of them silently never serves.
func TestPresetCataloguePortsAreUnique(t *testing.T) {
	seen := map[int]string{}
	for _, p := range wizardPresetPlans() {
		if prev, dup := seen[p.port]; dup {
			t.Errorf("port %d claimed by both %q and %q", p.port, prev, p.remark)
		}
		seen[p.port] = p.remark
	}
	// The panel and sshd own these; a preset landing on one takes down access.
	for _, reserved := range []int{22, 80, 2053} {
		if r, bad := seen[reserved]; bad {
			t.Errorf("preset %q claims reserved port %d", r, reserved)
		}
	}
}

// TestPresetCatalogueCredentialsAreMinted: applyCreateDefaults is what turns a
// plan into something connectable. A preset that ships without its secret is an
// inbound that starts and rejects every client.
func TestPresetCatalogueCredentialsAreMinted(t *testing.T) {
	for remark, n := range buildCatalogue(t) {
		switch n.Protocol {
		case model.ProtoVLESS, model.ProtoVMess, model.ProtoTUIC:
			if n.UUID == "" {
				t.Errorf("preset %q (%s) has no UUID", remark, n.Protocol)
			}
		case model.ProtoHysteria2, model.ProtoTrojan, model.ProtoAnyTLS:
			if n.Password == "" {
				t.Errorf("preset %q (%s) has no password", remark, n.Protocol)
			}
		case model.ProtoShadowsocks:
			if n.Password == "" {
				t.Errorf("preset %q has no shadowsocks key", remark)
			}
		case model.ProtoWireGuard, model.ProtoAmneziaWG:
			// AmneziaWG carries its keys in AmneziaWG.WireGuardOptions, not in
			// Node.WireGuard; the two are separate blocks on the model.
			wg := n.WireGuard
			if n.Protocol == model.ProtoAmneziaWG {
				if n.AmneziaWG == nil {
					t.Fatalf("preset %q has no amneziawg block at all", remark)
				}
				wg = &n.AmneziaWG.WireGuardOptions
			}
			if wg == nil {
				t.Fatalf("preset %q has no wireguard block at all", remark)
			}
			if wg.PrivateKey == "" || wg.PeerPrivateKey == "" {
				t.Errorf("preset %q is missing a wireguard keypair (server=%q client=%q)",
					remark, wg.PrivateKey, wg.PeerPrivateKey)
			}
		}
		if n.Security.Type == model.SecReality {
			r := n.Security.Reality
			if r == nil || r.PrivateKey == "" || len(r.ShortIDs) == 0 {
				t.Errorf("preset %q claims REALITY without a usable keypair/shortId", remark)
			}
		}
	}
}

// TestPresetCatalogueExportsAClientConfig closes the loop the wizard exists
// for: every preset must yield something a client can import. For URI
// protocols that is a parseable link carrying the host and port; WireGuard
// family exports native .conf instead, which is asserted separately.
func TestPresetCatalogueExportsAClientConfig(t *testing.T) {
	for remark, n := range buildCatalogue(t) {
		// ShadowTLS has no share-link scheme in any client; its native format
		// is a sing-box config, asserted by TestPresetShadowTLSExportsRunnable.
		if n.Protocol == model.ProtoShadowTLS {
			if _, _, err := nativeConfFor(n, n.Address); err != nil {
				t.Errorf("preset %q exports nothing at all: %v", remark, err)
			}
			continue
		}
		if n.Protocol == model.ProtoWireGuard || n.Protocol == model.ProtoAmneziaWG {
			conf, cerr := export.WireGuardConf(n, n.Address)
			if n.Protocol == model.ProtoAmneziaWG {
				conf, cerr = export.AmneziaWGConf(n, n.Address)
			}
			if cerr != nil {
				t.Errorf("preset %q exports no native conf: %v", remark, cerr)
				continue
			}
			if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
				t.Errorf("preset %q did not export a native wireguard conf:\n%s", remark, conf)
			}
			// AmneziaWG must keep its obfuscation parameters. Reduced to plain
			// WireGuard it still parses, still connects to nothing that matters,
			// and defeats the only reason to pick it.
			if n.Protocol == model.ProtoAmneziaWG && !strings.Contains(conf, "Jc =") {
				t.Errorf("AmneziaWG preset lost its obfuscation params:\n%s", conf)
			}
			continue
		}
		uri, err := export.URI(n)
		if err != nil {
			t.Errorf("preset %q exports no client URI: %v", remark, err)
			continue
		}
		// vmess:// is base64-encoded JSON, not a host:port URL. Decode it and
		// check the fields a client actually dials.
		if n.Protocol == model.ProtoVMess {
			assertVMessDialable(t, remark, uri)
			continue
		}
		u, perr := url.Parse(uri)
		if perr != nil {
			t.Errorf("preset %q exported an unparseable URI %q: %v", remark, uri, perr)
			continue
		}
		if u.Hostname() == "" || u.Port() == "" {
			t.Errorf("preset %q exported a URI with no host:port — %q", remark, uri)
		}
	}
}

// TestPresetCatalogueAcceptedByRealCores is the §9 gate the task asks for:
// hand every generated server config to the actual Xray and sing-box binaries
// and require them to accept it. This is the difference between "the JSON is
// syntactically valid" and "the core will serve it". Skipped when the cores
// cannot be fetched (offline CI).
func TestPresetCatalogueAcceptedByRealCores(t *testing.T) {
	if testing.Short() {
		t.Skip("real-core validation needs the pinned binaries; skipped in -short")
	}
	cat := buildCatalogue(t)
	// Bind on loopback so nothing in the test reaches the network, and give
	// each node a free port so a busy box does not fail the validator.
	var nodes []*model.Node
	for _, n := range cat {
		n.Address = "127.0.0.1"
		n.Port = freeTestPort(t)
		nodes = append(nodes, n)
	}
	ctrl := core.NewController(t.TempDir(), 0)
	defer ctrl.StopAll()
	_, results := ctrl.Validate(nodes)
	if len(results) == 0 {
		t.Skip("no engine reported; binaries unavailable")
	}
	for engineName, verdict := range results {
		if verdict == "valid" {
			t.Logf("%s ACCEPTED the generated config for its share of the catalogue", engineName)
			continue
		}
		if strings.Contains(verdict, "download") || strings.Contains(verdict, "not found") {
			t.Skipf("%s binary unavailable (%s)", engineName, verdict)
		}
		t.Errorf("%s REJECTED the generated config: %s", engineName, verdict)
	}
}

func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

var _ = time.Second

// assertVMessDialable decodes a vmess:// payload and requires the two fields a
// client cannot connect without.
func assertVMessDialable(t *testing.T, remark, uri string) {
	t.Helper()
	raw, err := base64.StdEncoding.WithPadding(base64.NoPadding).
		DecodeString(strings.TrimPrefix(uri, "vmess://"))
	if err != nil {
		t.Errorf("preset %q: vmess payload is not base64: %v", remark, err)
		return
	}
	var v struct {
		Add  string `json:"add"`
		Port string `json:"port"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Errorf("preset %q: vmess payload is not JSON: %v", remark, err)
		return
	}
	if v.Add == "" || v.Port == "" || v.ID == "" {
		t.Errorf("preset %q: vmess link missing add/port/id: %+v", remark, v)
	}
}

// TestPresetShadowTLSExportsRunnable is the export gap the task names: a
// protocol the panel could create but hand the operator nothing for. The
// emitted config must be a real sing-box document carrying the PAIR, and the
// authority on that is sing-box itself.
func TestPresetShadowTLSExportsRunnable(t *testing.T) {
	var node *model.Node
	for _, n := range buildCatalogue(t) {
		if n.Protocol == model.ProtoShadowTLS {
			node = n
		}
	}
	if node == nil {
		t.Fatal("the catalogue no longer contains a ShadowTLS preset")
	}
	name, body, err := nativeConfFor(node, node.Address)
	if err != nil {
		t.Fatalf("ShadowTLS exports nothing: %v", err)
	}
	if !strings.HasSuffix(name, ".json") {
		t.Errorf("expected a sing-box json file, got %q", name)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("exported config is not valid JSON: %v", err)
	}
	var kinds []string
	for _, o := range doc.Outbounds {
		kinds = append(kinds, fmt.Sprint(o["type"]))
	}
	// Both halves, or the client completes a handshake and moves no traffic.
	joined := strings.Join(kinds, ",")
	for _, want := range []string{"shadowtls", "shadowsocks"} {
		if !strings.Contains(joined, want) {
			t.Errorf("exported config has no %s outbound; got %v", want, kinds)
		}
	}

	bin := findSingbox()
	if bin == "" {
		t.Skip("sing-box binary not found; format checked, core acceptance NOT verified")
	}
	cfg := filepath.Join(t.TempDir(), "shadowtls.json")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", cfg).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box REJECTED the exported ShadowTLS config: %v\n%s", err, out)
	}
	t.Logf("sing-box ACCEPTED the exported ShadowTLS client config")
}
