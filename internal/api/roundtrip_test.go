package api

// Cross-language round trip: Go model -> real schema -> the REAL TypeScript
// buildNode -> back to a Go model -> real renderer -> the REAL Xray core.
//
// This is the only test that exercises the path an operator actually takes when
// they open an existing inbound and press Update, and it exists because that
// path silently destroyed data. PUT /admin/inbounds/:id binds a whole model.Node
// and REPLACES the stored row, while buildNode assembled a fresh object from the
// schema's fields alone. Everything the schema could not describe — the Egress
// chain, the xmux block, the split download leg, ECH, WireGuard peer keys — was
// therefore absent from the payload and overwritten with nothing. The operator
// saw a successful save.
//
// Neither language's tests could see it: Go's tests prove the model round-trips
// through JSON, the Svelte tests prove the form renders what it is handed, and
// the config that reaches the core is valid either way. Only running the real
// buildNode against the real schema and diffing the result finds it.
//
// It skips rather than fails when bun or xray is unavailable, so a machine
// without them is not blocked; CI has both.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// schemaDocument builds exactly what handleSchema serves to the browser.
func schemaDocument() map[string]any {
	fps := model.ValidFingerprints()
	transports := []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
	securities := []string{"none", "tls", "reality"}
	return map[string]any{
		"protocols":    protocolSchemas(transports, securities),
		"common":       commonFields(),
		"transports":   transportFields(),
		"securities":   securityFields(fps),
		"fingerprints": fps,
	}
}

// fullXHTTPNode uses the complete modern XHTTP surface plus a chain, which is
// precisely the set the form used to drop.
func fullXHTTPNode() *model.Node {
	return &model.Node{
		Protocol: model.ProtoVLESS,
		Remark:   "full-xhttp-chained",
		Address:  "203.0.113.10",
		Port:     443,
		Country:  "NL",
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Egress: model.EgressChain{
			"vless://11111111-2222-4333-8444-555555555555@203.0.113.50:443?security=reality" +
				"&sni=www.cloudflare.com&fp=chrome&pbk=xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU&sid=0123abcd&type=tcp#hop",
		},
		Transport: model.Transport{
			Network:              model.NetXHTTP,
			Path:                 "/up",
			Host:                 "cdn.example.com",
			Headers:              map[string]string{"X-Forwarded-Proto": "https"},
			XHTTPMode:            model.XHTTPModePacketUp,
			XPaddingB:            "100-1000",
			XPaddingObfsMode:     true,
			XPaddingKey:          "padkey",
			XPaddingHeader:       "X-Padding",
			XPaddingPlacement:    "header",
			XPaddingMethod:       "tokenish",
			NoGRPCHeader:         true,
			NoSSEHeader:          true,
			SCMaxEachPostBytes:   "1000000",
			SCMinPostsIntervalMs: "30-50",
			SCMaxBufferedPosts:   30,
			SCStreamUpServerSecs: "20-80",
			SessionPlacement:     "cookie",
			SessionKey:           "sid",
			SeqPlacement:         "header",
			SeqKey:               "X-Seq",
			UplinkDataPlacement:  "header",
			UplinkDataKey:        "X-Up",
			UplinkHTTPMethod:     "GET",
			UplinkChunkSize:      8192,
			ServerMaxHeaderBytes: 16384,
			XMux: &model.XMux{
				MaxConcurrency: "16-32",
				// maxConnections is deliberately unset: the core rejects it
				// combined with maxConcurrency, they are alternative strategies.
				CMaxReuseTimes:   "64-128",
				HMaxRequestTime:  "600-900",
				HMaxReusableSecs: "1800-3000",
				HKeepAlivePeriod: 45,
			},
			XHTTPDownload: &model.XHTTPDownload{
				Address: "dl.example.com",
				Port:    8443,
				// The download leg carries a COMPLETE transport. The form exposes
				// the subset that is meaningful on a second leg (where it goes,
				// which transport, how it is protected); the rest — padding
				// shape, extra headers, its own xmux — has no control and is
				// exactly what the base merge has to protect. Set them here so
				// this test fails if the merge is ever removed.
				Transport: model.Transport{
					Network: model.NetXHTTP, Path: "/down", Host: "dl.example.com",
					XHTTPMode: model.XHTTPModeStreamOne,
					XPaddingB: "200-400",
					Headers:   map[string]string{"X-Leg": "download"},
					XMux:      &model.XMux{MaxConcurrency: "8-16"},
				},
				Security: model.Security{
					Type: "reality", ServerName: "www.cloudflare.com", Fingerprint: "chrome",
					ALPN: []string{"h2"},
					Reality: &model.Reality{
						Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
						PublicKey: "xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU",
						ShortIDs:  []string{"0123abcd"}, SpiderX: "/",
					},
				},
			},
		},
		Security: model.Security{
			Type: "reality", ServerName: "www.cloudflare.com", Fingerprint: "chrome",
			Reality: &model.Reality{
				Dest: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
				PrivateKey: "yBl6cZ0hRJ8lRVJ0Xo0X6vY3vE8zqDp1oQ5x0aFhVXc",
				PublicKey:  "xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU",
				ShortIDs:   []string{"0123abcd"},
			},
		},
	}
}

// runBuildNode drives the real frontend module under bun and returns the node it
// produces for an EDIT of `stored`.
func runBuildNode(t *testing.T, dir string, schema map[string]any, stored *model.Node) map[string]any {
	t.Helper()
	bun, err := exec.LookPath("bun")
	if err != nil {
		t.Skip("bun not installed; the cross-language round trip needs it")
	}
	frontend, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(dir, "schema.json"), schema)
	write(t, filepath.Join(dir, "node.json"), stored)

	// The driver mirrors InboundForm exactly: prefill the flat values from the
	// stored node using the schema's own field list, then rebuild with the
	// stored node as the base — which is what an operator does by opening the
	// inbound and pressing Update without touching anything.
	driver := `
import { buildNode, fieldsFor, getPath, formatKV } from ` + "`" + filepath.Join(frontend, "src/lib/nodebuild.ts") + "`" + `;
const schema = await Bun.file(process.argv[2]).json();
const node = await Bun.file(process.argv[3]).json();

const proto = node.protocol;
const transport = node.transport?.network || 'tcp';
const security = node.security?.type || 'none';

const values = {
  remark: node.remark ?? '',
  port: node.port ?? 443,
  address: node.address ?? '',
  country: node.country ?? '',
};
for (const sec of fieldsFor(schema, proto, transport, security)) {
  for (const f of sec.fields) {
    const v = getPath(node, f.key);
    if (v === undefined) continue;
    values[f.key] = f.type === 'kv' ? formatKV(v) : Array.isArray(v) ? v.join(',') : v;
  }
}
const out = buildNode(schema, proto, transport, security, values, node);
await Bun.write(process.argv[4], JSON.stringify(out, null, 1));
`
	driverPath := filepath.Join(dir, "driver.ts")
	if err := os.WriteFile(driverPath, []byte(driver), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "rebuilt.json")
	cmd := exec.Command(bun, "run", driverPath,
		filepath.Join(dir, "schema.json"), filepath.Join(dir, "node.json"), out)
	cmd.Dir = frontend
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bun driver failed: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("rebuilt node is not JSON: %v", err)
	}
	return m
}

func write(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The core assertion: editing an inbound without changing anything must not
// change the inbound.
func TestEditingAnInboundPreservesEveryField(t *testing.T) {
	dir := t.TempDir()
	stored := fullXHTTPNode()
	stored.Normalize()
	if err := stored.Validate(); err != nil {
		t.Fatalf("the fixture itself is invalid: %v", err)
	}

	rebuiltRaw := runBuildNode(t, dir, schemaDocument(), stored)

	// Back through the same binding the PUT handler uses.
	b, _ := json.Marshal(rebuiltRaw)
	var got model.Node
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("the rebuilt node does not bind to model.Node: %v", err)
	}
	got.Normalize()
	if err := got.Validate(); err != nil {
		t.Fatalf("the rebuilt node is invalid: %v", err)
	}

	// Tag is assigned by the builder, not by the form.
	want := *stored
	got.Tag, want.Tag = "", ""

	if got.Egress.Key() != want.Egress.Key() {
		t.Errorf("EGRESS LOST: the chain is the whole reason the inbound exists\n got %v\nwant %v", got.Egress, want.Egress)
	}
	if !reflect.DeepEqual(got.Transport.XMux, want.Transport.XMux) {
		t.Errorf("xmux lost or altered:\n got %+v\nwant %+v", got.Transport.XMux, want.Transport.XMux)
	}
	if !reflect.DeepEqual(got.Transport.XHTTPDownload, want.Transport.XHTTPDownload) {
		gb, _ := json.MarshalIndent(got.Transport.XHTTPDownload, "", " ")
		wb, _ := json.MarshalIndent(want.Transport.XHTTPDownload, "", " ")
		t.Errorf("download leg lost or altered:\n got %s\nwant %s", gb, wb)
	}
	if got.Security.Reality == nil || got.Security.Reality.PrivateKey != want.Security.Reality.PrivateKey {
		t.Errorf("REALITY private key lost — the inbound would stop accepting every existing client")
	}
	if !reflect.DeepEqual(got.Transport.Headers, want.Transport.Headers) {
		t.Errorf("headers lost or altered:\n got %v\nwant %v", got.Transport.Headers, want.Transport.Headers)
	}

	// And the whole node, field for field, so a future field cannot slip through
	// the named checks above.
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Errorf("the node changed on a no-op edit.\n got %s\nwant %s", gb, wb)
	}
}

// The rebuilt node must still produce a config the real core accepts. A
// preserved-but-unrenderable node would be a different way to lose the inbound.
func TestRebuiltNodeStillStartsOnTheRealCore(t *testing.T) {
	xray, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray not installed; cannot validate against the real core")
	}
	dir := t.TempDir()
	stored := fullXHTTPNode()
	stored.Normalize()

	rebuiltRaw := runBuildNode(t, dir, schemaDocument(), stored)
	b, _ := json.Marshal(rebuiltRaw)
	var got model.Node
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	got.Normalize()

	in, err := render.XrayInbound(&got)
	if err != nil {
		t.Fatalf("the rebuilt node does not render: %v", err)
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{in},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	path := filepath.Join(dir, "xray.json")
	write(t, path, cfg)

	out, err := exec.Command(xray, "run", "-test", "-c", path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Configuration OK") {
		t.Fatalf("the real core rejected the rebuilt config: %v\n%s", err, out)
	}
}
