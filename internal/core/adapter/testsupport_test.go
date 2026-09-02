package adapter

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// testCert / testKey are paths, never files: the aggregator only ever writes
// these strings into a rendered inbound, it does not read them, so a test that
// created real certificates would only be testing the certificate package.
const (
	testCert = "/var/lib/forgepanel/certs/fullchain.pem"
	testKey  = "/var/lib/forgepanel/certs/privkey.pem"
)

// matrixNodes is one valid inbound per engine and per interesting variant,
// every port distinct. Ports must be distinct because the aggregator derives an
// inbound tag from the port, and the AmneziaWG adapter keys its configs by it —
// a duplicate would make two inbounds indistinguishable and hide exactly the
// kind of collision these tests exist to catch.
func matrixNodes(t *testing.T) []*model.Node {
	t.Helper()
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	psk128, err := keygen.SS2022PSK(model.SS2022AES128)
	if err != nil {
		t.Fatalf("ss2022 psk: %v", err)
	}
	tls := func(sni string) model.Security {
		return model.Security{Type: model.SecTLS, ServerName: sni}
	}
	nodes := []*model.Node{
		{Remark: "vless-tcp", Protocol: model.ProtoVLESS, Address: "203.0.113.1", Port: 30001, UUID: uuid,
			Transport: model.Transport{Network: model.NetTCP}},
		{Remark: "vless-ws-tls", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 30002, UUID: uuid,
			Transport: model.Transport{Network: model.NetWS, Path: "/ws", Host: "a.example.com"}, Security: tls("a.example.com")},
		{Remark: "vless-xhttp", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 30003, UUID: uuid,
			Transport: model.Transport{Network: model.NetXHTTP, Path: "/xh", XHTTPMode: "auto"}, Security: tls("a.example.com")},
		{Remark: "vmess-grpc-tls", Protocol: model.ProtoVMess, Address: "203.0.113.2", Port: 30004, UUID: uuid,
			Transport: model.Transport{Network: model.NetGRPC, ServiceName: "svc"}, Security: tls("b.example.com")},
		{Remark: "trojan-tcp-tls", Protocol: model.ProtoTrojan, Address: "203.0.113.3", Port: 30005, Password: "trojanpw",
			Transport: model.Transport{Network: model.NetTCP}, Security: tls("c.example.com")},
		{Remark: "ss-chacha", Protocol: model.ProtoShadowsocks, Address: "203.0.113.4", Port: 30006,
			Method: model.SSChaCha20Poly, Password: "sspw"},
		{Remark: "ss-2022", Protocol: model.ProtoShadowsocks, Address: "203.0.113.5", Port: 30007,
			Method: model.SS2022AES128, Password: psk128},
		{Remark: "socks", Protocol: model.ProtoSOCKS, Address: "203.0.113.6", Port: 30008, Username: "u", Password: "p"},
		{Remark: "http", Protocol: model.ProtoHTTP, Address: "203.0.113.7", Port: 30009, Username: "u", Password: "p"},

		{Remark: "hy2", Protocol: model.ProtoHysteria2, Address: "203.0.113.8", Port: 30010, Password: "hy2pw",
			Security:  model.Security{Type: model.SecTLS, ServerName: "hy.example.com"},
			Hysteria2: &model.Hysteria2Options{UpMbps: 100, DownMbps: 200}},
		{Remark: "tuic", Protocol: model.ProtoTUIC, Address: "203.0.113.9", Port: 30011, UUID: uuid, Password: "tuicpw",
			Security: model.Security{Type: model.SecTLS, ServerName: "tuic.example.com"},
			TUIC:     &model.TUICOptions{HeartbeatSeconds: 10}},
		{Remark: "anytls", Protocol: model.ProtoAnyTLS, Address: "203.0.113.10", Port: 30012, Password: "anytlspw",
			Security: tls("any.example.com")},
		{Remark: "shadowtls", Protocol: model.ProtoShadowTLS, Address: "203.0.113.11", Port: 30013,
			ShadowTLS: &model.ShadowTLSOptions{Version: 3, Password: "hs", HandshakeHost: "www.apple.com", HandshakePort: 443}},
		{Remark: "ssh", Protocol: model.ProtoSSH, Address: "203.0.113.12", Port: 30014,
			SSH: &model.SSHOptions{User: "root", Password: "pw"}},
		{Remark: "wireguard", Protocol: model.ProtoWireGuard, Address: "203.0.113.13", Port: 30015,
			WireGuard: &model.WireGuardOptions{PrivateKey: "sk", PublicKey: "pk", PeerPrivateKey: "csk", PeerPublicKey: "cpk",
				ServerAddress: []string{"10.66.66.1/24"}, PeerAddress: []string{"10.66.66.2/32"}}},

		{Remark: "amneziawg", Protocol: model.ProtoAmneziaWG, Address: "203.0.113.14", Port: 30016,
			AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
				PrivateKey: "sk", PublicKey: "pk", PeerPrivateKey: "csk", PeerPublicKey: "cpk",
				ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"}}}},

		{Remark: "brook", Protocol: model.ProtoBrook, Address: "203.0.113.15", Port: 30017, Password: "brookpw",
			Brook: &model.BrookOptions{Mode: "wsserver", Path: "/b"}},

		{Remark: "forgedns", Protocol: model.ProtoForgeDNS, Address: "dns.example.com", Port: 30018,
			ForgeDNS: &model.ForgeDNSOptions{Adapter: "stormdns", Zone: "dns.example.com", Key: "k", NSHost: "ns1.example.com"}},
	}
	for _, n := range nodes {
		n.Normalize()
		if err := n.Validate(); err != nil {
			t.Fatalf("test fixture %q is not a valid inbound: %v", n.Remark, err)
		}
	}
	return nodes
}

func specsOf(nodes []*model.Node) []engine.InboundSpec {
	out := make([]engine.InboundSpec, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, engine.InboundSpec{Node: n})
	}
	return out
}

func nodesWithProtocol(nodes []*model.Node, p model.Protocol) []*model.Node {
	var out []*model.Node
	for _, n := range nodes {
		if n.Protocol == p {
			out = append(out, n)
		}
	}
	return out
}

// fakeBins is a BinaryResolver that never downloads. It records every Ensure so
// a test can prove the adapters do not fetch a core for a plan that has no
// inbound for it.
type fakeBins struct {
	dir string
	err error

	mu      sync.Mutex
	ensured []binmgr.Engine
}

func (f *fakeBins) Path(e binmgr.Engine) string { return filepath.Join(f.dir, string(e)) }

// Present mirrors the real resolver: on disk and non-empty. The tests write real
// stub binaries, so this answers truthfully rather than always saying yes — a
// double that always claims presence would hide a caller that skips validation.
func (f *fakeBins) Present(e binmgr.Engine) bool {
	st, err := os.Stat(f.Path(e))
	return err == nil && !st.IsDir() && st.Size() > 0
}

func (f *fakeBins) Ensure(e binmgr.Engine) (string, error) {
	f.mu.Lock()
	f.ensured = append(f.ensured, e)
	f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	return f.Path(e), nil
}

func (f *fakeBins) calls() []binmgr.Engine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]binmgr.Engine(nil), f.ensured...)
}

// fakeCore is a stand-in core binary: it answers `version`, accepts any config
// offered to `-test` / `check`, and otherwise stays alive until it is signalled.
// It lets the supervised adapter be driven end to end without downloading a
// 30MB release in a unit test.
const fakeCore = `#!/bin/sh
case "$1" in
  version|-version) echo "fake-core 9.9.9"; exit 0 ;;
esac
for a in "$@"; do
  if [ "$a" = "-test" ] || [ "$a" = "check" ]; then exit 0; fi
done
echo "fake-core started" 1>&2
while true; do sleep 1; done
`

// rejectingCore refuses every config, the way a real core refuses one it cannot
// parse.
const rejectingCore = `#!/bin/sh
case "$1" in
  version|-version) echo "fake-core 9.9.9"; exit 0 ;;
esac
echo "fake-core: config rejected" 1>&2
exit 1
`

func writeFakeCore(t *testing.T, path, script string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// fakeBrook records what the Brook reconciler was asked to do.
type fakeBrook struct {
	mu       sync.Mutex
	synced   [][]*model.Node
	cert     string
	key      string
	stops    int
	err      error
	statuses []map[string]any
}

func (f *fakeBrook) Sync(nodes []*model.Node, certPath, keyPath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, nodes)
	f.cert, f.key = certPath, keyPath
	return f.err
}

func (f *fakeBrook) StopAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeBrook) Status() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses
}

func (f *fakeBrook) lastSync() []*model.Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.synced) == 0 {
		return nil
	}
	return f.synced[len(f.synced)-1]
}

func (f *fakeBrook) syncCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.synced)
}

// fakeAWG records what the AmneziaWG reconciler was asked to do.
type fakeAWG struct {
	mu       sync.Mutex
	synced   [][]*model.Node
	stops    int
	err      error
	statuses []map[string]any
	kernel   map[string]any
}

func (f *fakeAWG) Sync(nodes []*model.Node) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, nodes)
	return f.err
}

func (f *fakeAWG) StopAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
}

func (f *fakeAWG) Status() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses
}

func (f *fakeAWG) KernelStatus() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.kernel == nil {
		return map[string]any{"tools_installed": false, "module_loaded": false, "kernel_ready": false, "last_error": ""}
	}
	return f.kernel
}

func (f *fakeAWG) lastSync() []*model.Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.synced) == 0 {
		return nil
	}
	return f.synced[len(f.synced)-1]
}

// fakeAdapter is a minimal CoreAdapter for registry tests: it needs no binaries
// and no host state, so registry behaviour can be tested without any core.
type fakeAdapter struct {
	name   string
	protos []model.Protocol
	nets   []model.Network
}

func (s *fakeAdapter) Name() string                         { return s.name }
func (s *fakeAdapter) SupportedProtocols() []model.Protocol { return s.protos }
func (s *fakeAdapter) SupportedTransports() []model.Network { return s.nets }
func (s *fakeAdapter) Supports(n *model.Node) error         { return supportsNode(s, n) }
func (s *fakeAdapter) Detect() (bool, string, error)        { return false, "", nil }
func (s *fakeAdapter) ValidateConfig([]byte) error          { return nil }
func (s *fakeAdapter) Start(context.Context) error          { return nil }
func (s *fakeAdapter) Stop(context.Context) error           { return nil }
func (s *fakeAdapter) Restart(context.Context) error        { return nil }
func (s *fakeAdapter) Reload(context.Context) error         { return nil }
func (s *fakeAdapter) Apply(context.Context, Plan) error    { return nil }
func (s *fakeAdapter) GenerateConfig([]*model.Node) ([]byte, error) {
	return []byte("{}"), nil
}
func (s *fakeAdapter) HealthCheck(context.Context) (Health, error) {
	return Health{Engine: s.name, State: StateStopped}, nil
}
