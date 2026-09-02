package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Multi-hop chains: client -> entry (this server) -> hop0 -> hop1 -> internet.
//
// The routing rule must point at the LAST hop, because each hop reaches its own
// server THROUGH the one before it. Pointing it at the first hop is the
// natural-looking mistake and produces a working single-hop tunnel, which is
// exactly why it would ship unnoticed.

const (
	hopVLESS = "vless://11111111-2222-4333-8444-555555555555@203.0.113.50:443?" +
		"security=reality&sni=www.cloudflare.com&fp=chrome&pbk=xh8kL1s5H8k6VYwB4nCq3rJ0mE9xZQ7YtA2sD4fG6hU&sid=0123abcd&type=tcp#hop1"
	hopTrojan = "trojan://hunter2hunter2@203.0.113.60:443?security=tls&sni=example.com&type=tcp#hop2"
	hopSS     = "ss://YWVzLTI1Ni1nY206aHVudGVyMg@203.0.113.70:8388#hop3"
)

func threeHop() model.EgressChain {
	return model.EgressChain{hopVLESS, hopTrojan, hopSS}
}

func outboundsByTag(t *testing.T, cfg map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	arr, _ := cfg["outbounds"].([]any)
	for _, e := range arr {
		m, _ := e.(map[string]any)
		if tag, ok := m["tag"].(string); ok {
			out[tag] = m
		}
	}
	return out
}

// --- Xray -------------------------------------------------------------------

func TestXrayChainDialsEachHopThroughThePrevious(t *testing.T) {
	n := chainNode("chained", 20801, "")
	n.Egress = threeHop()
	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 0 {
		t.Fatalf("inbound skipped: %+v", b.Skipped)
	}
	cfg := xrayObj(t, b)
	outs := outboundsByTag(t, cfg)

	for i := 0; i < 3; i++ {
		tag := chainTag(0, i)
		o, ok := outs[tag]
		if !ok {
			t.Fatalf("hop %d (%s) is missing; outbounds = %v", i, tag, keysOf(outs))
		}
		dialer := xrayDialerProxy(o)
		if i == 0 {
			if dialer != "" {
				t.Errorf("the first hop dials through %q; it must be dialled directly", dialer)
			}
			continue
		}
		if want := chainTag(0, i-1); dialer != want {
			t.Errorf("hop %d dials through %q, want %q — the chain is not linked", i, dialer, want)
		}
	}

	// The rule must target the EXIT, not the entry hop.
	routing, _ := cfg["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	last, _ := rules[len(rules)-1].(map[string]any)
	got, _ := last["outboundTag"].(string)
	if want := chainTag(0, 2); got != want {
		t.Fatalf("traffic is routed to %q, want the exit %q. Routing to the first hop yields a "+
			"working SINGLE-hop tunnel, which is why this must be asserted.", got, want)
	}
}

func xrayDialerProxy(o map[string]any) string {
	ss, _ := o["streamSettings"].(map[string]any)
	if ss == nil {
		return ""
	}
	sock, _ := ss["sockopt"].(map[string]any)
	if sock == nil {
		return ""
	}
	s, _ := sock["dialerProxy"].(string)
	return s
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- sing-box ---------------------------------------------------------------

// The headline case: Hysteria2 is a sing-box protocol, so a chained hy2 inbound
// exercises the sing-box side of the chain end to end.
func TestHysteria2ChainDetoursThroughEachHop(t *testing.T) {
	n := sbChainNode(model.ProtoHysteria2, "hy2-chained", 20802, "")
	n.Egress = threeHop()
	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 0 {
		t.Fatalf("inbound skipped: %+v", b.Skipped)
	}
	cfg := singboxObj(t, b)
	outs := outboundsByTag(t, cfg)

	for i := 0; i < 3; i++ {
		o, ok := outs[chainTag(0, i)]
		if !ok {
			t.Fatalf("hop %d is missing; outbounds = %v", i, keysOf(outs))
		}
		detour, _ := o["detour"].(string)
		if i == 0 {
			if detour != "" {
				t.Errorf("the first hop detours through %q; it must be dialled directly", detour)
			}
			continue
		}
		if want := chainTag(0, i-1); detour != want {
			t.Errorf("hop %d detours through %q, want %q", i, detour, want)
		}
	}

	route, _ := cfg["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	r, _ := rules[0].(map[string]any)
	got, _ := r["outbound"].(string)
	if want := chainTag(0, 2); got != want {
		t.Fatalf("hy2 traffic is routed to %q, want the exit %q", got, want)
	}
}

// Two inbounds on the SAME chain share one set of outbounds; a different chain
// gets its own. Dialling the same path twice doubles the connections to every
// hop for no benefit.
func TestIdenticalChainsAreDialledOnce(t *testing.T) {
	a := chainNode("a", 20803, "")
	a.Egress = threeHop()
	bNode := chainNode("b", 20804, "")
	bNode.Egress = threeHop()
	c := chainNode("c", 20805, "")
	c.Egress = model.EgressChain{hopSS} // a different path

	b, err := BuildMulti([]InboundSpec{{Node: a}, {Node: bNode}, {Node: c}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	cfg := xrayObj(t, b)
	n := 0
	for _, tag := range tagsOf(t, cfg, "outbounds") {
		if strings.HasPrefix(tag, "egress-") {
			n++
		}
	}
	if n != 4 { // three hops shared + one for the distinct chain
		t.Fatalf("expected 4 egress outbounds (3 shared + 1), got %d", n)
	}
}

// A broken hop ANYWHERE in the chain must skip the inbound, and say which hop.
// Falling through to a direct exit is the one outcome a chain exists to prevent.
func TestABrokenMiddleHopSkipsTheInboundAndNamesIt(t *testing.T) {
	n := chainNode("bad-middle", 20806, "")
	n.Egress = model.EgressChain{hopVLESS, "not-a-uri://nonsense", hopSS}
	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, "", "")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if len(b.Skipped) != 1 {
		t.Fatalf("expected the inbound to be skipped, got %+v", b.Skipped)
	}
	reason := b.Skipped[0].Reason
	if !strings.Contains(reason, "hop 2 of 3") {
		t.Fatalf("the reason should name the failing hop, got %q", reason)
	}
	cfg := xrayObj(t, b)
	if ins, _ := cfg["inbounds"].([]any); len(ins) != 1 { // api only
		t.Fatalf("the unusable inbound must not be served; inbounds = %d", len(ins))
	}
}

// --- the engines' own validators --------------------------------------------

func engineBin(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	t.Skipf("%s not installed", name)
	return ""
}

// A chain that the panel renders but the core rejects is worse than no chain:
// the config is replaced as a whole, so one bad chain takes every inbound down.
func TestXrayAcceptsAChainedConfig(t *testing.T) {
	bin := engineBin(t, "xray")
	n := chainNode("chained", 20807, "")
	n.Egress = threeHop()
	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, "", "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Configuration OK") {
		t.Fatalf("xray rejected the chained config: %v\n%s", err, out)
	}
}

func TestSingboxAcceptsAChainedHysteria2Config(t *testing.T) {
	bin := singboxBinary(t)
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)

	n := sbChainNode(model.ProtoHysteria2, "hy2-chained", 20808, "")
	n.Egress = threeHop()
	n.Security.CertificateFile = certPath
	n.Security.KeyFile = keyPath

	b, err := BuildMulti([]InboundSpec{{Node: n}}, 10099, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Skipped) != 0 {
		t.Fatalf("skipped: %+v", b.Skipped)
	}
	path := filepath.Join(dir, "singbox.json")
	if err := os.WriteFile(path, b.Singbox, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box rejected the chained hysteria2 config: %v\n%s\n---\n%s", err, out, b.Singbox)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// singboxBinary finds the pinned sing-box the harness caches, falling back to
// one on PATH. sing-box is not usually installed system-wide, so without the
// cache lookup this whole file would silently skip.
func singboxBinary(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err == nil {
		matches, _ := filepath.Glob(filepath.Join(root, "test", "harness", ".cache", "bin", "sing-box-*", "sing-box"))
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.Mode()&0o111 != 0 {
				return m
			}
		}
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	t.Skip("sing-box not available")
	return ""
}

// writeSelfSigned mints a certificate, because a TLS-terminating inbound will
// not pass the core's own validator without one.
func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "c.pem")
	keyPath = filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
