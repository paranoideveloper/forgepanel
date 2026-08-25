package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// ReloadSpecs handed BuildMulti the self-signed pair unconditionally, so a TLS
// inbound on a domain the panel held a real Let's Encrypt certificate for was
// still served a self-signed one — and every client had to be told to skip
// verification, which is the exact posture the certificate exists to remove.
//
// These tests drive the resolver seam rather than the whole panel, because the
// bug was entirely in which paths reach the generated config.

func tlsNode(remark string, port int, sni string) *model.Node {
	n := &model.Node{
		Protocol: model.ProtoVLESS,
		Address:  "0.0.0.0",
		Port:     port,
		Remark:   remark,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Security: model.Security{Type: model.SecTLS, ServerName: sni},
	}
	n.Normalize()
	return n
}

func certPathsIn(t *testing.T, b *engine.Bundle) []string {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(b.Xray, &cfg); err != nil {
		t.Fatalf("xray config is not JSON: %v", err)
	}
	var out []string
	ins, _ := cfg["inbounds"].([]any)
	for _, e := range ins {
		m, _ := e.(map[string]any)
		ss, _ := m["streamSettings"].(map[string]any)
		tlsSet, _ := ss["tlsSettings"].(map[string]any)
		certs, _ := tlsSet["certificates"].([]any)
		for _, c := range certs {
			cm, _ := c.(map[string]any)
			if p, ok := cm["certificateFile"].(string); ok {
				out = append(out, p)
			}
		}
	}
	return out
}

// The regression: a real certificate must reach the generated config.
func TestRealCertificateReachesTheEngineConfig(t *testing.T) {
	c := NewController(t.TempDir(), 10099)
	c.SetCertResolver(func(sni string) (string, string, bool) {
		if sni == "real.example.com" {
			return "/live/real.crt", "/live/real.key", true
		}
		return "", "", false
	})

	specs := []engine.InboundSpec{{Node: tlsNode("real", 20601, "real.example.com")}}
	c.mu.Lock()
	c.applyCerts(specs)
	c.mu.Unlock()

	if specs[0].CertPath != "/live/real.crt" {
		t.Fatalf("the resolver's certificate never reached the spec: %q", specs[0].CertPath)
	}

	b, err := engine.BuildMulti(specs, 10099, "/self/signed.crt", "/self/signed.key")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	paths := certPathsIn(t, b)
	if len(paths) == 0 {
		t.Fatalf("no certificate reached the config at all")
	}
	for _, p := range paths {
		if strings.Contains(p, "self") {
			t.Fatalf("the inbound is served the SELF-SIGNED certificate (%s) although a real one exists", p)
		}
	}
}

// An inbound with no matching certificate must still get the self-signed pair,
// or it stops serving TLS entirely.
func TestInboundWithoutARealCertificateKeepsTheSelfSignedFallback(t *testing.T) {
	c := NewController(t.TempDir(), 10099)
	c.SetCertResolver(func(string) (string, string, bool) { return "", "", false })

	specs := []engine.InboundSpec{{Node: tlsNode("plain", 20602, "unknown.example.com")}}
	c.mu.Lock()
	c.applyCerts(specs)
	c.mu.Unlock()

	b, err := engine.BuildMulti(specs, 10099, "/self/signed.crt", "/self/signed.key")
	if err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	paths := certPathsIn(t, b)
	if len(paths) != 1 || !strings.Contains(paths[0], "self") {
		t.Fatalf("expected the self-signed fallback, got %v", paths)
	}
}

// REALITY borrows another site's certificate by design. Handing it one of ours
// would be meaningless, and asking the store for it wastes a lookup per reload.
func TestRealityIsNotGivenACertificate(t *testing.T) {
	c := NewController(t.TempDir(), 10099)
	asked := 0
	c.SetCertResolver(func(string) (string, string, bool) { asked++; return "/x.crt", "/x.key", true })

	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 20603,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Security: model.Security{Type: model.SecReality, ServerName: "www.cloudflare.com"},
	}
	n.Normalize()
	specs := []engine.InboundSpec{{Node: n}}
	c.mu.Lock()
	c.applyCerts(specs)
	c.mu.Unlock()

	if asked != 0 {
		t.Errorf("the certificate store was consulted for a REALITY inbound")
	}
	if specs[0].CertPath != "" {
		t.Errorf("a REALITY inbound was given a certificate path (%q)", specs[0].CertPath)
	}
}

// Building a config must not write into the caller's node. Specs carry pointers
// straight out of the store, so stamping a certificate path onto them meant a
// later save persisted a path the operator never chose.
func TestBuildingDoesNotMutateTheStoredNode(t *testing.T) {
	n := tlsNode("stored", 20604, "real.example.com")
	specs := []engine.InboundSpec{{Node: n, CertPath: "/live/real.crt", KeyPath: "/live/real.key"}}

	if _, err := engine.BuildMulti(specs, 10099, "/self/signed.crt", "/self/signed.key"); err != nil {
		t.Fatalf("BuildMulti: %v", err)
	}
	if n.Security.CertificateFile != "" || n.Security.KeyFile != "" {
		t.Fatalf("BuildMulti wrote certificate paths into the caller's node: %q / %q",
			n.Security.CertificateFile, n.Security.KeyFile)
	}
	if n.Tag != "" {
		t.Fatalf("BuildMulti wrote a tag into the caller's node: %q", n.Tag)
	}
}

// The self-signed pair still has to exist, since it is what every inbound
// without a real certificate falls back to.
func TestSelfSignedFallbackIsStillGenerated(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir, 10099)
	_ = c
	if _, err := engine.BuildMulti(nil, 10099, filepath.Join(dir, "x.crt"), filepath.Join(dir, "x.key")); err != nil {
		t.Fatalf("BuildMulti with no specs: %v", err)
	}
}
