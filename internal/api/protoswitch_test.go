package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// realityVLESS is a complete VLESS-REALITY node, the panel's flagship preset, as
// the create endpoint would have produced it.
func realityVLESS(t *testing.T) *model.Node {
	t.Helper()
	n := &model.Node{
		Protocol:  model.ProtoVLESS,
		Remark:    "edge-1",
		Tag:       "in-edge-1",
		Address:   "example.com",
		Port:      443,
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecReality},
	}
	applyCreateDefaults(n)
	if err := n.Validate(); err != nil {
		t.Fatalf("fixture is not a valid node: %v", err)
	}
	return n
}

func fieldNames(fs []FieldChange) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Field)
	}
	return out
}

func hasField(fs []FieldChange, name string) bool {
	for _, f := range fs {
		if f.Field == name {
			return true
		}
	}
	return false
}

// TestSwitchRealityVLESSToTrojanTLS is the headline case: the operator keeps the
// same box and label, gains a password, and loses the VLESS identity and the
// whole REALITY block.
func TestSwitchRealityVLESSToTrojanTLS(t *testing.T) {
	src := realityVLESS(t)
	beforeKey, beforeDest := src.Security.Reality.PrivateKey, src.Security.Reality.Dest

	out, sum := SwitchProtocol(src, model.ProtoTrojan)

	if out.Protocol != model.ProtoTrojan {
		t.Fatalf("want trojan, got %q", out.Protocol)
	}
	if out.Remark != "edge-1" || out.Address != "example.com" || out.Port != 443 {
		t.Errorf("remark/address/port not retained: %+v", out)
	}
	if !hasField(sum.Retained, "remark") || !hasField(sum.Retained, "address") || !hasField(sum.Retained, "port") {
		t.Errorf("summary should report remark/address/port retained, got %v", fieldNames(sum.Retained))
	}

	// Credentials: a fresh password, no leftover uuid.
	if out.Password == "" {
		t.Error("trojan needs a password")
	}
	if out.UUID != "" {
		t.Errorf("the VLESS uuid must not survive, got %q", out.UUID)
	}
	if out.Password == src.UUID {
		t.Error("the uuid was copied into the password field")
	}
	if !hasField(sum.Regenerated, "password") {
		t.Errorf("summary should report the password as regenerated, got %v", fieldNames(sum.Regenerated))
	}
	if !hasField(sum.Reset, "uuid") {
		t.Errorf("summary should report the uuid as reset, got %v", fieldNames(sum.Reset))
	}

	// REALITY is gone and did not leak into the TLS block.
	if out.Security.Type != model.SecTLS {
		t.Errorf("want security tls, got %q", out.Security.Type)
	}
	if out.Security.Reality != nil {
		t.Error("the REALITY block must not survive a switch to TLS")
	}
	if !hasField(sum.Reset, "security.reality") {
		t.Errorf("summary should report security.reality as reset, got %v", fieldNames(sum.Reset))
	}
	if out.Flow != "" {
		t.Errorf("xtls-rprx-vision is VLESS-only, got flow %q", out.Flow)
	}

	// The SNI follows the domain, so it is worth keeping.
	if out.Security.ServerName != src.Security.ServerName {
		t.Errorf("SNI should be retained: %q vs %q", out.Security.ServerName, src.Security.ServerName)
	}

	if err := out.Validate(); err != nil {
		t.Errorf("switched node does not validate: %v", err)
	}
	// Purity: the source node is untouched.
	if src.Protocol != model.ProtoVLESS || src.UUID == "" ||
		src.Security.Reality.PrivateKey != beforeKey || src.Security.Reality.Dest != beforeDest {
		t.Error("SwitchProtocol mutated its input")
	}
}

// TestSwitchTrojanToShadowsocks checks the reverse direction: Shadowsocks has no
// stream TLS layer, so the TLS block goes away and a cipher + PSK are minted.
func TestSwitchTrojanToShadowsocks(t *testing.T) {
	src := &model.Node{
		Protocol: model.ProtoTrojan, Remark: "ss-candidate", Address: "example.com", Port: 8443,
		Transport: model.Transport{Network: model.NetWS, Path: "/ws"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "example.com"},
	}
	applyCreateDefaults(src)
	srcPassword := src.Password

	out, sum := SwitchProtocol(src, model.ProtoShadowsocks)

	if out.Method == "" {
		t.Error("shadowsocks needs a cipher")
	}
	if out.Password == "" {
		t.Error("shadowsocks needs a PSK")
	}
	if out.Password == srcPassword {
		t.Error("the trojan password was carried into the shadowsocks PSK")
	}
	if out.Security.Type != model.SecNone {
		t.Errorf("shadowsocks carries no stream TLS layer, got security %q", out.Security.Type)
	}
	if out.Security.ServerName != "" {
		t.Errorf("no TLS layer means no SNI, got %q", out.Security.ServerName)
	}
	if !hasField(sum.Reset, "security") {
		t.Errorf("summary should report the security layer as reset, got %v", fieldNames(sum.Reset))
	}
	if !hasField(sum.Regenerated, "method") || !hasField(sum.Regenerated, "password") {
		t.Errorf("summary should report method+password regenerated, got %v", fieldNames(sum.Regenerated))
	}
	// Shadowsocks relays UDP on the same port; the summary must say so.
	var udp bool
	for _, p := range sum.RequiredPorts {
		if p.Proto == "udp" && p.Port == 8443 {
			udp = true
		}
	}
	if !udp {
		t.Errorf("shadowsocks needs udp/8443 too, got %+v", sum.RequiredPorts)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("switched node does not validate: %v", err)
	}
}

// TestSwitchRealityIsKeptBetweenRealityCapableProtocols documents the one case
// where TLS-layer material is deliberately retained: REALITY is a property of
// the listener's handshake, so vless-reality -> vmess-reality keeps the
// steal-site and its keypair and does not churn every client.
func TestSwitchRealityToRealityCapableProtocol(t *testing.T) {
	src := realityVLESS(t)
	out, sum := SwitchProtocol(src, model.ProtoVMess)

	if out.Security.Type != model.SecReality || out.Security.Reality == nil {
		t.Fatalf("REALITY should survive vless -> vmess, got %q", out.Security.Type)
	}
	if out.Security.Reality.Dest != src.Security.Reality.Dest {
		t.Errorf("dest changed: %q vs %q", out.Security.Reality.Dest, src.Security.Reality.Dest)
	}
	if out.Security.Reality.PrivateKey != src.Security.Reality.PrivateKey {
		t.Error("the REALITY keypair should be retained, not re-minted")
	}
	if out.UUID == src.UUID {
		t.Error("the uuid is a protocol credential and must still be re-minted")
	}
	if !hasField(sum.Retained, "security.reality.dest") {
		t.Errorf("summary should report the dest retained, got %v", fieldNames(sum.Retained))
	}
	if err := out.Validate(); err != nil {
		t.Errorf("switched node does not validate: %v", err)
	}
}

// TestSwitchRealityToQUICProtocolDropsReality covers an engine change plus a
// TCP->UDP listener change, both of which the operator must be warned about.
func TestSwitchRealityToHysteria2(t *testing.T) {
	src := realityVLESS(t)
	out, sum := SwitchProtocol(src, model.ProtoHysteria2)

	if out.Security.Type != model.SecTLS || out.Security.Reality != nil {
		t.Errorf("hysteria2 is TLS-native and cannot keep REALITY: %+v", out.Security)
	}
	if out.Password == "" {
		t.Error("hysteria2 needs a password")
	}
	if !sum.EngineChanged || sum.ToEngine != "sing-box" {
		t.Errorf("want an engine change to sing-box, got %q -> %q", sum.FromEngine, sum.ToEngine)
	}
	if len(sum.RequiredPorts) == 0 || sum.RequiredPorts[0].Proto != "udp" {
		t.Errorf("hysteria2 listens on UDP, got %+v", sum.RequiredPorts)
	}
	var warnedL4, warnedEngine bool
	for _, w := range sum.Warnings {
		if strings.Contains(w, "tcp") && strings.Contains(w, "udp") {
			warnedL4 = true
		}
		if strings.Contains(w, "engine changes") {
			warnedEngine = true
		}
	}
	if !warnedL4 || !warnedEngine {
		t.Errorf("want L4 and engine warnings, got %v", sum.Warnings)
	}
	if err := out.Validate(); err != nil {
		t.Errorf("switched node does not validate: %v", err)
	}
}

// TestSwitchToEveryProtocolValidates walks the whole protocol matrix: every
// switch must produce a node the canonical validator accepts, so the UI can
// never offer a target that yields a broken inbound.
func TestSwitchToEveryProtocolValidates(t *testing.T) {
	for _, from := range model.AllProtocols() {
		for _, to := range model.AllProtocols() {
			src := &model.Node{Protocol: from, Remark: "matrix", Address: "example.com", Port: 443}
			if from == model.ProtoForgeDNS {
				src.ForgeDNS = &model.ForgeDNSOptions{Adapter: "cottendns", Zone: "t.example.com"}
			}
			applyCreateDefaults(src)

			out, sum := SwitchProtocol(src, to)
			if out.Protocol != to {
				t.Errorf("%s -> %s: got protocol %q", from, to, out.Protocol)
			}
			if out.Port == 0 {
				t.Errorf("%s -> %s: port not carried", from, to)
			}
			if len(sum.RequiredPorts) == 0 {
				t.Errorf("%s -> %s: no required ports reported", from, to)
			}
			// A credential must never survive into a protocol that has no slot
			// for it -- Normalize enforces this, and this is the regression net.
			if out.UUID != "" && !usesCredential(to, "uuid") {
				t.Errorf("%s -> %s: uuid leaked", from, to)
			}
			if out.Password != "" && !usesCredential(to, "password") {
				t.Errorf("%s -> %s: password leaked", from, to)
			}
			if err := out.Validate(); err != nil {
				// The single legitimate gap: forgedns needs a delegated zone the
				// panel cannot invent. The summary must say so rather than
				// pretend the switch produced a working inbound.
				var warned bool
				for _, w := range sum.Warnings {
					warned = warned || strings.Contains(w, "delegated zone")
				}
				if to != model.ProtoForgeDNS || !warned {
					t.Errorf("%s -> %s: %v (warnings %v)", from, to, err, sum.Warnings)
				}
			}
		}
	}
}

// TestSwitchToSameProtocolIsANoop: re-selecting the protocol a node already
// speaks must not churn its credentials, or a stray UI click would invalidate
// every issued client link.
func TestSwitchToSameProtocolIsANoop(t *testing.T) {
	src := realityVLESS(t)
	out, sum := SwitchProtocol(src, model.ProtoVLESS)

	if out.UUID != src.UUID || out.Security.Reality.PrivateKey != src.Security.Reality.PrivateKey {
		t.Error("a same-protocol switch must not re-mint credentials")
	}
	if len(sum.Reset) != 0 || len(sum.Regenerated) != 0 {
		t.Errorf("nothing should be reset or regenerated: reset=%v regenerated=%v",
			fieldNames(sum.Reset), fieldNames(sum.Regenerated))
	}
	if len(sum.Warnings) != 0 {
		t.Errorf("a no-op needs no warnings, got %v", sum.Warnings)
	}
}

// TestSwitchPreviewRoute exercises the handler exactly as the documented route
// would, so the contract is verified without this file touching server.go.
func TestSwitchPreviewRoute(t *testing.T) {
	s := testServer(t)
	r := gin.New()
	r.POST("/api/protocols/switch/preview", s.handleProtocolSwitchPreview)

	body := `{"node":{"protocol":"vless","remark":"edge-1","address":"example.com","port":443,
	  "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","transport":{"network":"tcp"},
	  "security":{"type":"tls","server_name":"example.com"}},"target_protocol":"trojan"}`
	req := httptest.NewRequest(http.MethodPost, "/api/protocols/switch/preview", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp SwitchPreviewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Node == nil || resp.Node.Protocol != model.ProtoTrojan || resp.Node.Password == "" {
		t.Fatalf("preview did not produce a trojan node: %+v", resp.Node)
	}
	if resp.Summary.ToEngine != "xray" || resp.Summary.EngineChanged {
		t.Errorf("vless -> trojan stays on xray, got %q -> %q", resp.Summary.FromEngine, resp.Summary.ToEngine)
	}
	// The preview must never echo a credential back in the summary.
	raw := rec.Body.String()
	for _, f := range resp.Summary.Regenerated {
		if f.Value != "" {
			t.Errorf("summary carries a value for credential field %q", f.Field)
		}
	}
	if strings.Count(raw, resp.Node.Password) != 1 {
		t.Error("the minted password should appear only in the preview node, not in the summary")
	}

	// An unknown target is rejected at the boundary.
	req = httptest.NewRequest(http.MethodPost, "/api/protocols/switch/preview",
		strings.NewReader(`{"node":{"protocol":"vless"},"target_protocol":"nope"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("want 400 for an unknown protocol, got %d", rec.Code)
	}
}

// TestDeployComposeRoute checks the compose endpoint returns a file and rejects
// an empty selection, listing what is valid.
func TestDeployComposeRoute(t *testing.T) {
	s := testServer(t)
	r := gin.New()
	r.GET("/api/deploy/compose", s.handleDeployCompose)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/deploy/compose?profiles=xray,singbox", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"services:", "xray:", "singbox:", "cap_drop"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("compose output missing %q", want)
		}
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/deploy/compose", nil))
	if rec.Code != 400 {
		t.Errorf("want 400 with no profiles, got %d", rec.Code)
	}
}

// TestSwitchProtocolHandlesNilSource guards the API boundary: a missing node
// must not panic the handler's pure core.
func TestSwitchProtocolHandlesNilSource(t *testing.T) {
	out, sum := SwitchProtocol(nil, model.ProtoVLESS)
	if out == nil || out.Protocol != model.ProtoVLESS {
		t.Fatalf("want a fresh vless node, got %+v", out)
	}
	if out.UUID == "" {
		t.Error("a fresh node still gets credentials")
	}
	if sum.ToProtocol != string(model.ProtoVLESS) {
		t.Errorf("summary target is wrong: %q", sum.ToProtocol)
	}
}
