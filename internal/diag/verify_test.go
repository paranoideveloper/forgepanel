package diag

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TestVerifyCarriesRealTrafficVMess is the §3 Layer-3 / BUG-2 proof: a real
// sing-box server + client, built from ONE canonical node, must carry an HTTP
// request end to end. If the client link and the server inbound disagreed, no
// bytes would arrive. Skips cleanly when sing-box is absent.
func TestVerifyCarriesRealTrafficVMess(t *testing.T) {
	if FindSingbox() == "" {
		t.Skip("sing-box not installed")
	}
	n := &model.Node{
		Protocol: model.ProtoVMess, Address: "0.0.0.0", Port: 0,
		UUID:      keygen.UUID(),
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecNone},
	}
	n.Normalize()
	res := VerifySingbox(context.Background(), n, Cores{})
	if !res.Pass {
		t.Fatalf("vmess round trip failed: %s\nclient log:\n%s", res.Finding.Detail, res.ClientLog)
	}
	if res.LatencyMs < 0 {
		t.Fatalf("bad latency: %d", res.LatencyMs)
	}
	t.Logf("vmess verified end to end in %dms", res.LatencyMs)
}

// TestVerifyCarriesRealTrafficShadowsocks covers a second, TLS-free protocol.
func TestVerifyCarriesRealTrafficShadowsocks(t *testing.T) {
	if FindSingbox() == "" {
		t.Skip("sing-box not installed")
	}
	psk, err := keygen.SS2022PSK("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	n := &model.Node{
		Protocol: model.ProtoShadowsocks, Address: "0.0.0.0", Port: 0,
		Method: "2022-blake3-aes-128-gcm", Password: psk,
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecNone},
	}
	n.Normalize()
	res := VerifySingbox(context.Background(), n, Cores{})
	if !res.Pass {
		t.Fatalf("ss round trip failed: %s\nclient log:\n%s", res.Finding.Detail, res.ClientLog)
	}
	t.Logf("shadowsocks verified end to end in %dms", res.LatencyMs)
}

// TestVerifyRealityIsHonestlyUnprovable: REALITY cannot be verified offline; the
// engine must say so rather than claim a false pass or a false fail.
func TestVerifyRealityIsHonestlyUnprovable(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443,
		Security: model.Security{Type: model.SecReality}}
	res := VerifySingbox(context.Background(), n, Cores{})
	if res.Pass {
		t.Fatal("REALITY should not report a pass offline")
	}
	if !res.Unprovable {
		t.Fatal("REALITY should be reported as Unprovable (not a failure)")
	}
}

func TestVerifyUDPProtocolsAreUnprovableNotFailed(t *testing.T) {
	for _, p := range []model.Protocol{model.ProtoTUIC, model.ProtoHysteria2, model.ProtoWireGuard} {
		res := VerifySingbox(context.Background(), &model.Node{Protocol: p, Port: 443}, Cores{})
		if res.Pass || !res.Unprovable {
			t.Fatalf("%s should be Unprovable (not pass, not fail), got %+v", p, res)
		}
	}
}

var _ = time.Second

// --- failure taxonomy ------------------------------------------------------

// TestVerifyUnprovableIsCatalogued: FP-VERIFY-UNPROVABLE was emitted by
// VerifySingbox but was never added to the Catalogue, so New() fell back to
// stamping the raw code into TitleEN and shipped it with no Farsi title, no Why
// and no Fix — the one verdict a REALITY or QUIC inbound ever gets was the one
// verdict the UI could not explain.
func TestVerifyUnprovableIsCatalogued(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443,
		Security: model.Security{Type: model.SecReality}}
	f := VerifySingbox(context.Background(), n, Cores{}).Finding
	if f.Code != "FP-VERIFY-UNPROVABLE" {
		t.Fatalf("REALITY verdict code = %q", f.Code)
	}
	if f.TitleEN == f.Code {
		t.Error("TitleEN is the raw code — the finding fell through New()'s uncatalogued fallback")
	}
	if f.TitleFA == "" {
		t.Error("no Farsi title: the panel is bilingual and this is a user-facing verdict")
	}
	if f.Why == "" || f.Fix == "" {
		t.Errorf("catalogue entry missing Why/Fix: %+v", f)
	}
	if f.Severity != SevInfo {
		t.Errorf("unprovable is NOT a failure; severity = %q", f.Severity)
	}
}

// TestVerifyReportsCoreDownNotGenericFailure: when the core itself never runs,
// the verdict must say so. It used to be the same FP-VERIFY-FAIL ("no traffic
// carried") an inbound gets for a wrong password, which sent operators auditing
// credentials for a problem that never reached the inbound.
func TestVerifyReportsCoreDownNotGenericFailure(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVMess, Address: "0.0.0.0", Port: 0,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecNone},
	}
	n.Normalize()
	// A path that exists as a name but is not an executable core: rendering
	// succeeds, so this exercises the "core will not run" branch specifically.
	res := VerifySingbox(context.Background(), n, Cores{Singbox: filepath.Join(t.TempDir(), "sing-box")})
	if res.Pass {
		t.Fatal("a missing core must not report a pass")
	}
	if res.Finding.Code != "FP-VERIFY-CORE-DOWN" {
		t.Fatalf("core failure reported as %q (%s)", res.Finding.Code, res.Finding.Detail)
	}
}

func TestClassifyVerifyFailure(t *testing.T) {
	const body = "forgepanel-verify-ok"
	cases := []struct {
		name string
		err  error
		got  string
		log  string
		want string
	}{
		{"payload mangled", nil, "", body, "FP-VERIFY-NO-DATA"},
		{"payload truncated", nil, "forgepanel", body, "FP-VERIFY-NO-DATA"},
		{"auth rejected", errors.New("socks connect tcp: general SOCKS server failure"),
			"", "ERROR inbound/vmess[0]: authentication failed", "FP-VERIFY-AUTH"},
		{"bad password", errors.New("socks connect tcp: general SOCKS server failure"),
			"", "ERROR shadowsocks: invalid password", "FP-VERIFY-AUTH"},
		{"tls handshake", errors.New("unexpected EOF"),
			"", "ERROR outbound/vless: tls: handshake failure", "FP-VERIFY-HANDSHAKE"},
		{"bad certificate", errors.New("socks connect tcp: general SOCKS server failure"),
			"", "x509: certificate signed by unknown authority", "FP-VERIFY-HANDSHAKE"},
		{"refused", errors.New("dial tcp 127.0.0.1:1080: connect: connection refused"), "", "", "FP-VERIFY-NET-UNREACHABLE"},
		{"timed out", errors.New("i/o timeout"), "", "", "FP-VERIFY-NET-UNREACHABLE"},
		// Nothing in the evidence names a cause, so nothing is invented.
		{"no evidence", errors.New("socks connect tcp: unknown error"), "", "", "FP-VERIFY-FAIL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyVerifyFailure(c.err, c.got, body, c.log, ""); got != c.want {
				t.Fatalf("classifyVerifyFailure = %s want %s", got, c.want)
			}
			// Whatever it picked must be a real catalogue entry, or the UI shows
			// a bare code with no explanation.
			if _, ok := Catalogue[c.want]; !ok {
				t.Fatalf("%s is not in the Catalogue", c.want)
			}
		})
	}
}

// An auth rejection also tears the connection down, so the log carries reset/EOF
// noise alongside the real cause. Network-first ordering would label it
// unreachable and point the operator at the firewall instead of the credentials.
func TestClassifyPrefersAuthOverConnectionNoise(t *testing.T) {
	got := classifyVerifyFailure(errors.New("unexpected EOF"), "", "body",
		"ERROR inbound/trojan: authentication failed\nERROR connection reset by peer", "")
	if got != "FP-VERIFY-AUTH" {
		t.Fatalf("auth rejection classified as %s", got)
	}
}

func TestVerifySuccessCodeGradesDegraded(t *testing.T) {
	if got := verifySuccessCode(12); got != "FP-VERIFY-OK" {
		t.Errorf("a 12ms loopback round trip graded %s", got)
	}
	if got := verifySuccessCode(degradedLatencyMs + 1); got != "FP-VERIFY-DEGRADED" {
		t.Errorf("a %dms loopback round trip graded %s", degradedLatencyMs+1, got)
	}
	if Catalogue["FP-VERIFY-DEGRADED"].Severity != SevWarning {
		t.Error("a degraded pass is a warning, not a critical: traffic did arrive")
	}
}

// TestVerifyClassifiesTrafficStageFailure drives a REAL failure all the way to
// the traffic stage and checks the verdict names a cause. ShadowTLS whose
// handshake target is a dead port is the cheapest deterministic way to get
// there: both cores start and both open their ports, so the failure happens
// where the tunnel carries data, which is the branch that used to collapse every
// runtime cause into one FP-VERIFY-FAIL.
func TestVerifyClassifiesTrafficStageFailure(t *testing.T) {
	if FindSingbox() == "" {
		t.Skip("sing-box not installed")
	}
	psk, err := keygen.SS2022PSK("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	n := &model.Node{
		Protocol: model.ProtoShadowTLS, Address: "0.0.0.0", Port: 0,
		ShadowTLS: &model.ShadowTLSOptions{
			Version: 3, Password: "shadowtls-pw",
			// Nothing listens on port 1, so the camouflage handshake the inbound
			// must perform for every connection cannot complete.
			HandshakeHost: "127.0.0.1", HandshakePort: 1,
			InnerMethod: "2022-blake3-aes-128-gcm", InnerPassword: psk,
		},
		Security: model.Security{Type: model.SecNone},
	}
	n.Normalize()
	res := VerifySingbox(context.Background(), n, Cores{})
	if res.Pass || res.Unprovable {
		t.Fatalf("a dead handshake target must fail: %+v", res)
	}
	// A captured client log means both cores ran and the failure happened while
	// carrying traffic — not at start-up, which is a different code.
	if res.ClientLog == "" {
		t.Fatalf("failure did not reach the traffic stage: %s / %s", res.Finding.Code, res.Finding.Detail)
	}
	// ONE code, not "any of four". The first version of this accepted
	// NET-UNREACHABLE, HANDSHAKE, AUTH or NO-DATA, which only asserts "not
	// FP-VERIFY-FAIL" — and it passed while the answer was NET-UNREACHABLE,
	// whose remedy tells the operator to check that the core is listening and
	// the firewall permits it. Both cores were running, the port was open, and
	// no firewall was involved: the inbound's own camouflage target was dead.
	// A wrong cause with confident remediation is worse than the generic
	// verdict this taxonomy replaced.
	if res.Finding.Code != "FP-VERIFY-HANDSHAKE" {
		t.Fatalf("a dead ShadowTLS handshake target was reported as %q (%s)\nserver log:\n%s\nclient log:\n%s",
			res.Finding.Code, res.Finding.Fix, res.ServerLog, res.ClientLog)
	}
	// And the verdict must be reached from the SERVER's evidence: the client
	// only ever sees "connection reset by peer", which is what a firewall looks
	// like too.
	if res.ServerLog == "" {
		t.Error("the inbound core's log was not captured, so this cause is only guessable")
	}
}
