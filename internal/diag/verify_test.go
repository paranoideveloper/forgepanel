package diag

import (
	"context"
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
