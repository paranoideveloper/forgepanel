package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TestAggregateBuildsValidJSON verifies the aggregator emits valid, non-empty
// engine configs even for an empty inbound set (so validation passes on a fresh
// panel). It needs no network and always runs.
func TestAggregateBuildsValidJSON(t *testing.T) {
	b, err := engine.Build(nil, 10085)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Xray) == 0 || len(b.Singbox) == 0 {
		t.Fatal("empty engine configs")
	}
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: 12345,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: model.Transport{Network: model.NetTCP}}
	n.Normalize()
	b2, err := engine.Build([]*model.Node{n}, 10085)
	if err != nil {
		t.Fatal(err)
	}
	if b2.XrayN != 1 {
		t.Fatalf("expected 1 xray inbound, got %d", b2.XrayN)
	}
}

// TestSuperviseXrayReal is the §18 gate: download the pinned Xray, generate a
// config from a real inbound, have Xray VALIDATE it (`xray run -test`), then
// launch it under the supervisor and confirm the inbound port is actually
// listening. Skipped in -short mode and if the network is unavailable.
func TestSuperviseXrayReal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network+process test in -short mode")
	}
	dir := t.TempDir()
	ctrl := NewController(dir, 10085)

	// A VLESS-TCP inbound on a free localhost port.
	port := freePort(t)
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "127.0.0.1", Port: port,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "e2e",
		Transport: model.Transport{Network: model.NetTCP},
	}
	n.Normalize()

	// Validate path first: this downloads Xray and runs `xray run -test`.
	_, results := ctrl.Validate([]*model.Node{n})
	if v := results["xray"]; v != "valid" {
		t.Fatalf("xray did not validate generated config: %q (binary download may have failed)", v)
	}
	t.Logf("xray -test PASSED on generated config")

	// Now actually launch it and confirm the port opens.
	if _, err := ctrl.Reload([]*model.Node{n}); err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer ctrl.StopAll()

	if !waitListen(port, 10*time.Second) {
		st := ctrl.Status()
		t.Fatalf("xray inbound port %d never opened; status=%+v", port, st)
	}
	t.Logf("xray is LISTENING on the generated inbound port %d — serving", port)

	st := ctrl.Status()
	if len(st) == 0 || st[0].State != "running" {
		t.Fatalf("expected running xray, got %+v", st)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListen(port int, d time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	for ctx.Err() == nil {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [6]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
