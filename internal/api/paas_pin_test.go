package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Behind a platform edge the client's TLS terminates at the edge, which
// presents the platform's public certificate. Pinning the panel's own
// self-signed certificate made every Railway config in the xray-format
// subscription fail: "peer cert is unrecognized (against pinnedPeerCertSha256)".
// Found by connecting real clients to a real Railway deployment.
func TestBehindAnEdgeTheExportTrustsThePublicCertificate(t *testing.T) {
	s := paasServer(t)
	in := wsInbound(t, s, "ws1", "/tunnel")
	n, err := in.Node()
	if err != nil {
		t.Fatal(err)
	}
	s.applyExportDefaults(n)
	if len(n.Security.PinSHA256) != 0 || n.Security.AllowInsecure {
		t.Fatalf("edge-routed inbound exported with pin=%v insecure=%v; the edge's public cert would be refused",
			n.Security.PinSHA256, n.Security.AllowInsecure)
	}
}

// A port the platform routes raw (Fly) is served by the inbound's OWN TLS, so
// the self-signed certificate is what the client sees and the pin stays.
func TestOnARawRoutedPortThePinStays(t *testing.T) {
	t.Setenv("FORGEPANEL_PAAS_TCP_PORTS", "8443")
	s := paasServer(t)
	n := &model.Node{Remark: "raw", Protocol: model.ProtoVLESS, Address: "forge-test.up.railway.app", Port: 8443,
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecTLS, ServerName: "forge-test.up.railway.app"}}
	s.applyExportDefaults(n)
	if len(n.Security.PinSHA256) == 0 && !n.Security.AllowInsecure {
		t.Fatal("an inbound serving its own self-signed TLS lost its pin")
	}
}
