package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TestCapabilitiesMatchGuards keeps the advertised capability matrix honest: a
// transport marked supported here must NOT be rejected by model.Validate for an
// xray-family protocol, and a transport marked unsupported (h2/quic/mkcp) MUST be
// rejected. This prevents the matrix from ever advertising a combination the
// engine layer would refuse.
func TestCapabilitiesMatchGuards(t *testing.T) {
	net := map[string]model.Network{
		"tcp": model.NetTCP, "ws": model.NetWS, "grpc": model.NetGRPC,
		"httpupgrade": model.NetHTTPUpgrade, "xhttp": model.NetXHTTP,
		"h2": model.NetH2, "quic": model.NetQUIC, "mkcp": model.NetMKCP,
	}
	// Build a minimal valid xray-family node (VLESS+TLS) and swap the transport.
	base := func(n model.Network) *model.Node {
		return &model.Node{
			Protocol: model.ProtoVLESS, Address: "example.com", Port: 443, UUID: "u",
			Encryption: "none", Transport: model.Transport{Network: n},
			Security: model.Security{Type: model.SecTLS, CertificateFile: "/x", KeyFile: "/y"},
		}
	}
	for _, tc := range transportCapsForTest() {
		nw, ok := net[tc.Name]
		if !ok {
			continue
		}
		n := base(nw)
		n.Normalize()
		err := n.Validate()
		if tc.Supported && isTransportRejection(err) {
			t.Errorf("transport %q advertised as supported but rejected: %v", tc.Name, err)
		}
		if !tc.Supported && !isTransportRejection(err) {
			t.Errorf("transport %q advertised as UNsupported but was not rejected (err=%v)", tc.Name, err)
		}
	}
}

// transportCapsForTest mirrors the transport list in handleCapabilities.
func transportCapsForTest() []TransportCap {
	return []TransportCap{
		{Name: "tcp", Supported: true}, {Name: "ws", Supported: true},
		{Name: "grpc", Supported: true}, {Name: "httpupgrade", Supported: true},
		{Name: "xhttp", Supported: true}, {Name: "h2", Supported: false},
		{Name: "quic", Supported: false}, {Name: "mkcp", Supported: false},
	}
}

func isTransportRejection(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	for _, sub := range []string{"removed in Xray", "was removed"} {
		if containsStr := len(m) >= len(sub) && indexOf(m, sub) >= 0; containsStr {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
