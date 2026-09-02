package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// SOCKS5 and HTTP-CONNECT relay outbounds WITH user/pass auth, in the data path.
// Verified by the real core rather than asserted: the panel stores outbound
// settings verbatim, so the only meaningful check is whether Xray accepts them.
func TestSocksAndHTTPRelayOutboundsWithAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}

	b, err := BuildMultiWithRouting([]InboundSpec{chainedSpec()}, 10085, "", "",
		[]OutboundSpec{
			{Tag: "socks-relay", Protocol: "socks", Settings: json.RawMessage(
				`{"servers":[{"address":"198.51.100.7","port":1080,"users":[{"user":"u","pass":"p"}]}]}`)},
			{Tag: "http-relay", Protocol: "http", Settings: json.RawMessage(
				`{"servers":[{"address":"198.51.100.8","port":3128,"users":[{"user":"u","pass":"p"}]}]}`)},
		},
		[]RuleSpec{
			{Name: "via-socks", Domain: []string{"a.example"}, OutboundTag: "socks-relay"},
			{Name: "via-http", Domain: []string{"b.example"}, OutboundTag: "http-relay"},
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, b.Xray, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("the real core rejected authenticated SOCKS/HTTP relay outbounds: %v\n%s", err, out)
	}
}
