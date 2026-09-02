package export

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The panel's link must match what brook itself generates. A link only brook can
// read is the point; one only the panel can read is a bug nobody notices until a
// client refuses it.
func TestBrookLinkMatchesTheRealBinary(t *testing.T) {
	bin := "/usr/local/bin/brook"
	if _, err := exec.LookPath(bin); err != nil {
		t.Skip("no brook binary")
	}

	// EVERY mode, against the binary. The first version of this compared only
	// the plain server mode, and the other three were wrong the whole time: the
	// parameter naming the server is called after the mode (wsserver=,
	// wssserver=, quicserver=) and carries a URL with a scheme and, for the
	// WebSocket modes, the path — while the panel emitted server=host:port for
	// all four. A conformance test that covers one of four shapes is why that
	// survived, so this walks the whole set.
	cases := []struct {
		mode, arg, key string
		extra          []string
	}{
		{"server", "1.2.3.4:9999", "server", []string{"--udpovertcp"}},
		{"wsserver", "ws://1.2.3.4:9999/tunnel", "wsserver", nil},
		{"wssserver", "wss://1.2.3.4:9999/tunnel", "wssserver", nil},
		{"quicserver", "quic://1.2.3.4:9999", "quicserver", nil},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			args := append([]string{"link", "-s", tc.arg, "-p", "pw"}, tc.extra...)
			out, err := exec.Command(bin, args...).Output()
			if err != nil {
				t.Skip("brook link unavailable")
			}
			want := strings.TrimSpace(string(out))

			n := &model.Node{Protocol: model.ProtoBrook, Address: "1.2.3.4", Port: 9999,
				Password: "pw", Brook: &model.BrookOptions{
					Mode: tc.mode, Path: "/tunnel", UDPOverTCP: len(tc.extra) > 0}}
			got, err := URI(n)
			if err != nil {
				t.Fatal(err)
			}

			// Compare the parameter SET, not the exact string: ordering and
			// escaping differ harmlessly between the two.
			wantQ, gotQ := uriQuery(t, want), uriQuery(t, got)
			for k, v := range wantQ {
				g, ok := gotQ[k]
				if !ok {
					t.Fatalf("brook emits %s=%q and the panel emits no such parameter\n  brook: %s\n  panel: %s",
						k, v[0], want, got)
				}
				if g[0] != v[0] {
					t.Fatalf("%s: brook says %q, panel says %q", k, v[0], g[0])
				}
			}
			if !strings.HasPrefix(got, "brook://"+tc.mode+"?") {
				t.Fatalf("panel link is not in %s mode: %s", tc.mode, got)
			}
		})
	}
}
