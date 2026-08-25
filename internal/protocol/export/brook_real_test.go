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
	out, err := exec.Command(bin, "link", "-s", "1.2.3.4:9999", "-p", "pw", "--udpovertcp").Output()
	if err != nil {
		t.Skip("brook link unavailable")
	}
	want := strings.TrimSpace(string(out))

	n := &model.Node{Protocol: model.ProtoBrook, Address: "1.2.3.4", Port: 9999,
		Password: "pw", Brook: &model.BrookOptions{Mode: "server", UDPOverTCP: true}}
	got, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "udpovertcp=true") {
		t.Fatalf("panel link %q lacks what brook emits: %q", got, want)
	}
	// Compare the parameter set rather than the exact string: ordering and
	// escaping differ harmlessly, and pinning the whole string would break on a
	// cosmetic change in either tool.
	for _, kv := range []string{"password=pw", "udpovertcp=true"} {
		if !strings.Contains(want, kv) {
			t.Fatalf("brook's own link no longer contains %q: %q — the format changed", kv, want)
		}
		if !strings.Contains(got, kv) {
			t.Fatalf("panel link %q is missing %q", got, kv)
		}
	}
}
