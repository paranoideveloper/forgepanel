package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// A subscription is a list of URIs, and two protocols cannot be represented as
// one. AmneziaWG had no URI at all, so plainLinksMode's "skip anything that
// errors" dropped it silently — the panel could create the server side and hand
// the user nothing. WireGuard did produce a link, and it carried the server's
// private key. Neither gave anyone a working config.

func wgFamilyNodes() []*model.Node {
	return []*model.Node{
		{Remark: "plain", Protocol: model.ProtoVLESS, Address: "a.example.com", Port: 443,
			UUID: "11111111-1111-1111-1111-111111111111"},
		{Remark: "wg-one", Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 3445,
			WireGuard: &model.WireGuardOptions{
				PrivateKey: "SERVER-SK", PublicKey: "SERVER-PK",
				PeerPrivateKey: "CLIENT-SK", PeerAddress: []string{"10.66.66.2/32"},
				AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420, Keepalive: 25,
			}},
		{Remark: "awg-one", Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 5454,
			AmneziaWG: &model.AmneziaWGOptions{
				WireGuardOptions: model.WireGuardOptions{
					PrivateKey: "A-SERVER-SK", PublicKey: "A-SERVER-PK",
					PeerPrivateKey: "A-CLIENT-SK", PeerAddress: []string{"10.67.67.2/32"},
					AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1420,
				},
				Jc: 8, Jmin: 50, Jmax: 1000, S1: 86, S2: 574,
				H1: 1234567, H2: 2345678, H3: 3456789, H4: 4567890,
			}},
	}
}

func TestOnlyFileFormatProtocolsGetANativeConfEntry(t *testing.T) {
	got := nativeConfNodes(wgFamilyNodes())
	if len(got) != 2 {
		t.Fatalf("got %d native-config entries, want the WireGuard and AmneziaWG ones", len(got))
	}
	if got[0].Remark != "wg-one" || got[1].Remark != "awg-one" {
		t.Errorf("order is not stable: %q, %q — an index in a URL must keep meaning the same entry",
			got[0].Remark, got[1].Remark)
	}
}

// AmneziaWG must NOT be reduced to plain WireGuard. Without Jc/Jmin/Jmax/S1/S2
// and the H values the peer negotiates nothing with an AmneziaWG server, and it
// looks like an ordinary config that simply never connects.
func TestTheAmneziaConfKeepsItsObfuscationParameters(t *testing.T) {
	nodes := nativeConfNodes(wgFamilyNodes())
	_, body, err := nativeConfFor(nodes[1], "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Jc = 8", "Jmin = 50", "Jmax = 1000", "S1 = 86", "S2 = 574",
		"H1 = 1234567", "H2 = 2345678", "H3 = 3456789", "H4 = 4567890"} {
		if !strings.Contains(body, want) {
			t.Errorf("the AmneziaWG config lost %q — it is plain WireGuard now:\n%s", want, body)
		}
	}
}

// Neither config may contain the server's private key: these are handed to the
// subscriber.
func TestNativeConfsAreClientSide(t *testing.T) {
	for _, n := range nativeConfNodes(wgFamilyNodes()) {
		name, body, err := nativeConfFor(n, "vpn.example.com")
		if err != nil {
			t.Fatalf("%s: %v", n.Remark, err)
		}
		for _, secret := range []string{"SERVER-SK", "A-SERVER-SK"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s (%s) contains the server's private key", n.Remark, name)
			}
		}
		if !strings.Contains(body, "[Interface]") || !strings.Contains(body, "[Peer]") {
			t.Errorf("%s is not a wg-quick document:\n%s", n.Remark, body)
		}
		if !strings.HasSuffix(name, ".conf") {
			t.Errorf("filename %q should end .conf so a client opens it", name)
		}
	}
}

func TestAProtocolWithNoNativeFormatIsRefusedClearly(t *testing.T) {
	n := &model.Node{Remark: "v", Protocol: model.ProtoVLESS, Address: "a", Port: 1}
	if _, _, err := nativeConfFor(n, "a"); err == nil {
		t.Fatal("a VLESS node was given a wg-quick config")
	}
}

// The endpoint itself: an unknown token and an out-of-range index must both say
// what is wrong rather than serving an empty file.
func TestTheNativeConfEndpointRefusesWhatItCannotServe(t *testing.T) {
	s, _ := adminAPI(t)
	for _, path := range []string{"/subconf/no-such-token/0", "/subconf/no-such-token/9"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			t.Errorf("%s returned 200 for a token that does not exist", path)
		}
		if strings.TrimSpace(w.Body.String()) == "" {
			t.Errorf("%s refused with an empty body", path)
		}
	}
}
