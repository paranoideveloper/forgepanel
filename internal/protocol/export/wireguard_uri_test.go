package export

import (
	"net/url"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The WireGuard link is carried in every user subscription, so anything wrong
// with it reaches every subscriber. Two things were.

func wgNode() *model.Node {
	return &model.Node{
		Remark: "wg", Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 3445,
		WireGuard: &model.WireGuardOptions{
			PrivateKey:     "SERVER-PRIVATE-KEY",
			PublicKey:      "SERVER-PUBLIC-KEY",
			ServerAddress:  []string{"10.66.66.1/24"},
			PeerPrivateKey: "CLIENT-PRIVATE-KEY",
			PeerPublicKey:  "CLIENT-PUBLIC-KEY",
			PeerAddress:    []string{"10.66.66.2/32"},
			AllowedIPs:     []string{"0.0.0.0/0", "::/0"},
			MTU:            1420,
			Keepalive:      25,
		},
	}
}

// THE SECURITY ONE. The exporter preferred w.PrivateKey — the SERVER's key —
// and a panel-created inbound has both halves, so the link handed to every
// subscriber was the server's own private key. Anyone holding a subscription
// could impersonate the server.
func TestTheLinkNeverCarriesTheServersPrivateKey(t *testing.T) {
	uri, err := URI(wgNode())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "SERVER-PRIVATE-KEY") {
		t.Fatalf("the server's private key is in a link handed to subscribers:\n%s", uri)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.User.Username(); got != "CLIENT-PRIVATE-KEY" {
		t.Errorf("userinfo = %q, want the CLIENT's private key", got)
	}
	if got := u.Query().Get("publickey"); got != "SERVER-PUBLIC-KEY" {
		t.Errorf("publickey = %q, want the SERVER's public key — that is the peer the client dials", got)
	}
}

// THE USABILITY ONE. It published LocalAddress, which a panel-created node does
// not set, and carried no routes and no keepalive — so a client that parsed it
// got an interface with no address and nowhere to send traffic.
func TestTheLinkCarriesWhatAClientNeedsToConnect(t *testing.T) {
	uri, err := URI(wgNode())
	if err != nil {
		t.Fatal(err)
	}
	q, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	v := q.Query()
	if got := v.Get("address"); got != "10.66.66.2/32" {
		t.Errorf("address = %q, want the CLIENT's tunnel address; without one the interface cannot come up", got)
	}
	if got := v.Get("allowed_ips"); got == "" {
		t.Error("no allowed_ips: the tunnel comes up and routes nothing")
	}
	if got := v.Get("keepalive"); got != "25" {
		t.Errorf("keepalive = %q, want it carried so a NATed client stays reachable", got)
	}
	if got := v.Get("mtu"); got != "1420" {
		t.Errorf("mtu = %q", got)
	}
}

// A node parsed from somebody else's client link has only the client half. The
// exporter must still work there, which is why PrivateKey remains a fallback
// rather than being removed.
func TestAClientOnlyNodeStillExports(t *testing.T) {
	n := &model.Node{
		Remark: "imported", Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 51820,
		WireGuard: &model.WireGuardOptions{
			PrivateKey:   "THE-ONLY-KEY-PRESENT",
			PublicKey:    "PEER-PUBLIC",
			LocalAddress: []string{"10.7.0.2/32"},
			AllowedIPs:   []string{"0.0.0.0/0"},
		},
	}
	uri, err := URI(n)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	if u.User.Username() != "THE-ONLY-KEY-PRESENT" {
		t.Errorf("userinfo = %q; with only one key present it IS the client's", u.User.Username())
	}
	if got := u.Query().Get("address"); got != "10.7.0.2/32" {
		t.Errorf("address = %q, want LocalAddress used when PeerAddress is absent", got)
	}
}

// The native wg-quick file is the format every client imports, and it must
// carry the client's key too.
func TestTheNativeConfIsCompleteAndClientSide(t *testing.T) {
	conf, err := WireGuardConf(wgNode(), "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "SERVER-PRIVATE-KEY") {
		t.Fatal("the wg-quick config contains the server's private key")
	}
	for _, want := range []string{
		"[Interface]", "PrivateKey = CLIENT-PRIVATE-KEY", "Address = 10.66.66.2/32",
		"[Peer]", "PublicKey = SERVER-PUBLIC-KEY", "Endpoint = vpn.example.com:3445",
		"AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("wg-quick config is missing %q:\n%s", want, conf)
		}
	}
}
