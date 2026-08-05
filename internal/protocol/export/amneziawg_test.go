package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func awgNode() *model.Node {
	n := &model.Node{
		Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 51820,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "SRV-PRIV", PublicKey: "SRV-PUB",
			PeerPrivateKey: "CLI-PRIV", PeerPublicKey: "CLI-PUB",
			ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"},
		}},
	}
	n.Normalize() // fills obfuscation defaults + MTU
	return n
}

func TestAmneziaWGNormalizeDefaults(t *testing.T) {
	a := awgNode().AmneziaWG
	if a.Jc == 0 || a.Jmin == 0 || a.Jmax == 0 || a.H1 == 0 || a.H4 == 0 {
		t.Fatalf("obfuscation defaults not filled: %+v", a)
	}
	if a.Jmin >= a.Jmax {
		t.Fatalf("Jmin must be < Jmax: %d/%d", a.Jmin, a.Jmax)
	}
}

func TestAmneziaWGValidate(t *testing.T) {
	if err := awgNode().Validate(); err != nil {
		t.Fatalf("valid awg node rejected: %v", err)
	}
	// missing keys
	bad := &model.Node{Protocol: model.ProtoAmneziaWG, Port: 51820, AmneziaWG: &model.AmneziaWGOptions{}}
	if err := bad.Validate(); err == nil {
		t.Fatal("awg without keys must be rejected")
	}
	// Jmin >= Jmax
	n := awgNode()
	n.AmneziaWG.Jmin, n.AmneziaWG.Jmax = 100, 50
	if err := n.Validate(); err == nil {
		t.Fatal("Jmin>=Jmax must be rejected")
	}
	// S1+56 == S2
	n = awgNode()
	n.AmneziaWG.S1, n.AmneziaWG.S2 = 100, 156
	if err := n.Validate(); err == nil {
		t.Fatal("S1+56==S2 must be rejected")
	}
}

func TestAmneziaWGClientConf(t *testing.T) {
	conf, err := AmneziaWGConf(awgNode(), "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Interface]", "PrivateKey = CLI-PRIV", "[Peer]",
		"PublicKey = SRV-PUB", "Endpoint = 1.2.3.4:51820",
		"Jc = ", "Jmin = ", "Jmax = ", "S1 = ", "S2 = ", "H1 = ", "H2 = ", "H3 = ", "H4 = "} {
		if !strings.Contains(conf, want) {
			t.Fatalf("client conf missing %q\n%s", want, conf)
		}
	}
	// must NOT leak the server private key to a client
	if strings.Contains(conf, "SRV-PRIV") {
		t.Fatal("client conf leaked the server private key")
	}
}

func TestAmneziaWGServerConf(t *testing.T) {
	srv := awgNode()
	peer1 := awgNode()
	peer1.AmneziaWG.PeerPublicKey = "P1-PUB"
	peer1.AmneziaWG.PeerAddress = []string{"10.67.67.2/32"}
	peer2 := awgNode()
	peer2.AmneziaWG.PeerPublicKey = "P2-PUB"
	peer2.AmneziaWG.PeerAddress = []string{"10.67.67.3/32"}
	conf, err := AmneziaWGServerConf(srv, []*model.Node{peer1, peer2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "ListenPort = 51820") || !strings.Contains(conf, "PrivateKey = SRV-PRIV") {
		t.Fatalf("server conf interface wrong:\n%s", conf)
	}
	if strings.Count(conf, "[Peer]") != 2 {
		t.Fatalf("expected 2 peers, got:\n%s", conf)
	}
	for _, want := range []string{"PublicKey = P1-PUB", "AllowedIPs = 10.67.67.2/32",
		"PublicKey = P2-PUB", "AllowedIPs = 10.67.67.3/32", "Jc = ", "H4 = "} {
		if !strings.Contains(conf, want) {
			t.Fatalf("server conf missing %q\n%s", want, conf)
		}
	}
}

func TestAmneziaWGCloneAndEngine(t *testing.T) {
	n := awgNode()
	c := n.Clone()
	c.AmneziaWG.Jc = 999
	if n.AmneziaWG.Jc == 999 {
		t.Fatal("Clone did not deep-copy AmneziaWG")
	}
}
