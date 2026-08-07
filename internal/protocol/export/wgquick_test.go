package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// confValue returns the value of a "Key = value" line from a wg-quick config.
func confValue(t *testing.T, conf, key string) string {
	t.Helper()
	for _, line := range strings.Split(conf, "\n") {
		if k, v, ok := strings.Cut(line, " = "); ok && k == key {
			return v
		}
	}
	t.Fatalf("key %q not found in:\n%s", key, conf)
	return ""
}

func TestWireGuardConfDefaults(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoWireGuard, Address: "vpn.example.com", Port: 51820,
		WireGuard: &model.WireGuardOptions{PrivateKey: "SRV-SK", PublicKey: "SRV-PK", PeerPrivateKey: "CLI-SK"}}
	conf, err := WireGuardConf(n, "")
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}
	// With no host override the node's own address is used.
	if got := confValue(t, conf, "Endpoint"); got != "vpn.example.com:51820" {
		t.Errorf("Endpoint = %q", got)
	}
	// Defaults the panel guarantees so the config is connectable out of the box.
	for key, want := range map[string]string{
		"PrivateKey":          "CLI-SK",
		"PublicKey":           "SRV-PK",
		"Address":             "10.66.66.2/32",
		"AllowedIPs":          "0.0.0.0/0, ::/0",
		"MTU":                 "1420",
		"PersistentKeepalive": "25",
		"DNS":                 "1.1.1.1, 8.8.8.8",
	} {
		if got := confValue(t, conf, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(conf, "SRV-SK") {
		t.Fatal("the client config leaked the server private key")
	}
	if strings.Contains(conf, "PresharedKey") {
		t.Error("no pre-shared key was configured, so none may be emitted")
	}
	if !strings.HasPrefix(conf, "[Interface]\n") || !strings.Contains(conf, "\n[Peer]\n") {
		t.Errorf("section headers wrong:\n%s", conf)
	}
}

func TestWireGuardConfExplicitValues(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoWireGuard, Address: "10.0.0.1", Port: 51820,
		WireGuard: &model.WireGuardOptions{PublicKey: "SRV-PK", PeerPrivateKey: "CLI-SK", PreSharedKey: "PSK",
			PeerAddress: []string{"10.66.66.9/32", "fd00::9/128"}, AllowedIPs: []string{"10.0.0.0/8"},
			MTU: 1380, Keepalive: 15}}
	conf, err := WireGuardConf(n, "203.0.113.5")
	if err != nil {
		t.Fatalf("WireGuardConf: %v", err)
	}
	for key, want := range map[string]string{
		"Address":             "10.66.66.9/32, fd00::9/128",
		"AllowedIPs":          "10.0.0.0/8",
		"MTU":                 "1380",
		"PersistentKeepalive": "15",
		"PresharedKey":        "PSK",
		"Endpoint":            "203.0.113.5:51820",
	} {
		if got := confValue(t, conf, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestWireGuardConfErrors(t *testing.T) {
	cases := map[string]*model.Node{
		"wrong protocol": {Protocol: model.ProtoVLESS, Address: "a", Port: 443},
		"no block":       {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820},
		"no peer private key": {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
			WireGuard: &model.WireGuardOptions{PublicKey: "SRV-PK"}},
		"no server public key": {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
			WireGuard: &model.WireGuardOptions{PeerPrivateKey: "CLI-SK"}},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := WireGuardConf(n, "1.2.3.4"); err == nil {
				t.Fatal("WireGuardConf accepted an unusable node")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AmneziaWG
// ---------------------------------------------------------------------------

func awgFull() *model.Node {
	n := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 51820,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "SRV-PRIV", PublicKey: "SRV-PUB", PeerPrivateKey: "CLI-PRIV", PeerPublicKey: "CLI-PUB",
			PreSharedKey: "PSK", ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"},
			AllowedIPs: []string{"10.0.0.0/8"}, MTU: 1380, Keepalive: 15}}}
	n.Normalize()
	return n
}

func TestAmneziaWGConfDefaultsAndHostFallback(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "vpn.example.com", Port: 51820,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "SRV-PRIV", PublicKey: "SRV-PUB", PeerPrivateKey: "CLI-PRIV"}}}
	n.Normalize()
	conf, err := AmneziaWGConf(n, "")
	if err != nil {
		t.Fatalf("AmneziaWGConf: %v", err)
	}
	for key, want := range map[string]string{
		"Endpoint":            "vpn.example.com:51820",
		"Address":             "10.67.67.2/32",
		"AllowedIPs":          "0.0.0.0/0, ::/0",
		"MTU":                 "1420",
		"PersistentKeepalive": "25",
	} {
		if got := confValue(t, conf, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(conf, "PresharedKey") {
		t.Error("no pre-shared key was configured, so none may be emitted")
	}

	// A node whose obfuscation params were never normalized still renders every
	// line, because both ends of the tunnel must agree on all nine of them.
	rawNode := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PublicKey: "SRV-PUB", PeerPrivateKey: "CLI-PRIV"}}}
	rawConf, err := AmneziaWGConf(rawNode, "")
	if err != nil {
		t.Fatalf("AmneziaWGConf: %v", err)
	}
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4", "MTU"} {
		if !strings.Contains(rawConf, key+" = ") {
			t.Errorf("obfuscation line %q missing:\n%s", key, rawConf)
		}
	}
	if got := confValue(t, rawConf, "MTU"); got != "1420" {
		t.Errorf("MTU = %q, want the 1420 fallback", got)
	}
}

func TestAmneziaWGConfExplicitValues(t *testing.T) {
	conf, err := AmneziaWGConf(awgFull(), "203.0.113.5")
	if err != nil {
		t.Fatalf("AmneziaWGConf: %v", err)
	}
	for key, want := range map[string]string{
		"PrivateKey":          "CLI-PRIV",
		"PublicKey":           "SRV-PUB",
		"PresharedKey":        "PSK",
		"Address":             "10.67.67.2/32",
		"AllowedIPs":          "10.0.0.0/8",
		"MTU":                 "1380",
		"PersistentKeepalive": "15",
		"Endpoint":            "203.0.113.5:51820",
		"Jc":                  "8",
		"Jmin":                "50",
		"Jmax":                "1000",
		"S1":                  "86",
		"S2":                  "574",
		"H1":                  "1234567",
		"H4":                  "4567890",
	} {
		if got := confValue(t, conf, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if strings.Contains(conf, "SRV-PRIV") {
		t.Fatal("the client config leaked the server private key")
	}
	// The obfuscation block belongs to [Interface], before [Peer].
	if strings.Index(conf, "Jc = ") > strings.Index(conf, "[Peer]") {
		t.Errorf("obfuscation params must live in [Interface]:\n%s", conf)
	}
}

func TestAmneziaWGConfErrors(t *testing.T) {
	cases := map[string]*model.Node{
		"wrong protocol": {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820,
			WireGuard: &model.WireGuardOptions{PeerPrivateKey: "k", PublicKey: "p"}},
		"no block": {Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820},
		"no peer private key": {Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
			AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{PublicKey: "SRV-PUB"}}},
		"no server public key": {Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
			AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{PeerPrivateKey: "CLI-PRIV"}}},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := AmneziaWGConf(n, "1.2.3.4"); err == nil {
				t.Fatal("AmneziaWGConf accepted an unusable node")
			}
		})
	}
}

func TestAmneziaWGServerConfDefaultsAndPeerFiltering(t *testing.T) {
	srv := awgFull()

	good := awgFull()
	good.AmneziaWG.PeerPublicKey = "P1-PUB"
	good.AmneziaWG.PeerAddress = []string{"10.67.67.2/32"}
	good.AmneziaWG.PreSharedKey = "P1-PSK"

	noKey := awgFull()
	noKey.AmneziaWG.PeerPublicKey = ""
	noKey.AmneziaWG.PeerAddress = []string{"10.67.67.3/32"}

	noAddr := awgFull()
	noAddr.AmneziaWG.PeerPublicKey = "P3-PUB"
	noAddr.AmneziaWG.PeerAddress = nil

	notAWG := &model.Node{Protocol: model.ProtoWireGuard, Address: "a", Port: 51820}

	conf, err := AmneziaWGServerConf(srv, []*model.Node{nil, good, noKey, noAddr, notAWG})
	if err != nil {
		t.Fatalf("AmneziaWGServerConf: %v", err)
	}
	if got := confValue(t, conf, "PrivateKey"); got != "SRV-PRIV" {
		t.Errorf("PrivateKey = %q", got)
	}
	if got := confValue(t, conf, "ListenPort"); got != "51820" {
		t.Errorf("ListenPort = %q", got)
	}
	if got := confValue(t, conf, "Address"); got != "10.67.67.1/24" {
		t.Errorf("Address = %q", got)
	}
	// Only the fully-specified peer may be bound; the rest are skipped rather
	// than emitted as a half-written [Peer] block awg-quick would reject.
	if n := strings.Count(conf, "[Peer]"); n != 1 {
		t.Fatalf("got %d peers, want only the fully-specified one:\n%s", n, conf)
	}
	if !strings.Contains(conf, "PublicKey = P1-PUB") || !strings.Contains(conf, "PresharedKey = P1-PSK") ||
		!strings.Contains(conf, "AllowedIPs = 10.67.67.2/32") {
		t.Fatalf("peer block wrong:\n%s", conf)
	}
	if strings.Contains(conf, "P3-PUB") {
		t.Error("a peer without a tunnel address was emitted")
	}
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} {
		if !strings.Contains(conf, key+" = ") {
			t.Errorf("server obfuscation line %q missing; both ends must match:\n%s", key, conf)
		}
	}
}

func TestAmneziaWGServerConfAddressFallback(t *testing.T) {
	srv := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{PrivateKey: "SRV-PRIV"}}}
	srv.Normalize()
	conf, err := AmneziaWGServerConf(srv, nil)
	if err != nil {
		t.Fatalf("AmneziaWGServerConf: %v", err)
	}
	if got := confValue(t, conf, "Address"); got != "10.67.67.1/24" {
		t.Errorf("Address = %q, want the default server tunnel address", got)
	}
	if strings.Contains(conf, "[Peer]") {
		t.Errorf("a server with no bound clients must have no peers:\n%s", conf)
	}
}

func TestAmneziaWGServerConfErrors(t *testing.T) {
	cases := map[string]*model.Node{
		"wrong protocol": {Protocol: model.ProtoWireGuard, Address: "a", Port: 51820},
		"no block":       {Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820},
		"no private key": {Protocol: model.ProtoAmneziaWG, Address: "a", Port: 51820,
			AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{PublicKey: "SRV-PUB"}}},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := AmneziaWGServerConf(n, nil); err == nil {
				t.Fatal("AmneziaWGServerConf accepted an unusable server node")
			}
		})
	}
}
