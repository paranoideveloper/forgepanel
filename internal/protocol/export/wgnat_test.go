package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TestKernelServerConfsCarryEgressNAT is the fix for a tunnel that connected and
// went nowhere.
//
// Both the WireGuard and the AmneziaWG inbound on a live panel completed their
// handshake, answered a ping to the server's own tunnel address, and could not
// reach one thing on the internet. The generated server config had no PostUp, so
// no MASQUERADE was ever installed and every forwarded packet left the box with
// a private source. Adding only that rule by hand took the AmneziaWG inbound
// from nothing to 1MB at 21.7 MB/s.
func TestKernelServerConfsCarryEgressNAT(t *testing.T) {
	wg := &model.Node{Protocol: model.ProtoWireGuard, Address: "203.0.113.9", Port: 51820,
		WireGuard: &model.WireGuardOptions{
			PrivateKey: "SRV", PublicKey: "SRVPUB", PeerPublicKey: "CLI",
			ServerAddress: []string{"10.66.66.1/24"}, PeerAddress: []string{"10.66.66.2/32"},
			MTU: 1420,
		}}
	awg := &model.Node{Protocol: model.ProtoAmneziaWG, Address: "203.0.113.9", Port: 5454,
		AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
			PrivateKey: "SRV", PublicKey: "SRVPUB", PeerPublicKey: "CLI",
			ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: []string{"10.67.67.2/32"},
			MTU: 1420,
		}}}

	for _, tc := range []struct {
		name, subnet string
		render       func() (string, error)
	}{
		{"wireguard", "10.66.66.0/24", func() (string, error) { return WireGuardServerConf(wg, []*model.Node{wg}) }},
		{"amneziawg", "10.67.67.0/24", func() (string, error) { return AmneziaWGServerConf(awg, []*model.Node{awg}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := tc.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(conf, "PostUp = ") {
				t.Fatalf("no PostUp, so the tunnel forwards nothing:\n%s", conf)
			}
			want := "iptables -t nat -A POSTROUTING -s " + tc.subnet + " -j MASQUERADE"
			if !strings.Contains(conf, want) {
				t.Errorf("missing %q:\n%s", want, conf)
			}
			// A DROP forward policy silently discards the packet after NAT,
			// which looks exactly like having no NAT at all.
			if !strings.Contains(conf, "iptables -A FORWARD -i %i -j ACCEPT") {
				t.Error("no FORWARD accept; a host with a DROP policy still drops the traffic")
			}
			if !strings.Contains(conf, "net.ipv4.ip_forward=1") {
				t.Error("forwarding is never enabled")
			}
			// Teardown must remove exactly what setup added, or every restart
			// leaves another copy of the rule behind.
			if !strings.Contains(conf, "PostDown = ") ||
				!strings.Contains(conf, "iptables -t nat -D POSTROUTING -s "+tc.subnet) {
				t.Errorf("PostDown does not remove the NAT rule:\n%s", conf)
			}
			// wg-quick aborts a PostDown chain on the first failure, which would
			// leave the interface half torn down after a crash.
			if !strings.Contains(conf, "|| true") {
				t.Error("PostDown is not tolerant of an already-removed rule")
			}
		})
	}
}

// TestNATSubnetsRefusesWhatItCannotMasqueradeSafely: a /32 covers the server and
// none of its peers, and an IPv6 prefix needs ip6tables. Emitting either would
// install a rule that quietly does nothing.
func TestNATSubnetsRefusesWhatItCannotMasqueradeSafely(t *testing.T) {
	got := natSubnets([]string{"10.66.66.1/24", "10.66.66.1/32", "fd00::1/64", "10.66.66.9", "10.66.66.5/24"})
	if len(got) != 1 || got[0] != "10.66.66.0/24" {
		t.Fatalf("natSubnets = %v, want just the masked v4 prefix", got)
	}
}
