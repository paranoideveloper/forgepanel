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

// TestClientIsNotOfferedAFamilyTheTunnelCannotCarry is the fix for a tunnel
// that connects and then cannot load half the internet.
//
// The panel allocates an IPv4 tunnel address and advertised
// "AllowedIPs = 0.0.0.0/0, ::/0" anyway. The client installs a ::/0 route into
// an interface with no IPv6 address, so every IPv6 packet is dropped. It is
// invisible on an IPv4-only test host — which is why it survived a namespace
// test, a Linux client and a live external check — and severe on a real
// dual-stack phone, where happy-eyeballs prefers AAAA and most large sites
// publish one.
func TestClientIsNotOfferedAFamilyTheTunnelCannotCarry(t *testing.T) {
	mk := func(peerAddrs []string) *model.Node {
		return &model.Node{Protocol: model.ProtoAmneziaWG, Address: "203.0.113.9", Port: 5454,
			AmneziaWG: &model.AmneziaWGOptions{WireGuardOptions: model.WireGuardOptions{
				PrivateKey: "SRV", PublicKey: "SRVPUB",
				PeerPrivateKey: "CLI", PeerPublicKey: "CLIPUB",
				ServerAddress: []string{"10.67.67.1/24"}, PeerAddress: peerAddrs,
				AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1420,
			}}}
	}

	t.Run("v4-only tunnel drops ::/0", func(t *testing.T) {
		conf, err := AmneziaWGConf(mk([]string{"10.67.67.2/32"}), "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		line := allowedIPsLine(t, conf)
		if strings.Contains(line, "::/0") {
			t.Errorf("offered ::/0 on a tunnel with no IPv6 address; every IPv6 "+
				"destination would blackhole:\n  %s", line)
		}
		if !strings.Contains(line, "0.0.0.0/0") {
			t.Errorf("dropped the IPv4 route as well:\n  %s", line)
		}
	})

	t.Run("dual-stack tunnel keeps both", func(t *testing.T) {
		conf, err := AmneziaWGConf(mk([]string{"10.67.67.2/32", "fd00:67::2/128"}), "203.0.113.9")
		if err != nil {
			t.Fatal(err)
		}
		line := allowedIPsLine(t, conf)
		if !strings.Contains(line, "::/0") || !strings.Contains(line, "0.0.0.0/0") {
			t.Errorf("a tunnel that carries both families must offer both:\n  %s", line)
		}
	})

	t.Run("an operator's explicit list is filtered, not emptied", func(t *testing.T) {
		got := matchAllowedIPsToTunnel([]string{"::/0"}, []string{"10.67.67.2/32"})
		if len(got) != 1 || got[0] != "::/0" {
			t.Errorf("filtering everything away would leave a config that routes "+
				"nothing at all; got %v", got)
		}
	})
}

func allowedIPsLine(t *testing.T, conf string) string {
	t.Helper()
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "AllowedIPs") {
			return strings.TrimSpace(l)
		}
	}
	t.Fatalf("no AllowedIPs line in:\n%s", conf)
	return ""
}
