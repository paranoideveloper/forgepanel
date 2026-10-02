package model

import "testing"

func TestXrayRefusesCleartextVLESSAndTrojanToPublicAddressesOnly(t *testing.T) {
	cases := []struct {
		n    Node
		want bool
	}{
		{Node{Protocol: ProtoVLESS, Address: "8.8.8.8"}, true},
		{Node{Protocol: ProtoVLESS, Address: "vpn.example.com"}, true},
		{Node{Protocol: ProtoTrojan, Address: "2001:4860::8888"}, true},
		{Node{Protocol: ProtoVLESS, Address: "8.8.8.8", Security: Security{Type: SecTLS}}, false},
		{Node{Protocol: ProtoVLESS, Address: "8.8.8.8", Security: Security{Type: SecReality}}, false},
		{Node{Protocol: ProtoVLESS, Address: "8.8.8.8", Encryption: "mlkem768x25519plus.native.0rtt.x"}, false},
		{Node{Protocol: ProtoVLESS, Address: "10.1.2.3"}, false},
		{Node{Protocol: ProtoVLESS, Address: "100.80.16.45"}, false},
		{Node{Protocol: ProtoTrojan, Address: "[fd00::1]"}, false},
		{Node{Protocol: ProtoVLESS, Address: "box.internal"}, false},
		{Node{Protocol: ProtoVLESS, Address: "localhost"}, false},
		{Node{Protocol: ProtoVMess, Address: "8.8.8.8"}, false},
		{Node{Protocol: ProtoShadowsocks, Address: "8.8.8.8"}, false},
	}
	for _, c := range cases {
		if got := XrayRefusesAsOutbound(&c.n); got != c.want {
			t.Errorf("%s %s sec=%q enc=%q: got %v, want %v", c.n.Protocol, c.n.Address, c.n.Security.Type, c.n.Encryption, got, c.want)
		}
	}
}
