package export

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func awgGenNode(gen string) *model.Node {
	n := &model.Node{
		Protocol: model.ProtoAmneziaWG, Address: "203.0.113.14", Port: 51851,
		AmneziaWG: &model.AmneziaWGOptions{
			Generation: gen,
			WireGuardOptions: model.WireGuardOptions{
				PrivateKey: "SRV-PRIV", PublicKey: "SRV-PUB",
				PeerPrivateKey: "CLI-PRIV", PeerPublicKey: "CLI-PUB",
				PeerAddress: []string{"10.41.0.2/32"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
				MTU: 1420, Keepalive: 25,
			},
		},
	}
	n.Normalize()
	return n
}

// TestAWGGenerationEmitsOnlyItsOwnKeys is the property that decides whether a
// generated config connects at all. AmneziaWG parameters are two-sided: a 3.x
// key in a conf whose peer speaks 1.5 does not degrade gracefully, it stops the
// handshake. Measured on live 3.0 and 3.1 servers: 1.5 client -> 3.0 server
// fails, and 3.0 client -> 3.1 server fails, because RandomTrailers changes the
// wire format for both ends.
func TestAWGGenerationEmitsOnlyItsOwnKeys(t *testing.T) {
	only20 := []string{"S3 =", "S4 ="}
	only30 := []string{"HeaderProtectionKey =", "ContentPaddingAddition =", "RekeyAfterTime =",
		"RekeyTimeout =", "RejectAfterTime =", "KeepaliveTimeout =", "MaxHandshakeAttempts ="}
	only31 := []string{"RandomTrailers ="}

	cases := []struct {
		gen          string
		wantAbsent   []string
		wantPresent  []string
	}{
		{model.AWG15, concat(only20, only30, only31), []string{"Jc =", "H1 ="}},
		{model.AWG20, concat(only30, only31), concat(only20, []string{"Jc ="})},
		{model.AWG30, only31, concat(only20, only30)},
		{model.AWG31, nil, concat(only20, only30, only31)},
	}
	for _, tc := range cases {
		t.Run(tc.gen, func(t *testing.T) {
			conf, err := AmneziaWGConf(awgGenNode(tc.gen), "203.0.113.14")
			if err != nil {
				t.Fatalf("AmneziaWGConf: %v", err)
			}
			for _, k := range tc.wantPresent {
				if !strings.Contains(conf, k) {
					t.Errorf("generation %s is missing %q:\n%s", tc.gen, k, conf)
				}
			}
			for _, k := range tc.wantAbsent {
				if strings.Contains(conf, k) {
					t.Errorf("generation %s leaked the newer key %q — this conf will not "+
						"hand-shake with a %s peer:\n%s", tc.gen, k, tc.gen, conf)
				}
			}
		})
	}
}

func concat(ss ...[]string) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s...)
	}
	return out
}

// TestAWG31MatchesAMeasuredWorkingServer pins the emitted 3.1 conf against one
// verified against a real AmneziaWG 3.1 kernel module (s7, 203.0.113.14:51851 —
// 3.1 client handshake OK, 4/4 ping, 33.6 MB/s; a 1.5-style client got no
// handshake at all).
func TestAWG31MatchesAMeasuredWorkingServer(t *testing.T) {
	conf, err := AmneziaWGConf(awgGenNode(model.AWG31), "203.0.113.14")
	if err != nil {
		t.Fatal(err)
	}
	// Every key the working server's conf carried, with the shape it carried.
	for _, want := range []string{
		"Jc = ", "Jmin = ", "Jmax = ", "S1 = ", "S2 = ",
		"H1 = ", "H2 = ", "H3 = ", "H4 = ",
		"S3 = ", "S4 = ",
		"HeaderProtectionKey = ",
		"ContentPaddingAddition = 16-128",
		"RekeyAfterTime = 100-140",
		"RekeyTimeout = 4-7",
		"RejectAfterTime = 160-200",
		"KeepaliveTimeout = 8-15",
		"MaxHandshakeAttempts = 12-20",
		"RandomTrailers = on",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("3.1 conf missing %q:\n%s", want, conf)
		}
	}
	// The measured hard constraint: HPK needs S3 and S4 >= 12, and 11 is
	// rejected by the module with "Unable to modify interface: Invalid
	// argument". The defaults must clear it without the operator knowing.
	n := awgGenNode(model.AWG31)
	if n.AmneziaWG.S3 < 12 || n.AmneziaWG.S4 < 12 {
		t.Errorf("3.1 defaults leave S3=%d S4=%d below the HeaderProtectionKey floor of 12",
			n.AmneziaWG.S3, n.AmneziaWG.S4)
	}
	if err := n.Validate(); err != nil {
		t.Errorf("the panel's own 3.1 defaults do not validate: %v", err)
	}
}

// TestAWGValidationCatchesWhatTheModuleRejects: each of these was observed
// failing on real hardware, with an error message that did not name the field.
func TestAWGValidationCatchesWhatTheModuleRejects(t *testing.T) {
	t.Run("H4 above uint32", func(t *testing.T) {
		n := awgGenNode(model.AWG15)
		n.AmneziaWG.H4 = "4300000000000"
		if err := n.Validate(); err == nil {
			t.Error("accepted an H4 the module reports only as \"Configuration parsing error\"")
		}
	})
	t.Run("HeaderProtectionKey with S3 below 12", func(t *testing.T) {
		n := awgGenNode(model.AWG31)
		n.AmneziaWG.S3 = 11
		if err := n.Validate(); err == nil {
			t.Error("accepted S3=11 with a header protection key; the module rejects the interface")
		}
	})
	t.Run("3.1-only key on a 1.5 config", func(t *testing.T) {
		n := awgGenNode(model.AWG15)
		n.AmneziaWG.RandomTrailers = true
		if err := n.Validate(); err == nil {
			t.Error("accepted RandomTrailers on a 1.5 config")
		}
	})
	t.Run("H ranges are accepted", func(t *testing.T) {
		n := awgGenNode(model.AWG20)
		n.AmneziaWG.H1 = "1500000000-1500999999"
		if err := n.Validate(); err != nil {
			t.Errorf("rejected a header-magic RANGE, which AmneziaWG 2.0 added: %v", err)
		}
	})
}
