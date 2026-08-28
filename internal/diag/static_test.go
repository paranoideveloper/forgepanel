package diag

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func has(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestStaticCatchesPortConflict(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: model.NetTCP}, Security: model.Security{Type: model.SecReality}}
	fs := StaticValidate(n, map[int]string{443: "other-inbound"})
	if !has(fs, "FP-PORT-002") {
		t.Fatalf("port conflict not caught: %+v", fs)
	}
}

func TestStaticCatchesPlaintextShownAsSecure(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 80, Transport: model.Transport{Network: model.NetTCP}, Security: model.Security{Type: model.SecNone}}
	fs := StaticValidate(n, nil)
	if !has(fs, "FP-TLS-002") {
		t.Fatalf("plaintext-as-secure not caught: %+v", fs)
	}
	// Every finding carries EN + FA text and a severity — never colour alone.
	for _, f := range fs {
		if f.TitleEN == "" || f.TitleFA == "" || f.Severity == "" {
			t.Fatalf("finding %s missing EN/FA/severity: %+v", f.Code, f)
		}
	}
}

func TestStaticCatchesIllegalVisionFlow(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Flow: "xtls-rprx-vision",
		Transport: model.Transport{Network: model.NetWS}, Security: model.Security{Type: model.SecTLS}}
	fs := StaticValidate(n, nil)
	if !has(fs, "FP-FLOW-001") {
		t.Fatalf("illegal vision flow not caught: %+v", fs)
	}
}

func TestStaticCatchesBadShortID(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, Reality: &model.Reality{ShortIDs: []string{"abc"}}}} // odd length
	fs := StaticValidate(n, nil)
	if !has(fs, "FP-REALITY-002") {
		t.Fatalf("bad shortId not caught: %+v", fs)
	}
}

func TestEveryCatalogueEntryIsComplete(t *testing.T) {
	for code, e := range Catalogue {
		if e.TitleEN == "" || e.TitleFA == "" || e.Severity == "" {
			t.Errorf("catalogue %s missing EN/FA/severity", code)
		}
	}
}

// TestStaticCatchesRealityWithoutDest guards FP-REALITY-001, which was in the
// catalogue but emitted by nothing: the panel shipped the code, the severity and
// the Farsi text for a check that never ran. An empty dest makes Xray omit the
// field entirely and then refuse to start, which reaches the operator as "the
// core keeps restarting" rather than as the one-line config error it is.
func TestStaticCatchesRealityWithoutDest(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, Reality: &model.Reality{
			ServerNames: []string{"www.cloudflare.com"}, PublicKey: "PK"}}}
	fs := StaticValidate(n, nil)
	if !has(fs, "FP-REALITY-001") {
		t.Fatalf("REALITY without a dest not caught: %+v", fs)
	}
}

func TestStaticCatchesRealityDestWithoutPort(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: model.NetTCP},
		Security: model.Security{Type: model.SecReality, Reality: &model.Reality{
			Dest: "www.cloudflare.com", ServerNames: []string{"www.cloudflare.com"}}}}
	fs := StaticValidate(n, nil)
	if !has(fs, "FP-REALITY-001") {
		t.Fatalf("REALITY dest without a port not caught: %+v", fs)
	}
}

// A well-formed dest must stay silent — a check that fires on healthy configs is
// worse than no check, because operators learn to ignore the report.
func TestStaticAcceptsGoodRealityDest(t *testing.T) {
	for _, dest := range []string{"www.cloudflare.com:443", "[2606:4700::1]:443", "1.1.1.1:8443"} {
		n := &model.Node{Protocol: model.ProtoVLESS, Port: 443, Transport: model.Transport{Network: model.NetTCP},
			Security: model.Security{Type: model.SecReality, Reality: &model.Reality{Dest: dest}}}
		if fs := StaticValidate(n, nil); has(fs, "FP-REALITY-001") {
			t.Errorf("valid dest %q flagged: %+v", dest, fs)
		}
	}
}

// TestStaticCatchesPortHopOverlap guards FP-PORT-HOP-001, the second catalogue
// code that nothing emitted. A hop range that covers another inbound's port
// steals that port after a hop, so both inbounds fail intermittently.
func TestStaticCatchesPortHopOverlap(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoHysteria2, Port: 8443,
		Hysteria2: &model.Hysteria2Options{PortHopping: "20000-30000"}}
	fs := StaticValidate(n, map[int]string{25000: "reality-tcp"})
	if !has(fs, "FP-PORT-HOP-001") {
		t.Fatalf("overlapping hop range not caught: %+v", fs)
	}
	var detail string
	for _, f := range fs {
		if f.Code == "FP-PORT-HOP-001" {
			detail = f.Detail
		}
	}
	if !strings.Contains(detail, "25000") || !strings.Contains(detail, "reality-tcp") {
		t.Errorf("finding must name the stolen port and its owner, got %q", detail)
	}
}

func TestStaticAllowsNonOverlappingHopRange(t *testing.T) {
	n := &model.Node{Protocol: model.ProtoHysteria2, Port: 8443,
		Hysteria2: &model.Hysteria2Options{PortHopping: "20000-30000,40000"}}
	fs := StaticValidate(n, map[int]string{8443: "", 31000: "other", 39999: "other2"})
	if has(fs, "FP-PORT-HOP-001") {
		t.Fatalf("hop range that overlaps nothing was flagged: %+v", fs)
	}
}

func TestParseHopRanges(t *testing.T) {
	cases := []struct {
		in   string
		want []hopRange
	}{
		{"20000-50000", []hopRange{{20000, 50000}}},
		{"20000-50000,60000", []hopRange{{20000, 50000}, {60000, 60000}}},
		{"1000-2000, 3000-4000", []hopRange{{1000, 2000}, {3000, 4000}}},
		// Garbage is skipped, never guessed at: a reversed or out-of-range piece
		// must not turn into a range that covers the whole port space.
		{"5000-1000", nil},
		{"70000-80000", nil},
		{"abc", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := parseHopRanges(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseHopRanges(%q) = %+v want %+v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseHopRanges(%q)[%d] = %+v want %+v", c.in, i, got[i], c.want[i])
			}
		}
	}
}
