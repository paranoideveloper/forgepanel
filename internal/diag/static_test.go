package diag

import (
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
