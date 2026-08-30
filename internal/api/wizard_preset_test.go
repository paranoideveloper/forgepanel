package api

import (
	"errors"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
)

// Every inbound the Preset Wizard mints must (a) pass model validation and (b)
// render to a real xray inbound — otherwise the wizard would create a broken
// server, which is the exact failure mode it exists to prevent.
func TestPresetWizardPlansAreValidAndRenderable(t *testing.T) {
	kp, err := keygen.RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := keygen.ShortID(8)
	w := &presetWizardCtx{
		domain:   "example.com",
		cdnHost:  "edge-abcd.example.com",
		serverIP: "203.0.113.10",
		reality:  &model.Reality{PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, ShortID: sid, Dest: realityDest},
	}

	plans := wizardPresetPlans()
	if len(plans) < 6 {
		t.Fatalf("expected the full catalogue, got %d", len(plans))
	}
	seenPorts := map[int]bool{}
	for i := range plans {
		p := &plans[i]
		if seenPorts[p.port] {
			t.Fatalf("port collision: %d used twice (%s)", p.port, p.remark)
		}
		seenPorts[p.port] = true

		n := p.build(p, w)
		applyCreateDefaults(n)
		if err := n.Validate(); err != nil {
			t.Errorf("%s: validate: %v", p.remark, err)
			continue
		}
		if _, err := render.XrayInbound(n); err != nil {
			t.Errorf("%s: xray render: %v", p.remark, err)
		}
		// REALITY inbounds must carry the shared key + the SNI rotation.
		if n.Security.Type == model.SecReality {
			if n.Security.Reality.PublicKey != kp.PublicKey {
				t.Errorf("%s: reality did not use the shared keypair", p.remark)
			}
			if len(n.Security.Reality.ServerNames) < 5 {
				t.Errorf("%s: expected the borrowed-SNI rotation, got %d", p.remark, len(n.Security.Reality.ServerNames))
			}
			// An inbound LISTENS on a bind-all address; the public IP is substituted
			// into the client link at export time, not stored on the node.
			if n.Address != "0.0.0.0" && n.Address != "" {
				t.Errorf("%s: inbound must listen bind-all, got %q", p.remark, n.Address)
			}
		}
		// CDN inbounds must front the proxied sub-domain.
		if p.cdn && n.Domain != w.cdnHost {
			t.Errorf("%s: CDN inbound not fronted behind %s", p.remark, w.cdnHost)
		}
	}
}

// The wizard's warnings render as one <p> each, so a multi-line err.Error()
// arrives with its newlines collapsed: the missing Cloudflare permission — the
// only part the operator can act on — ends up mid-sentence. This checks the
// typed fields are read back out instead.
func TestCFWizardWarningLeadsWithTheMissingScope(t *testing.T) {
	w := cfWizardWarning(&dns.Error{
		Provider:     "cloudflare",
		Op:           "create-record",
		Kind:         dns.KindPermission,
		Message:      "the token cannot write DNS records in this zone",
		MissingScope: "Zone → DNS → Edit",
		Remediation:  "add that permission to the token",
	}, "edge-ab12.example.com", "203.0.113.7")

	if strings.Contains(w, "\n") {
		t.Errorf("warning is multi-line, so HTML will collapse it into a run-on sentence:\n%s", w)
	}
	if !strings.Contains(w, "Zone → DNS → Edit") {
		t.Errorf("the missing permission is absent; that is the only actionable part:\n%s", w)
	}
	if !strings.Contains(w, "edge-ab12.example.com") || !strings.Contains(w, "203.0.113.7") {
		t.Errorf("the manual fallback lost the record it is telling the operator to create:\n%s", w)
	}

	// A plain error has no typed fields to read; the line must still be usable.
	plain := cfWizardWarning(errors.New("dial tcp: i/o timeout"), "edge-ab12.example.com", "203.0.113.7")
	if !strings.Contains(plain, "i/o timeout") || !strings.Contains(plain, "edge-ab12.example.com") {
		t.Errorf("untyped error lost its message or the fallback instruction:\n%s", plain)
	}
}
