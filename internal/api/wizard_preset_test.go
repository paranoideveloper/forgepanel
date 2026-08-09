package api

import (
	"testing"

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
