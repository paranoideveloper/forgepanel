package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// TestPresetsAreValid asserts every advertised preset, once completed by the
// create-defaults, passes model validation (the API must never advertise a
// combination the engine layer would reject). Engine-level rendering is covered
// by the protocol matrix test against the pinned binaries.
func TestPresetsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range presetList() {
		if p.ID == "" || seen[p.ID] {
			t.Fatalf("preset id empty or duplicated: %q", p.ID)
		}
		seen[p.ID] = true
		if p.Node == nil {
			t.Fatalf("preset %s has no node", p.ID)
		}
		// A preset is a template with no port (the operator supplies it); simulate
		// that before validating the completed node.
		p.Node.Port = 443
		applyCreateDefaults(p.Node)
		if err := p.Node.Validate(); err != nil {
			t.Errorf("preset %s does not validate: %v", p.ID, err)
		}
		// CDN flag must never be set on transports a normal HTTP CDN can't carry.
		if p.CDN {
			switch p.Node.Transport.Network {
			case model.NetWS, model.NetXHTTP, model.NetHTTPUpgrade, model.NetGRPC:
			default:
				t.Errorf("preset %s marked CDN but transport %q is not HTTP-frontable",
					p.ID, p.Node.Transport.Network)
			}
			if p.Node.Security.Type == model.SecReality {
				t.Errorf("preset %s marked CDN but uses REALITY", p.ID)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no presets defined")
	}
}
