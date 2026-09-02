package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// The Config Studio renders the server's presets and translates each
// description through a catalogue key chosen by preset id. That mapping lives in
// the frontend and the presets live here, so nothing in either language notices
// when they drift: a preset added on this side simply shows its English
// description forever, and a key left behind on that side is translation work
// for a preset that no longer exists.
//
// The studio's shortcuts used to be an entirely separate hardcoded list that set
// only the protocol, which is how "VLESS + REALITY" came to mean "vless, plus
// whatever security the form defaulted to". Both lists are one list now, and
// this keeps the words attached to it.
func TestEveryPresetHasAStudioDescriptionKey(t *testing.T) {
	src, err := os.ReadFile(filepath.FromSlash("../../frontend/src/routes/studio/StudioView.svelte"))
	if err != nil {
		t.Skipf("frontend source not available: %v", err)
	}
	entry := regexp.MustCompile(`\{\s*id:\s*'([^']+)',\s*descKey:\s*'([^']+)'\s*\}`)
	mapped := map[string]string{}
	for _, m := range entry.FindAllStringSubmatch(string(src), -1) {
		mapped[m[1]] = m[2]
	}
	if len(mapped) == 0 {
		t.Fatal("no preset description keys found in StudioView — the scan is broken, not the mapping")
	}

	ids := map[string]bool{}
	for _, p := range presetList() {
		ids[p.ID] = true
		if _, ok := mapped[p.ID]; !ok {
			t.Errorf("preset %q has no description key in the studio, so it will always show the server's English", p.ID)
		}
	}
	for id := range mapped {
		if !ids[id] {
			t.Errorf("the studio maps a description key for preset %q, which no longer exists", id)
		}
	}

	// And the keys must be present in BOTH catalogues, or tr() renders the key
	// itself into the sidebar.
	for _, cat := range []string{"en.ts", "fa.ts"} {
		b, err := os.ReadFile(filepath.FromSlash("../../frontend/src/lib/i18n/" + cat))
		if err != nil {
			t.Skipf("catalogue %s not available: %v", cat, err)
		}
		for id, key := range mapped {
			if !strings.Contains(string(b), "'"+key+"'") {
				t.Errorf("%s has no entry for %q (preset %q)", cat, key, id)
			}
		}
	}
}
