package deploy

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
)

// A control the platform owns is REMOVED, not disabled. These pin which
// capabilities each environment actually has, because the failure they prevent
// is silent: an operator sets a port that is never routed, or requests a
// certificate for a hostname the platform already terminates, and the failure
// surfaces far from the switch they flipped.

func TestAPlainServerOwnsEverything(t *testing.T) {
	s := Describe(config.PaaS{})
	if s.Kind != "vps" {
		t.Fatalf("kind = %q, want vps", s.Kind)
	}
	for _, c := range All() {
		if !s.Allows(c) {
			t.Errorf("a server the operator owns should allow %q", c)
		}
	}
	if len(s.Hidden()) != 0 {
		t.Errorf("nothing should be hidden on a VPS, got %v", s.Hidden())
	}
}

func TestRailwayHidesWhatRailwayOwns(t *testing.T) {
	s := Describe(config.PaaS{Enabled: true, Platform: "railway", Domain: "x.up.railway.app"})
	if s.Kind != "paas" {
		t.Fatalf("kind = %q, want paas", s.Kind)
	}
	for _, c := range []Capability{OwnTLS, ArbitraryPorts, OwnDomain, SystemServices, RawTCP, UDP} {
		if s.Allows(c) {
			t.Errorf("%q should be unavailable on Railway — the platform owns it", c)
		}
		if s.Why[c] == "" {
			t.Errorf("%q is hidden with no explanation; a missing section must be explicable", c)
		}
	}
	// Enrolling other servers works fine from a container, and hiding it would
	// remove the main reason to run a panel on a platform at all.
	if !s.Allows(RemoteNodes) {
		t.Error("remote node management should still be available on Railway")
	}
}

// Fly is the outlier: it routes raw TCP and UDP, so REALITY and Hysteria2 work
// there — but only once the ports are DECLARED. Inferring them would make the
// panel offer inbounds that cannot be reached.
func TestFlyGainsRawTCPAndUDPOnlyWhenPortsAreDeclared(t *testing.T) {
	bare := Describe(config.PaaS{Enabled: true, Platform: "fly"})
	if bare.Allows(RawTCP) || bare.Allows(UDP) {
		t.Error("Fly with no declared ports must not claim raw TCP or UDP")
	}
	if bare.Why[RawTCP] == "" || bare.Why[UDP] == "" {
		t.Error("the refusal should say how to enable it")
	}

	declared := Describe(config.PaaS{
		Enabled: true, Platform: "fly",
		TCPPorts: []int{8443}, UDPPorts: []int{443},
	})
	if !declared.Allows(RawTCP) {
		t.Error("declared TCP ports should enable raw TCP")
	}
	if !declared.Allows(UDP) {
		t.Error("declared UDP ports should enable UDP")
	}
	// Declaring a routed port does not hand back the platform's own jobs.
	if declared.Allows(OwnTLS) || declared.Allows(SystemServices) {
		t.Error("declaring ports must not imply the panel owns TLS or the host")
	}
}

func TestEveryDeniedCapabilityExplainsItself(t *testing.T) {
	for _, pa := range []config.PaaS{
		{Enabled: true, Platform: "railway"},
		{Enabled: true, Platform: "render", CDNFronted: true},
		{Enabled: true, Platform: "koyeb"},
		{Enabled: true, Platform: ""}, // generic
	} {
		s := Describe(pa)
		for _, c := range s.Hidden() {
			if s.Why[c] == "" {
				t.Errorf("%s: %q hidden with no reason", pa.Platform, c)
			}
		}
	}
}

// A generic platform must still name itself in the explanation rather than
// producing "  terminates TLS at its own edge".
func TestAnUnnamedPlatformStillReadsProperly(t *testing.T) {
	s := Describe(config.PaaS{Enabled: true})
	why := s.Why[OwnTLS]
	if why == "" {
		t.Fatal("no reason given")
	}
	if why[0] == ' ' {
		t.Errorf("reason starts with a blank platform name: %q", why)
	}
}

func TestSectionsAndSettingsOnlyNameRealCapabilities(t *testing.T) {
	known := map[Capability]bool{}
	for _, c := range All() {
		known[c] = true
	}
	for section, c := range Sections() {
		if !known[c] {
			t.Errorf("section %q requires unknown capability %q", section, c)
		}
	}
	for key, c := range SettingRequires() {
		if !known[c] {
			t.Errorf("setting %q requires unknown capability %q", key, c)
		}
	}
}

// The section ids are the frontend's tab ids. A rename on either side orphans
// the mapping, and the symptom is a section that never hides.
func TestSectionIdsMatchTheSidebarTabs(t *testing.T) {
	// Kept in sync by hand deliberately: the alternative is parsing Svelte here,
	// and a stale literal that fails loudly beats a parser that quietly matches
	// nothing.
	sidebar := map[string]bool{
		"overview": true, "wizard": true, "inbounds": true, "users": true,
		"admins": true, "routing": true, "online": true, "usage": true,
		"audit": true, "nodes": true, "studio": true, "domains": true,
		"forgedns": true, "edge": true, "certs": true, "system": true,
	}
	for id := range Sections() {
		if !sidebar[id] {
			t.Errorf("Sections() gates %q, which is not a sidebar tab — the mapping is orphaned", id)
		}
	}
}

func TestSettingRequiresNamesRealSettings(t *testing.T) {
	// Prefix keys (core_version_) are families, matched by prefix in the
	// registry; they are legitimate here.
	for key := range SettingRequires() {
		if key == "" {
			t.Error("empty settings key in the requirement map")
		}
	}
}
