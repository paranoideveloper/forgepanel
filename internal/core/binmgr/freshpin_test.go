package binmgr_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// TestFreshSingboxDownloadVerifies proves the new pin end to end: an empty data
// directory, a real download from the release, and the checksum the panel ships
// gating it. A wrong sum here would brick every new install.
func TestFreshSingboxDownloadVerifies(t *testing.T) {
	m := binmgr.New(t.TempDir())
	path, err := m.Ensure(binmgr.EngineSingbox)
	if err != nil {
		t.Fatalf("fresh install of the pinned sing-box failed: %v", err)
	}
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed binary will not run: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, binmgr.SingboxVersion) {
		t.Errorf("installed %s, expected %s\n%s", s, binmgr.SingboxVersion, out)
	}
	// Metering is NOT asserted here. With no shipped ForgePanel build beside
	// the executable — the ordinary case for a test binary in a temp dir —
	// adoptForgePanelSingboxPin finds nothing and the upstream official archive
	// is used by design. That build has no with_v2ray_api, so hysteria2, tuic,
	// anytls, shadowtls and wireguard are unmetered and the "Traffic metering"
	// health subsystem says so. Adoption of the shipped build is covered by
	// singbox_forgepanel_test.go, which stages an artifact to adopt.
	if strings.Contains(s, "with_v2ray_api") {
		t.Logf("adopted the ForgePanel build (metering available)")
	} else {
		t.Logf("fell back to the upstream official build (unmetered, as documented)")
	}
	t.Logf("fresh download verified against the shipped checksum:\n%s", strings.TrimSpace(s))
}
