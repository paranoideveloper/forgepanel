package binmgr

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOperatorSelectedVersionChangesThePathAndTheDigest(t *testing.T) {
	m := New(t.TempDir())
	m.Pins = map[Engine]Pin{EngineXray: {
		Version: "v25.1.1",
		SHA256:  map[string]string{"Xray-linux-64.zip": strings.Repeat("a", 64)},
	}}

	// LOAD-BEARING: the operator's version, not the compiled constant, decides
	// the cache directory — which is what Ensure installs into and what every
	// adapter execs.
	got := m.Path(EngineXray)
	if !strings.Contains(got, "xray-v25.1.1") {
		t.Fatalf("Path = %q; an operator-selected version must decide the cache dir, not the compiled constant %s", got, XrayVersion)
	}
	if strings.Contains(got, "xray-"+XrayVersion) {
		t.Fatalf("Path = %q still names the compiled constant %s", got, XrayVersion)
	}

	// The pin's digest must be the one verifyPinned consults, or a new version
	// could never install at all.
	if d, ok := m.digest("Xray-linux-64.zip"); !ok || d != strings.Repeat("a", 64) {
		t.Fatalf("digest(Xray-linux-64.zip) = %q,%v; the pin's digest must win over the compiled map", d, ok)
	}

	// SECOND LOAD-BEARING ASSERTION — the checksum mandate stays intact. A pin
	// with no digest for THIS host's asset must be refused before it can reach
	// finalizeInstall.
	hostAsset, ok := xrayAssets[hostPlatform()]
	if !ok {
		t.Skipf("no Xray asset published for %s", hostPlatform())
	}
	err := m.SetPins(map[Engine]Pin{EngineXray: {Version: "v25.1.1"}})
	if err == nil {
		t.Fatal("SetPins accepted a version with no digest; an unverified core could reach finalizeInstall")
	}
	if !strings.Contains(err.Error(), hostAsset) {
		t.Fatalf("SetPins error %q must name the asset it would have downloaded (%s)", err, hostAsset)
	}
}

// The adopter runs BEFORE installSingbox, so it is the one place a pin can be
// silently ignored and still report success. Unthreaded, an operator who pinned
// 9.9.9 got the SHIPPED build copied into bin/sing-box-9.9.9/ and Ensure
// returned nil — the panel then reporting, in /api/capabilities and everywhere
// else, a version it demonstrably was not running.
func TestAPinnedSingboxDoesNotAdoptTheShippedBuild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve the test executable")
	}
	dir := filepath.Dir(exe)
	shipped := filepath.Join(dir, ForgePanelSingboxAsset(runtime.GOARCH))
	if _, err := os.Stat(shipped); err == nil {
		t.Skip("a real artifact is already present next to the test binary")
	}
	if err := os.WriteFile(shipped, []byte("the shipped build"), 0o755); err != nil {
		t.Skipf("cannot plant a file next to the test binary: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(shipped) })

	m := New(t.TempDir())
	m.Pins = map[Engine]Pin{EngineSingbox: {Version: "9.9.9"}}
	dst := filepath.Join(t.TempDir(), "sing-box")
	adopted, err := adoptForgePanelSingboxPin(dst, runtime.GOARCH, m.version(EngineSingbox), m.digestFn())
	if adopted || err != nil {
		t.Fatalf("a pinned sing-box looked at the shipped build (adopted=%v, err=%v); "+
			"the pinned version must decide the artifact name", adopted, err)
	}

	// And the pinned version's OWN artifact is adopted, verified against the
	// operator's digest rather than the compiled table.
	name := "sing-box-9.9.9-linux-" + runtime.GOARCH
	content := []byte("the 9.9.9 build")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o755); err != nil {
		t.Skipf("cannot plant a file next to the test binary: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(dir, name)) })

	m.Pins = map[Engine]Pin{EngineSingbox: {Version: "9.9.9",
		SHA256: map[string]string{name: hex.EncodeToString(sum[:])}}}
	adopted, err = adoptForgePanelSingboxPin(dst, runtime.GOARCH, m.version(EngineSingbox), m.digestFn())
	if err != nil || !adopted {
		t.Fatalf("the pinned version's own artifact was not adopted (adopted=%v, err=%v)", adopted, err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != string(content) {
		t.Fatalf("adopted the wrong bytes: %q (%v)", got, err)
	}
}
