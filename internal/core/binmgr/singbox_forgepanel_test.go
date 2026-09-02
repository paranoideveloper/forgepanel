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

// ForgePanel ships its own sing-box because per-user counters for hysteria2,
// tuic, anytls, shadowtls and wireguard exist only in a build carrying
// with_v2ray_api, which the official archives lack. Shipping a proxy core is a
// trust decision, so the adoption path is checksum-gated.

func TestShippedAssetNameIsDistinctFromUpstream(t *testing.T) {
	ours := ForgePanelSingboxAsset("amd64")
	if strings.HasSuffix(ours, ".tar.gz") {
		t.Fatalf("our asset %q looks like the upstream archive; they are different artifacts "+
			"and must never share a checksum entry", ours)
	}
	if _, clash := pinnedSHA256[ours+".tar.gz"]; !clash {
		// The upstream entry should exist under the archive name.
		t.Errorf("upstream archive entry missing for %s.tar.gz", ours)
	}
	if _, pinned := pinnedSHA256[ours]; !pinned {
		t.Errorf("no pinned checksum for our own build %q; binmgr would refuse it", ours)
	}
}

// The ordinary case on a host that installed only the panel. Not a fault: the
// upstream build is used and those protocols are simply unmetered.
func TestNoShippedBinaryIsNotAnError(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "sing-box")
	adopted, err := adoptForgePanelSingbox(dst, "riscv64") // no candidate can exist
	if err != nil {
		t.Fatalf("a missing shipped binary must not be an error: %v", err)
	}
	if adopted {
		t.Fatal("reported adopting a binary that does not exist")
	}
}

// A file in the release location whose bytes do not verify is either corrupt or
// tampered with. Silently ignoring it to fall back to upstream would hide
// exactly the event worth noticing.
func TestAWrongChecksumIsRefusedRatherThanIgnored(t *testing.T) {
	dir := t.TempDir()
	// Put a bogus artifact where the adopter looks, via the exe-neighbour path.
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve the test executable")
	}
	name := ForgePanelSingboxAsset(runtime.GOARCH)
	planted := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(planted); err == nil {
		t.Skip("a real artifact is already present next to the test binary")
	}
	if err := os.WriteFile(planted, []byte("not a sing-box"), 0o755); err != nil {
		t.Skipf("cannot plant a file next to the test binary: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(planted) })

	_, err = adoptForgePanelSingbox(filepath.Join(dir, "sing-box"), runtime.GOARCH)
	if err == nil {
		t.Fatal("an artifact with the wrong checksum was accepted, or silently skipped")
	}
	if !strings.Contains(err.Error(), "pinned checksum") {
		t.Errorf("the error should name the checksum mismatch, got: %v", err)
	}
}

// A verifying artifact is installed, executable, and byte-identical.
func TestAVerifyingArtifactIsAdopted(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve the test executable")
	}
	name := ForgePanelSingboxAsset(runtime.GOARCH)
	planted := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(planted); err == nil {
		t.Skip("a real artifact is already present next to the test binary")
	}

	// Content whose checksum we temporarily pin, so this exercises the adoption
	// path without needing the real 46 MB core in the test tree.
	content := []byte("forgepanel test artifact")
	sum := sha256.Sum256(content)
	orig, had := pinnedSHA256[name]
	pinnedSHA256[name] = hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		if had {
			pinnedSHA256[name] = orig
		} else {
			delete(pinnedSHA256, name)
		}
	})

	if err := os.WriteFile(planted, content, 0o644); err != nil {
		t.Skipf("cannot plant a file next to the test binary: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(planted) })

	dst := filepath.Join(t.TempDir(), "sing-box")
	adopted, err := adoptForgePanelSingbox(dst, runtime.GOARCH)
	if err != nil {
		t.Fatalf("adopting a verifying artifact failed: %v", err)
	}
	if !adopted {
		t.Fatal("a verifying artifact was not adopted")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Error("the adopted binary does not match the source bytes")
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("the adopted core is not executable")
	}
}

// An artifact with no pinned checksum at all must be refused, not trusted.
// This is the whole point of pinning: an unknown proxy core is not installed.
func TestAnUnpinnedArtifactIsRefused(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve the test executable")
	}
	name := ForgePanelSingboxAsset(runtime.GOARCH)
	planted := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(planted); err == nil {
		t.Skip("a real artifact is already present next to the test binary")
	}
	orig, had := pinnedSHA256[name]
	delete(pinnedSHA256, name)
	t.Cleanup(func() {
		if had {
			pinnedSHA256[name] = orig
		}
	})
	if err := os.WriteFile(planted, []byte("anything"), 0o755); err != nil {
		t.Skipf("cannot plant a file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(planted) })

	if _, err := adoptForgePanelSingbox(filepath.Join(t.TempDir(), "sing-box"), runtime.GOARCH); err == nil {
		t.Fatal("an artifact with no pinned checksum was installed")
	}
}
