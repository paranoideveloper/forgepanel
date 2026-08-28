package binmgr

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPinnedMandatory(t *testing.T) {
	// Unknown artifact filename => refuse (this is the silent-bypass regression:
	// a failed/absent checksum must never let an install proceed).
	if err := verifyPinned("mystery-file.zip", []byte("x")); err == nil {
		t.Fatal("unknown artifact must fail verification")
	}
	// Known artifact, wrong bytes => mismatch.
	if err := verifyPinned("Xray-linux-64.zip", []byte("tampered")); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered artifact must fail with mismatch, got %v", err)
	}
	// All three engines (both arches) have a syntactically valid pinned SHA-256.
	wantEngines := []string{"Xray-linux-64.zip", "Xray-linux-arm64-v8a.zip",
		"sing-box-1.13.15-linux-amd64.tar.gz", "brook_linux_amd64", "brook_linux_arm64"}
	for _, name := range wantEngines {
		h, ok := pinnedSHA256[name]
		if !ok {
			t.Fatalf("missing pinned checksum for %s", name)
		}
		if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
			t.Fatalf("pinned hash for %s is not a 32-byte hex sha256: %q", name, h)
		}
	}
}

func TestManagerPathAndEnsureInstalled(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)

	xrayPath := m.Path(EngineXray)
	if !strings.Contains(xrayPath, "xray-"+XrayVersion) {
		t.Fatalf("unexpected xray path: %s", xrayPath)
	}

	singPath := m.Path(EngineSingbox)
	if !strings.Contains(singPath, "sing-box-"+SingboxVersion) {
		t.Fatalf("unexpected singbox path: %s", singPath)
	}

	brookPath := m.Path(EngineBrook)
	if !strings.Contains(brookPath, "brook-"+BrookVersion) {
		t.Fatalf("unexpected brook path: %s", brookPath)
	}

	// Mock existing installed binary and test Ensure returns path without downloading
	fakeBin := m.Path(EngineXray)
	if err := os.MkdirAll(filepath.Dir(fakeBin), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho xray"), 0755); err != nil {
		t.Fatal(err)
	}

	gotPath, err := m.Ensure(EngineXray)
	if err != nil || gotPath != fakeBin {
		t.Fatalf("Ensure existing binary failed: %v, got %s", err, gotPath)
	}
}

func TestVersionForAndAssetName(t *testing.T) {
	if versionFor(EngineXray) != XrayVersion {
		t.Fatal("versionFor(EngineXray) mismatch")
	}
	if versionFor(EngineSingbox) != SingboxVersion {
		t.Fatal("versionFor(EngineSingbox) mismatch")
	}

	aName, err := assetFor(EngineXray, hostPlatform())
	if err != nil || len(aName) == 0 {
		t.Fatalf("assetFor(xray, host) failed: %v", err)
	}

	sbName, err := assetFor(EngineSingbox, hostPlatform())
	if err != nil || len(sbName) == 0 {
		t.Fatalf("assetFor(sing-box, host) failed: %v", err)
	}
}
