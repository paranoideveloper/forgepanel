package binmgr

import (
	"encoding/hex"
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
