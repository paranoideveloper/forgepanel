package binmgr

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestBinmgr_ManagerAndPaths(t *testing.T) {
	dir := t.TempDir()
	m := New(dir)

	if m.BinDir != filepath.Join(dir, "bin") {
		t.Fatalf("unexpected BinDir: %s", m.BinDir)
	}

	pXray := m.Path(EngineXray)
	pSB := m.Path(EngineSingbox)
	pBrook := m.Path(EngineBrook)

	if pXray == "" || pSB == "" || pBrook == "" {
		t.Fatalf("expected non-empty binary paths")
	}

	vXray := versionFor(EngineXray)
	vSB := versionFor(EngineSingbox)
	vBrook := versionFor(EngineBrook)

	if vXray != XrayVersion || vSB != SingboxVersion || vBrook != BrookVersion {
		t.Fatalf("version mismatch: %s, %s, %s", vXray, vSB, vBrook)
	}
}

func TestBinmgr_ArchHelpers(t *testing.T) {
	// Whatever machine the suite runs on, every managed core must resolve to a
	// real asset for it. (The per-platform mapping itself is covered
	// exhaustively in binmgr_platform_test.go.)
	host := hostPlatform()
	for _, e := range ManagedEngines() {
		asset, err := assetFor(e, host)
		if err != nil {
			t.Fatalf("assetFor(%s, %s) failed: %v", e, host, err)
		}
		if asset == "" {
			t.Fatalf("empty %s asset for %s", e, host)
		}
	}
}

func TestBinmgr_ExtractZipAndTarGz(t *testing.T) {
	dir := t.TempDir()

	// 1. Zip extraction
	zipBuf := new(bytes.Buffer)
	zw := zip.NewWriter(zipBuf)
	f, err := zw.Create("xray")
	if err != nil {
		t.Fatalf("zip create failed: %v", err)
	}
	f.Write([]byte("mock binary"))
	zw.Close()

	zipDst := filepath.Join(dir, "extracted_xray")
	if err := extractZipFile(zipBuf.Bytes(), "xray", zipDst); err != nil {
		t.Fatalf("extractZipFile failed: %v", err)
	}

	content, err := os.ReadFile(zipDst)
	if err != nil || string(content) != "mock binary" {
		t.Fatalf("zip extract mismatch: %s, err: %v", content, err)
	}

	// 2. TarGz extraction
	tarBuf := new(bytes.Buffer)
	gw := gzip.NewWriter(tarBuf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name: "sing-box-1.0/sing-box",
		Mode: 0755,
		Size: int64(len("mock sb binary")),
	}
	tw.WriteHeader(hdr)
	tw.Write([]byte("mock sb binary"))
	tw.Close()
	gw.Close()

	tarDst := filepath.Join(dir, "extracted_sb")
	if err := extractTarGzFile(tarBuf.Bytes(), "sing-box", tarDst); err != nil {
		t.Fatalf("extractTarGzFile failed: %v", err)
	}

	content, err = os.ReadFile(tarDst)
	if err != nil || string(content) != "mock sb binary" {
		t.Fatalf("tar.gz extract mismatch: %s, err: %v", content, err)
	}
}

func TestBinmgr_FirstLineAndVerifyPinned(t *testing.T) {
	line := firstLine("Line 1\nLine 2\nLine 3")
	if line != "Line 1" {
		t.Fatalf("expected 'Line 1', got %q", line)
	}

	// verifyPinned checksum mismatch
	err := verifyPinned("unknown_asset.zip", []byte("data"))
	if err == nil {
		t.Fatalf("expected error for unpinned asset")
	}

	fakeData := []byte("fake binary data")
	sum := sha256.Sum256(fakeData)
	hexsum := hex.EncodeToString(sum[:])
	// Remove it again: pinnedSHA256 is package state, and a synthetic entry left
	// behind is indistinguishable from a real pin to any test that audits the
	// map (TestTablesAndPinsAgree flags pins no platform can reach).
	pinnedSHA256["test_asset.zip"] = hexsum
	defer delete(pinnedSHA256, "test_asset.zip")

	if err := verifyPinned("test_asset.zip", fakeData); err != nil {
		t.Fatalf("verifyPinned failed for valid checksum: %v", err)
	}
}

func TestBinmgr_BytesReaderAt(t *testing.T) {
	data := []byte("hello world")
	r := bytesReaderAt(data)
	buf := make([]byte, 5)
	n, err := r.ReadAt(buf, 0)
	if err != nil || n != 5 || string(buf) != "hello" {
		t.Fatalf("ReadAt failed: %s, err: %v", buf, err)
	}
}
