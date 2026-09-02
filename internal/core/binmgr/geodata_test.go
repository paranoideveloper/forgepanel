package binmgr

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The geodata that ships inside Xray's own release archive was being thrown
// away: the installer extracted "xray" and discarded everything else. A
// panel-managed core therefore had no geosite.dat or geoip.dat, and every rule
// using `geosite:category-ads-all` or `geoip:private` failed — not subtly, but
// by the core refusing the ENTIRE config ("code not found in geosite.dat") and
// taking every inbound down with it.
//
// It looked fine on any machine that happened to have a system-wide Xray
// installed separately, which is exactly why it survived: the failure only
// appears on a clean host, which is every real deployment.

func TestGeodataIsExtractedFromTheArchive(t *testing.T) {
	// A zip shaped like Xray's: the binary plus the two data files.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"xray":        "#!/bin/sh\necho fake\n",
		"geoip.dat":   "GEOIP-DATA",
		"geosite.dat": "GEOSITE-DATA",
		"LICENSE":     "irrelevant",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := installGeodata(dir, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"geoip.dat": "GEOIP-DATA", "geosite.dat": "GEOSITE-DATA"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not installed: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// No .tmp left behind: these are 30MB together, and a leaked temp copy per
	// upgrade fills a small VPS disk over time.
	entries, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(entries) != 0 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestGeoAssetsPresentDistinguishesMissingFromEmpty(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{BinDir: dir}
	binDir := m.GeoAssetDir(EngineXray)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if m.GeoAssetsPresent(EngineXray) {
		t.Fatal("reported geodata present when the directory is empty")
	}
	// A zero-length file is what a failed or interrupted download leaves. Treating
	// it as present means the panel reports the config as valid and the core
	// refuses it — the split that is hardest to diagnose.
	for _, n := range GeoAssetNames {
		if err := os.WriteFile(filepath.Join(binDir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if m.GeoAssetsPresent(EngineXray) {
		t.Fatal("a zero-length geodata file was reported as present")
	}
	for _, n := range GeoAssetNames {
		if err := os.WriteFile(filepath.Join(binDir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !m.GeoAssetsPresent(EngineXray) {
		t.Fatal("real geodata files were reported as missing")
	}
}

// TestGeodataLocationActuallyChangesTheCore proves XRAY_LOCATION_ASSET is
// honoured in PREFERENCE to the system-wide copy.
//
// Measured, and the first attempt at this test was wrong: the core has hardcoded
// fallbacks (/usr/local/share/xray, /usr/share/xray, /opt/share/xray), so
// pointing the variable at an EMPTY directory proves nothing on a machine that
// has any of those — it quietly finds the system copy and passes. The
// discriminating test is a deliberately CORRUPT file at the variable's path: if
// the variable were ignored, the core would find the good system copy and
// succeed.
//
// That precedence is the whole point of setting it. Without it a panel whose own
// geodata is current would silently route against whatever version an unrelated
// system install left behind — and on a clean VPS, which is every real
// deployment, there is no fallback at all and every geosite rule fails.
func TestGeodataLocationActuallyChangesTheCore(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the real core")
	}
	bin := "/usr/local/bin/xray"
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no xray binary")
	}
	sysGeo := "/usr/local/share/xray/geosite.dat"
	if _, err := os.Stat(sysGeo); err != nil {
		t.Skip("no system geodata to copy from")
	}

	cfg := []byte(`{"log":{"loglevel":"warning"},
	 "inbounds":[{"tag":"in","listen":"127.0.0.1","port":29543,"protocol":"socks","settings":{"udp":false}}],
	 "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	 "routing":{"rules":[{"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"}]}}`)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(assetDir string) error {
		cmd := exec.Command(bin, "run", "-test", "-c", cfgPath)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assetDir)
		return cmd.Run()
	}

	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, "geosite.dat"), []byte("not a geosite database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(corrupt); err == nil {
		t.Fatal("the core succeeded with a corrupt geosite.dat at XRAY_LOCATION_ASSET; " +
			"it is reading the system-wide copy instead, so the panel's own geodata would be ignored")
	}

	// Now the same config with geodata where the panel would put it.
	good := t.TempDir()
	data, err := os.ReadFile(sysGeo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "geosite.dat"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if ip, err := os.ReadFile("/usr/local/share/xray/geoip.dat"); err == nil {
		_ = os.WriteFile(filepath.Join(good, "geoip.dat"), ip, 0o644)
	}
	if err := run(good); err != nil {
		t.Fatalf("the core rejected a geosite rule WITH geodata present: %v", err)
	}
}
