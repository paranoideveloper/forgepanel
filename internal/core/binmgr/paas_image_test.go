package binmgr

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The PaaS image bakes the cores in, with its own copy of each version and
// SHA-256. Those copies are what Railway, Render and Fly build from, so they
// drift silently: binmgr looks for <engine>-<version> and downloads on a
// mismatch, and a digest that disagrees with binmgr's either fails the build or
// installs a file the panel would refuse. Both have to say the same thing.
func TestThePaaSImagePinsWhatBinmgrPins(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "paas", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(raw)

	for arg, want := range map[string]string{
		"XRAY_VERSION":    XrayVersion,
		"SINGBOX_VERSION": SingboxVersion,
		"BROOK_VERSION":   BrookVersion,
	} {
		all := regexp.MustCompile(`(?m)^ARG `+arg+`=(\S+)$`).FindAllStringSubmatch(df, -1)
		if len(all) == 0 {
			t.Errorf("deploy/paas/Dockerfile has no ARG %s", arg)
		}
		for _, m := range all {
			if m[1] != want {
				t.Errorf("ARG %s=%s, binmgr pins %s", arg, m[1], want)
			}
		}
	}

	// Each architecture's block names an asset and its digest; the digest must
	// be binmgr's for that exact file.
	checked := 0
	pairs := regexp.MustCompile(`(XRAY|BROOK)_ASSET=(\S+?);\s*\\\s*\n\s*(?:XRAY|BROOK)_SHA=([0-9a-f]{64})`)
	for _, m := range pairs.FindAllStringSubmatch(df, -1) {
		checked++
		if want, ok := compiledDigest(m[2]); !ok || want != m[3] {
			t.Errorf("%s: image pins %s, binmgr pins %q", m[2], m[3], want)
		}
	}
	sb := regexp.MustCompile(`SB_TAIL=(\S+?);\s*\\\s*\n\s*SB_SHA=([0-9a-f]{64})`)
	for _, m := range sb.FindAllStringSubmatch(df, -1) {
		checked++
		asset := "sing-box-" + SingboxVersion + "-" + m[1] + ".tar.gz"
		if want, ok := compiledDigest(asset); !ok || want != m[2] {
			t.Errorf("%s: image pins %s, binmgr pins %q", asset, m[2], want)
		}
	}
	metered := regexp.MustCompile(`(amd64|arm64)\) SBM_SHA=([0-9a-f]{64})`)
	for _, m := range metered.FindAllStringSubmatch(df, -1) {
		checked++
		asset := forgePanelSingboxAssetVer(m[1], SingboxVersion)
		if want, ok := compiledDigest(asset); !ok || want != m[2] {
			t.Errorf("%s: image pins %s, binmgr pins %q", asset, m[2], want)
		}
	}
	// amd64 and arm64, three upstream cores each, plus the metered build.
	if checked != 8 {
		t.Errorf("checked %d digests in the image, want 8 — the Dockerfile layout changed and this test no longer reads it", checked)
	}
}

// The script that builds the metered sing-box defaults to the version binmgr
// pins; a mismatch builds a binary whose checksum binmgr has no entry for.
func TestTheSingboxBuildScriptBuildsThePinnedVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "build-singbox.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`SINGBOX_VERSION="\$\{SINGBOX_VERSION:-([^}]+)\}"`).FindStringSubmatch(string(raw))
	if m == nil || m[1] != SingboxVersion {
		t.Fatalf("build-singbox.sh defaults to %v, binmgr pins %s", m, SingboxVersion)
	}
}
