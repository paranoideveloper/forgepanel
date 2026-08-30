package binmgr

// Adopting the sing-box ForgePanel builds and ships.
//
// WHY THERE IS A SECOND SING-BOX AT ALL. Per-user traffic counters for the
// protocols only sing-box serves — hysteria2, tuic, anytls, shadowtls,
// wireguard — exist only in a build carrying `with_v2ray_api`, and the official
// release archives are not built with it. On an official binary those protocols
// are UNMETERED: a user can exhaust their plan on them and stay active forever,
// because the quota system is guarding traffic it cannot see.
//
// So ForgePanel builds its own (scripts/build-singbox.sh): the same pinned
// upstream version, the official tag set plus that one tag, built with -trimpath
// and a pinned toolchain so the output is reproducible. Two independent builds
// produce byte-identical binaries, which is what makes the published checksum
// checkable rather than something to take on faith.
//
// HOW IT GETS HERE. The panel's own release ships it alongside forgepanel and
// forgenode, so it arrives however the panel itself arrived. This file finds
// that artifact, verifies it against the pinned checksum, and adopts it into the
// engine bin directory.
//
// WHEN IT IS ABSENT, the upstream official build is still downloaded and used.
// That is a deliberate fallback rather than a failure: the panel works, those
// protocols are simply unmetered, and the "Traffic metering" health subsystem
// says so in as many words. Refusing to start would be a worse trade for an
// operator who does not sell metered plans.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ForgePanelSingboxAsset is the filename of the build we ship, per architecture.
// It intentionally does NOT collide with the upstream archive name: the two are
// different artifacts and must never share a checksum entry.
func ForgePanelSingboxAsset(goarch string) string {
	return forgePanelSingboxAssetVer(goarch, SingboxVersion)
}

// forgePanelSingboxAssetVer names the shipped artifact for an arbitrary version,
// so an operator-pinned sing-box looks for the shipped build of THAT version
// rather than of the compiled one.
func forgePanelSingboxAssetVer(goarch, ver string) string {
	return fmt.Sprintf("sing-box-%s-linux-%s", ver, goarch)
}

// forgepanelSingboxCandidates lists where a shipped sing-box may be found,
// most-specific first.
//
// The neighbour of the running executable comes first because the release
// installs forgepanel and its cores side by side, so that copy is the one
// guaranteed to match this build.
func forgepanelSingboxCandidates(goarch string) []string {
	return forgepanelSingboxCandidatesNamed(ForgePanelSingboxAsset(goarch))
}

// forgepanelSingboxCandidatesNamed takes the resolved asset name so a pinned
// version searches for its own file.
func forgepanelSingboxCandidatesNamed(name string) []string {
	var out []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		out = append(out, filepath.Join(dir, name), filepath.Join(dir, "sing-box-forgepanel"))
	}
	out = append(out,
		filepath.Join("/usr/local/lib/forgepanel", name),
		filepath.Join("/usr/local/lib/forgepanel", "sing-box-forgepanel"),
		"/usr/local/bin/sing-box-forgepanel",
	)
	return out
}

// adoptForgePanelSingbox installs the shipped build into dst if one is present
// and its checksum matches the pin.
//
// It reports (false, nil) when no artifact is present — that is the ordinary
// case on a host that installed only the panel, not a fault. It reports an ERROR
// when an artifact IS present but does not verify: a file sitting in the release
// location with the wrong bytes is either a corrupt download or a tampered one,
// and silently ignoring it to fall back to upstream would hide exactly the event
// worth noticing.
func adoptForgePanelSingbox(dst, goarch string) (bool, error) {
	return adoptForgePanelSingboxPin(dst, goarch, SingboxVersion, compiledDigest)
}

// adoptForgePanelSingboxPin is adoptForgePanelSingbox for the version the
// manager has actually resolved.
//
// Threading this is not cosmetic. Ensure calls adopt BEFORE installSingbox, so
// on the unthreaded version an operator who pinned sing-box 1.14 got the SHIPPED
// 1.13 build copied into bin/sing-box-1.14/ and Ensure returned success — the
// panel reporting, in /api/capabilities and to every operator reading it, a
// version it was demonstrably not running.
func adoptForgePanelSingboxPin(dst, goarch, ver string, digest func(string) (string, bool)) (bool, error) {
	asset := forgePanelSingboxAssetVer(goarch, ver)
	for _, src := range forgepanelSingboxCandidatesNamed(asset) {
		info, err := os.Stat(src)
		if err != nil || info.IsDir() {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return false, fmt.Errorf("binmgr: read shipped sing-box %s: %w", src, err)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		want, pinned := digest(asset)
		if !pinned {
			return false, fmt.Errorf("binmgr: %s has no pinned checksum — refusing to install "+
				"an unverified proxy core", asset)
		}
		if !strings.EqualFold(got, want) {
			return false, fmt.Errorf("binmgr: %s at %s does not match its pinned checksum "+
				"(got %s, want %s). Refusing to install it: rebuild with scripts/build-singbox.sh "+
				"and compare, or remove the file to fall back to the upstream build", asset, src, got, want)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return false, err
		}
		// Write through a temp file and rename, so a reader never sees a
		// half-written core.
		tmp := dst + ".adopt"
		if err := os.WriteFile(tmp, data, 0o755); err != nil {
			return false, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return false, err
		}
		return true, nil
	}
	return false, nil
}
