package binmgr

import (
	"strings"
	"testing"
)

// allPlatforms is the union of every OS/CPU any of the three cores publishes a
// build for. The golden table below states, for each engine, exactly which
// asset each of these resolves to — or that it must be refused.
var allPlatforms = []platform{
	{"linux", "386"}, {"linux", "amd64"}, {"linux", "armv5"}, {"linux", "armv6"},
	{"linux", "armv7"}, {"linux", "arm64"}, {"linux", "riscv64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"freebsd", "386"}, {"freebsd", "amd64"}, {"freebsd", "armv7"}, {"freebsd", "arm64"},
	{"windows", "386"}, {"windows", "amd64"}, {"windows", "arm64"},
}

// wantAssets is the golden mapping. An empty value means "upstream publishes
// nothing for this platform, so resolution must fail".
//
// This is spelled out per platform rather than derived, because deriving it is
// exactly what went wrong before: sing-box and brook computed an arch from
// runtime.GOARCH with an `else { amd64 }` fallback, so every platform other than
// amd64/arm64 quietly resolved to the x86-64 Linux build.
var wantAssets = map[Engine]map[platform]string{
	EngineXray: {
		{"linux", "386"}:     "Xray-linux-32.zip",
		{"linux", "amd64"}:   "Xray-linux-64.zip",
		{"linux", "armv5"}:   "Xray-linux-arm32-v5.zip",
		{"linux", "armv6"}:   "Xray-linux-arm32-v6.zip",
		{"linux", "armv7"}:   "Xray-linux-arm32-v7a.zip",
		{"linux", "arm64"}:   "Xray-linux-arm64-v8a.zip",
		{"linux", "riscv64"}: "Xray-linux-riscv64.zip",
		{"darwin", "amd64"}:  "Xray-macos-64.zip",
		{"darwin", "arm64"}:  "Xray-macos-arm64-v8a.zip",
		{"freebsd", "386"}:   "Xray-freebsd-32.zip",
		{"freebsd", "amd64"}: "Xray-freebsd-64.zip",
		{"freebsd", "armv7"}: "Xray-freebsd-arm32-v7a.zip",
		{"freebsd", "arm64"}: "Xray-freebsd-arm64-v8a.zip",
		{"windows", "386"}:   "Xray-windows-32.zip",
		{"windows", "amd64"}: "Xray-windows-64.zip",
		{"windows", "arm64"}: "Xray-windows-arm64-v8a.zip",
	},
	EngineSingbox: {
		{"linux", "386"}:     "sing-box-" + SingboxVersion + "-linux-386.tar.gz",
		{"linux", "amd64"}:   "sing-box-" + SingboxVersion + "-linux-amd64.tar.gz",
		{"linux", "armv5"}:   "sing-box-" + SingboxVersion + "-linux-armv5.tar.gz",
		{"linux", "armv6"}:   "sing-box-" + SingboxVersion + "-linux-armv6.tar.gz",
		{"linux", "armv7"}:   "sing-box-" + SingboxVersion + "-linux-armv7.tar.gz",
		{"linux", "arm64"}:   "sing-box-" + SingboxVersion + "-linux-arm64.tar.gz",
		{"linux", "riscv64"}: "sing-box-" + SingboxVersion + "-linux-riscv64.tar.gz",
		{"darwin", "amd64"}:  "sing-box-" + SingboxVersion + "-darwin-amd64.tar.gz",
		{"darwin", "arm64"}:  "sing-box-" + SingboxVersion + "-darwin-arm64.tar.gz",
		// sing-box publishes no FreeBSD build of any architecture.
		{"freebsd", "386"}:   "",
		{"freebsd", "amd64"}: "",
		{"freebsd", "armv7"}: "",
		{"freebsd", "arm64"}: "",
		{"windows", "386"}:   "sing-box-" + SingboxVersion + "-windows-386.zip",
		{"windows", "amd64"}: "sing-box-" + SingboxVersion + "-windows-amd64.zip",
		{"windows", "arm64"}: "sing-box-" + SingboxVersion + "-windows-arm64.zip",
	},
	EngineBrook: {
		{"linux", "386"}:   "brook_linux_386",
		{"linux", "amd64"}: "brook_linux_amd64",
		{"linux", "armv5"}: "brook_linux_arm5",
		{"linux", "armv6"}: "brook_linux_arm6",
		{"linux", "armv7"}: "brook_linux_arm7",
		{"linux", "arm64"}: "brook_linux_arm64",
		// brook publishes no riscv64 build, and no 32-bit or ARM FreeBSD build.
		{"linux", "riscv64"}: "",
		{"darwin", "amd64"}:  "brook_darwin_amd64",
		{"darwin", "arm64"}:  "brook_darwin_arm64",
		{"freebsd", "386"}:   "",
		{"freebsd", "amd64"}: "brook_freebsd_amd64",
		{"freebsd", "armv7"}: "",
		{"freebsd", "arm64"}: "brook_freebsd_arm64",
		{"windows", "386"}:   "brook_windows_386.exe",
		{"windows", "amd64"}: "brook_windows_amd64.exe",
		{"windows", "arm64"}: "brook_windows_arm64.exe",
	},
}

// The regression this whole file guards: a host that is not amd64/arm64 Linux
// must get the build for ITS platform or a clear refusal, never the x86-64 Linux
// build under another name.
func TestAssetForResolvesEveryPlatformOrRefusesIt(t *testing.T) {
	for _, e := range ManagedEngines() {
		for _, p := range allPlatforms {
			want, listed := wantAssets[e][p]
			if !listed {
				t.Fatalf("golden table has no expectation for %s on %s", e, p)
			}
			got, err := assetFor(e, p)
			switch {
			case want == "" && err == nil:
				t.Errorf("%s on %s: upstream publishes nothing, but resolved to %q", e, p, got)
			case want == "":
				if !strings.Contains(err.Error(), p.String()) {
					t.Errorf("%s on %s: refusal must name the platform, got %v", e, p, err)
				}
			case err != nil:
				t.Errorf("%s on %s: want %q, got error %v", e, p, want, err)
			case got != want:
				t.Errorf("%s on %s: want %q, got %q", e, p, want, got)
			}
		}
	}
}

// A platform this panel has no PINNED asset for must be refused by name, not
// silently served some other machine's binary.
//
// The distinction matters and the first version of this test got it wrong: it
// was written as "a platform none of the cores publishes for" and listed
// linux/s390x, linux/mips64le, linux/ppc64le, openbsd/amd64 and android/arm64 —
// six of which upstream DOES publish (Xray-linux-s390x.zip, Xray-openbsd-64.zip,
// Xray-android-arm64-v8a.zip and so on). The test passed, but on a false
// premise, and it would have been read as evidence that those platforms are
// impossible rather than merely unpinned.
//
// What is actually guaranteed here is narrower and still worth guarding: the
// resolver refuses anything outside its own tables instead of guessing. Adding a
// platform is a deliberate act — a table entry AND a checksum pin, enforced by
// the test below — because an unpinned download is an unverified binary.
func TestAssetForRefusesPlatformsWithNoPinnedAsset(t *testing.T) {
	for _, p := range []platform{
		// Genuinely nonexistent, so no future pin can make these pass.
		{"plan9", "arm64"}, {"darwin", "386"}, {"linux", "sparc64"},
		// Real upstream platforms this panel has deliberately not pinned. If one
		// is ever added, this case must be removed in the same commit — which is
		// the point: it makes the addition visible rather than incidental.
		{"linux", "s390x"}, {"openbsd", "amd64"},
	} {
		for _, e := range ManagedEngines() {
			got, err := assetFor(e, p)
			if err == nil {
				t.Errorf("%s on unpinned %s resolved to %q instead of failing", e, p, got)
			}
		}
	}
}

// Every platform in a table must have a pinned checksum, and every pin must be
// reachable from a table. A pin with no table entry is dead weight that hides a
// dropped platform; a table entry with no pin is a download that can only end in
// a refusal, and assetFor is where that has to be caught.
func TestTablesAndPinsAgree(t *testing.T) {
	reachable := map[string]bool{}
	for _, e := range ManagedEngines() {
		for _, p := range allPlatforms {
			if name, err := assetFor(e, p); err == nil {
				reachable[name] = true
			}
		}
	}
	// The builds ForgePanel compiles itself are adopted from disk, never
	// downloaded, so they are pinned without appearing in any asset table.
	for _, goarch := range []string{"amd64", "arm64"} {
		reachable[ForgePanelSingboxAsset(goarch)] = true
	}
	for name := range pinnedSHA256 {
		if !reachable[name] {
			t.Errorf("pinned checksum for %q is unreachable: no platform resolves to it", name)
		}
	}
}

// An asset that is published but not pinned must be refused BEFORE the download,
// with a message that says the pin is missing rather than implying tampering.
func TestAssetForRefusesUnpinnedAsset(t *testing.T) {
	const name = "Xray-linux-riscv64.zip"
	orig, had := pinnedSHA256[name]
	if !had {
		t.Fatalf("%s should be pinned", name)
	}
	delete(pinnedSHA256, name)
	defer func() { pinnedSHA256[name] = orig }()

	_, err := assetFor(EngineXray, platform{"linux", "riscv64"})
	if err == nil {
		t.Fatal("an unpinned asset must not be offered for download")
	}
	if !strings.Contains(err.Error(), "no pinned checksum") {
		t.Fatalf("error should name the missing pin, got %v", err)
	}
}

func TestNormalizeGOARM(t *testing.T) {
	for in, want := range map[string]string{
		"5": "5", "6": "6", "7": "7",
		"7,hardfloat": "7", // Go 1.23+ records the float mode alongside the level
		"5,softfloat": "5",
		"":            "5", // unknown falls back to the level every ARM CPU runs
		"9":           "5",
	} {
		if got := normalizeGOARM(in); got != want {
			t.Errorf("normalizeGOARM(%q) = %q, want %q", in, got, want)
		}
	}
}

// On Windows the archive member and the installed file both carry .exe; on every
// other OS neither does.
func TestBinaryNamePerOS(t *testing.T) {
	for _, tc := range []struct {
		e    Engine
		goos string
		want string
	}{
		{EngineXray, "linux", "xray"},
		{EngineXray, "windows", "xray.exe"},
		{EngineSingbox, "darwin", "sing-box"},
		{EngineSingbox, "windows", "sing-box.exe"},
		{EngineBrook, "freebsd", "brook"},
		{EngineBrook, "windows", "brook.exe"},
	} {
		if got := binaryName(tc.e, tc.goos); got != tc.want {
			t.Errorf("binaryName(%s, %s) = %q, want %q", tc.e, tc.goos, got, tc.want)
		}
	}
}

// hostPlatform must describe the machine the test is running on, and must narrow
// 32-bit ARM to a concrete level so it can key the asset tables at all.
func TestHostPlatformIsResolvable(t *testing.T) {
	p := hostPlatform()
	if p.os == "" || p.arch == "" {
		t.Fatalf("hostPlatform() incomplete: %+v", p)
	}
	if p.arch == "arm" {
		t.Fatal("32-bit ARM must be narrowed to armv5/armv6/armv7; bare \"arm\" keys no table")
	}
}
