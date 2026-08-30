// Package binmgr downloads, verifies, pins and caches the proxy-core binaries
// the supervisor drives (spec §6). Versions are pinned; the first download is
// checksum-verified and the observed SHA-256 is recorded so later runs detect
// tampering. Binaries live under <dataDir>/bin/<engine>-<version>/.
package binmgr

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// Pinned versions (spec §6: pinned, checksum-verified).
const (
	XrayVersion    = "v26.3.27"
	SingboxVersion = "1.13.15"
	BrookVersion   = "v20260101.0"
)

// Engine identifies a supervised core.
type Engine string

const (
	EngineXray    Engine = "xray"
	EngineSingbox Engine = "sing-box"
	EngineBrook   Engine = "brook"
)

// httpClient bounds download time so a boot never hangs forever.
var httpClient = netegress.Client(5 * time.Minute)

// Pin is an operator-selected core version plus the digests that make it
// installable. The version above is what this build shipped with; a Pin is how
// an operator moves off it without a rebuild — a CVE fix upstream published this
// morning, or a rollback to the release that did not break their transport.
//
// SHA256 is not optional. Every path that writes a core binary goes through
// verifyPinned, and a version whose asset has no digest is refused by SetPins
// rather than downloaded and hoped about.
type Pin struct {
	Version string
	SHA256  map[string]string // release filename -> hex SHA-256
}

// Manager resolves and caches core binaries under BinDir.
type Manager struct {
	BinDir string
	// Pins overrides the compiled version and digests, per engine. Safe to
	// assign directly at construction, before the Manager is shared; after that
	// use SetPins, which takes the lock this field is guarded by.
	//
	// Nil is the ordinary state and means "the versions this build shipped
	// with", so every caller that never pins is unaffected by any of this.
	Pins map[Engine]Pin
	mu   sync.RWMutex
}

// New returns a Manager rooted at dataDir/bin.
func New(dataDir string) *Manager { return &Manager{BinDir: filepath.Join(dataDir, "bin")} }

// pin returns the operator's selection for e, if there is one.
func (m *Manager) pin(e Engine) (Pin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.Pins[e]
	return p, ok && p.Version != ""
}

// version is the version this manager will actually resolve for e: the
// operator's selection when there is one, otherwise the compiled constant.
func (m *Manager) version(e Engine) string {
	if p, ok := m.pin(e); ok {
		return p.Version
	}
	return versionFor(e)
}

// Version exposes the effective version so the API can report the core the panel
// is really running rather than the one it was compiled against.
func (m *Manager) Version(e Engine) string { return m.version(e) }

// digest resolves an asset's expected SHA-256: an operator pin first, then the
// compiled table. Pins never write into pinnedSHA256 — that map is the record of
// what THIS BUILD verified, and TestTablesAndPinsAgree holds it to being
// reachable from a platform table.
func (m *Manager) digest(asset string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.Pins {
		if want, ok := p.SHA256[asset]; ok {
			return want, true
		}
	}
	return compiledDigest(asset)
}

// digestFn snapshots the digest resolver so the install path — which spends
// minutes inside a download — never holds the lock a SetPins is waiting on.
func (m *Manager) digestFn() func(string) (string, bool) {
	m.mu.RLock()
	snapshot := make(map[string]string)
	for _, p := range m.Pins {
		for asset, want := range p.SHA256 {
			snapshot[asset] = want
		}
	}
	m.mu.RUnlock()
	return func(asset string) (string, bool) {
		if want, ok := snapshot[asset]; ok {
			return want, true
		}
		return compiledDigest(asset)
	}
}

// Path returns the on-disk path a resolved engine binary would have (whether or
// not it is present yet).
//
// The version in the directory name is the EFFECTIVE one, which is what makes a
// pin reach the running cores at all: Ensure installs into this path and every
// adapter execs it. It is also what makes rollback free — the previous version's
// directory is still on disk under its own name.
func (m *Manager) Path(e Engine) string {
	return filepath.Join(m.BinDir, string(e)+"-"+m.version(e), binaryName(e, runtime.GOOS))
}

// binaryName is the file name a core has on disk AND inside its release archive.
//
// They are the same string on purpose: the extractors match archive members by
// base name, so "what we pull out of the zip" and "what we install" cannot drift
// apart. On Windows every upstream archive carries the ".exe" suffix, and an
// extension-less copy is not executable there, so the suffix is part of the name
// rather than something the caller remembers to append.
func binaryName(e Engine, goos string) string {
	name := "xray"
	switch e {
	case EngineSingbox:
		name = "sing-box"
	case EngineBrook:
		name = "brook"
	}
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// managedEngines is every core this manager can download. It is the single list
// Managed and Ensure both answer from, so a core added to one and not the other
// is a test failure rather than an "unknown engine" at an operator's first
// reload.
var managedEngines = []Engine{EngineXray, EngineSingbox, EngineBrook}

// Managed reports whether this manager fetches a binary for e.
//
// Not every core has one to fetch. AmneziaWG runs from the host's own kernel
// module and awg-quick tooling, so asking for its "binary" is not an error and
// must not be treated as one — a caller that fetches whatever the inbounds need
// has to be able to tell "nothing to download" from "download failed".
func Managed(e Engine) bool {
	for _, m := range managedEngines {
		if m == e {
			return true
		}
	}
	return false
}

// ManagedEngines returns the cores this manager can download.
func ManagedEngines() []Engine { return append([]Engine(nil), managedEngines...) }

// Ensure makes sure the pinned binary for e exists and is executable, downloading
// and verifying it if necessary. It returns the binary path.
func (m *Manager) Ensure(e Engine) (string, error) {
	p := m.Path(e)
	if fi, err := os.Stat(p); err == nil && fi.Mode()&0o111 != 0 {
		return p, nil // already installed
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	switch e {
	case EngineXray:
		return p, m.installXray(p)
	case EngineSingbox:
		// Prefer the build ForgePanel ships: it is the only one that can report
		// per-user traffic for the protocols sing-box serves. Falling back to
		// upstream is deliberate — the panel works either way, those protocols
		// are simply unmetered, and the metering health subsystem says so.
		if adopted, err := adoptForgePanelSingboxPin(p, runtime.GOARCH, m.version(EngineSingbox), m.digestFn()); err != nil {
			return "", err
		} else if adopted {
			return p, nil
		}
		return p, m.installSingbox(p)
	case EngineBrook:
		return p, m.installBrook(p)
	default:
		return "", fmt.Errorf("binmgr: unknown engine %q", e)
	}
}

// ShippedVersion is the version this build was compiled against, which is what
// an engine falls back to with no operator pin.
func ShippedVersion(e Engine) string { return versionFor(e) }

func versionFor(e Engine) string {
	switch e {
	case EngineSingbox:
		return SingboxVersion
	case EngineBrook:
		return BrookVersion
	}
	return XrayVersion
}

// pinnedSHA256 maps a downloaded engine artifact (by its exact release filename)
// to its expected SHA-256. Verification against these baked-in values is
// MANDATORY for every engine: an artifact whose checksum is unknown or does not
// match is never written into place. This is stronger than trusting a checksum
// file fetched from the same host, and it closes the previous silent bypass
// (installs proceeding when the .dgst download failed). Update these when the
// pinned versions above change.
var pinnedSHA256 = map[string]string{
	// Xray-core, one archive per published GOOS/GOARCH. Every value below was
	// cross-checked against the .dgst file upstream publishes beside the asset.
	"Xray-linux-32.zip":          "d1eeb0d9a9106eefd286fbb73595c2dfe1c48c56aa91ba1c9aefe04f188d0927",
	"Xray-linux-64.zip":          "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
	"Xray-linux-arm32-v5.zip":    "0da9a632e15e82504831f61bf6b46c21e3081bcc79ad46bdc16e7dc2f0dc9088",
	"Xray-linux-arm32-v6.zip":    "0c6e751e2bba3f3ff09a793dd6a6bc45fd6fd89f49b49dfc0cf6d922dc123bec",
	"Xray-linux-arm32-v7a.zip":   "c7265ae13c63ca0241a037df4ef960ad37938c8a67d984cc08834b2cfdf5654b",
	"Xray-linux-arm64-v8a.zip":   "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
	"Xray-linux-riscv64.zip":     "627ea5870b6fd05d95b7f4ceb5a54d7f2664dd075b30a7ac46ee9a6f9653d6f8",
	"Xray-macos-64.zip":          "f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203",
	"Xray-macos-arm64-v8a.zip":   "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
	"Xray-freebsd-32.zip":        "d2e5d9cf175f4449b5506e2de45de144b5e1160cada1f8c350087aba465b127f",
	"Xray-freebsd-64.zip":        "c0fcd6962fc8a382e14441370ddbdb6a56e7108c73e817938c626770ac4a1358",
	"Xray-freebsd-arm32-v7a.zip": "ffc017f8a25452996897f5aa04b7cde4a08d9b11a716c2e906afc93be36d7103",
	"Xray-freebsd-arm64-v8a.zip": "0f0adda9c445696f7bdd7c3788358988359cc9c5218c7487851de7db7ec6dabd",
	"Xray-windows-32.zip":        "956a5ec00bce747c7936dc4ff7ac570df1c8030b0a4a8640f843488365084db3",
	"Xray-windows-64.zip":        "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
	"Xray-windows-arm64-v8a.zip": "35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88",
	// sing-box official release archives: .tar.gz everywhere, .zip on Windows.
	// These are NOT the ForgePanel builds at the bottom of this map.
	"sing-box-1.13.15-linux-386.tar.gz":     "4180f34fcab227b1b6912e2a4e3cf9e6d484a7c885b5b0ea9d4cd45c7351527e",
	"sing-box-1.13.15-linux-amd64.tar.gz":   "a3a3ff223b23c3f4731d0a17cb0ef94c97ce257c70721a5b07dc7ca079203c9f",
	"sing-box-1.13.15-linux-armv5.tar.gz":   "9a9f4504eef9b4a00e17f56389c69a96df4dfbea3713f5e6ab77323316f415ac",
	"sing-box-1.13.15-linux-armv6.tar.gz":   "27f068b9ef3069bb682fa72740a852d531d84c1868235a984e1c4628d9da8bc7",
	"sing-box-1.13.15-linux-armv7.tar.gz":   "30e951f091a80464d2b22a2c5f02fbe55f04b2d3f38a5701d51da3be8cf09761",
	"sing-box-1.13.15-linux-arm64.tar.gz":   "f0810bbb5722ae36635687c421019defcc8b328d31a0b3c287901f331747ca93",
	"sing-box-1.13.15-linux-riscv64.tar.gz": "160a68cc4e29de6c733ab110c285820c55660bdd5277bbfbc91566ecfa666da0",
	"sing-box-1.13.15-darwin-amd64.tar.gz":  "817e04f90f941b718fedd965ff05bfe72abfcc62952888b01751a6dec5547e14",
	"sing-box-1.13.15-darwin-arm64.tar.gz":  "3452d866834c9572389e5ca73e60d4ee45a7d5b79332188c9a9e533c5fd40a6d",
	"sing-box-1.13.15-windows-386.zip":      "42cba95de96ffd6cea599fa18ff3328a37738025c7233c9b9e4a382c237c8b50",
	"sing-box-1.13.15-windows-amd64.zip":    "599b296f6e57511d36d2a6f3011aed1a86fa98418578bbb06bd6dc241b5d8877",
	"sing-box-1.13.15-windows-arm64.zip":    "82419193e0f087279fd7add4fbe90a26c93396057477e8c014a534ec8b2d63ec",
	// brook ships one bare binary per platform, no archive.
	"brook_linux_386":         "7311a61483c805954d0ca49aaf5db9480138cf4ea00d09e2b83d4fd88b1b874b",
	"brook_linux_amd64":       "7853250042877716376fab14a3a99be44bf242cd69dec11cfa71fada915db372",
	"brook_linux_arm5":        "075498ecd120f666dcc67f5a2967aaaee3bafe52853905efbb9ae43ec180c10c",
	"brook_linux_arm6":        "4fa330d379943610a93017bcba6d1784771654a6dac8b0d0178052888e436eca",
	"brook_linux_arm7":        "dcb748424868f2f8d9946856b409522d556a811d797b0b06d9803e0100863de6",
	"brook_linux_arm64":       "5c720698f811ecc265311574140c20d912037ca36aecccd7e8536d03e581a2db",
	"brook_darwin_amd64":      "ec43880e6beb3f6f98462b180cd6c8f8e9bd25df2633d3b13aa4b8ac8e20a1ae",
	"brook_darwin_arm64":      "8b3e25b65d4a4f8a5715575a49282d95c04f6493d17fd7ae21c51444432c2e8b",
	"brook_freebsd_amd64":     "9681e0c4067a300a718327ec14887585182c5694f7b0498e3ac61aaac89c1504",
	"brook_freebsd_arm64":     "66963ad89b43bf4e72128c651571202bc91cef093bb400f83b44d6ecc46351ab",
	"brook_windows_386.exe":   "a6d6a8af13e1db9d66f27b033cf08f8665b64204957261a3422a9f45b733fc60",
	"brook_windows_amd64.exe": "ce8459f83dfd4384be00b980a3d0a8f753fd058b8bbe3775b97a1daaa27472d2",
	"brook_windows_arm64.exe": "429a6aaa541670214d90bac63c604c85a63c5dc9244c05846a1510cef642038b",
	// The sing-box ForgePanel builds and ships (scripts/build-singbox.sh): the
	// same upstream version, the official tag set plus with_v2ray_api, built
	// reproducibly. These are NOT the upstream archives above and must never
	// share an entry with them — they are different artifacts. Only the two
	// architectures the panel itself is released for get a build.
	//
	// Reproduce with:  TARGETS="amd64 arm64" scripts/build-singbox.sh
	// and compare; two independent builds are byte-identical.
	"sing-box-1.13.15-linux-amd64": "bb4d1b057836e2d955020b4be6c8084023cb6c91f330b50e485e6b8b02dc7563",
	"sing-box-1.13.15-linux-arm64": "f163bae1ac31e80fed67a9e51463ef943ed4a13ffba35db591546220073eab0a",
}

// compiledDigest reads the table above: the digests this build was shipped with.
func compiledDigest(asset string) (string, bool) {
	want, ok := pinnedSHA256[asset]
	return want, ok
}

// verifyPinned enforces the mandatory checksum: it fails if the artifact has no
// pinned entry (unknown filename) or if the SHA-256 does not match.
func verifyPinned(asset string, data []byte) error {
	return verifyPinnedWith(asset, data, compiledDigest)
}

// verifyPinnedWith is verifyPinned against a caller-supplied digest source, so
// an operator-pinned version is verified by exactly the same code — and refused
// by exactly the same message — as a compiled one. There is deliberately no
// second, laxer checksum path for pinned versions to slip through.
func verifyPinnedWith(asset string, data []byte, digest func(string) (string, bool)) error {
	want, ok := digest(asset)
	if !ok {
		return fmt.Errorf("binmgr: no pinned checksum for %q — refusing to install unverified artifact", asset)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("binmgr: checksum mismatch for %s: got %s, want %s", asset, got, want)
	}
	return nil
}

// finalizeInstall verifies the pinned checksum, materializes the binary into a
// temp path via extract, checks its self-reported version, then atomically swaps
// it into place — so a failed or tampered download never replaces a known-good
// binary, and temp files are cleaned up on any failure.
func finalizeInstall(dst, asset string, data []byte, extract func(tmp string) error, wantVersion string, digest func(string) (string, bool)) error {
	if err := verifyPinnedWith(asset, data, digest); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	if err := extract(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := verifyVersion(tmp, wantVersion); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// installXray downloads the Xray archive for this host, verifies its pinned
// SHA-256, and atomically installs the binary.
func (m *Manager) installXray(dst string) error {
	host := hostPlatform()
	ver, dg := m.version(EngineXray), m.digestFn()
	asset, err := assetForPin(EngineXray, host, ver, dg)
	if err != nil {
		return err
	}
	member := binaryName(EngineXray, host.os)
	base := "https://github.com/XTLS/Xray-core/releases/download/" + ver + "/"
	zipBytes, err := download(base + asset)
	if err != nil {
		return fmt.Errorf("download xray: %w", err)
	}
	// The effective version reaches verifyVersion too, not just the URL: a
	// pinned v25.1.1 binary self-reports v25.1.1, so checking it against the
	// compiled constant would fail every pinned install with a message about a
	// version mismatch that nobody asked for.
	if err := finalizeInstall(dst, asset, zipBytes,
		func(tmp string) error { return extractZipFile(zipBytes, member, tmp) },
		"Xray "+strings.TrimPrefix(ver, "v"), dg); err != nil {
		return err
	}
	return installGeodata(filepath.Dir(dst), zipBytes)
}

// GeoAssetNames are the geodata files Xray needs to resolve geosite: and geoip:
// rules.
var GeoAssetNames = []string{"geoip.dat", "geosite.dat"}

// installGeodata extracts the geodata files that ship in the SAME archive as the
// binary.
//
// They were being thrown away. The extractor pulled out "xray" and discarded the
// rest, so a panel-managed Xray had no geosite.dat or geoip.dat — and every rule
// using `geosite:category-ads-all` or `geoip:private` failed, both when the panel
// validated it and when the core ran it. Not a subtle failure: the core refuses
// the whole config with "code not found in geosite.dat", taking every inbound
// down. It only looked fine on a machine that happened to have a system-wide
// Xray installed separately.
//
// They are installed NEXT TO the binary, and the engines are started with
// XRAY_LOCATION_ASSET pointing there, so the panel's core uses the panel's
// geodata rather than whatever version some unrelated system install left behind.
func installGeodata(dir string, zipBytes []byte) error {
	for _, name := range GeoAssetNames {
		dst := filepath.Join(dir, name)
		tmp := dst + ".tmp"
		_ = os.Remove(tmp)
		if err := extractZipFile(zipBytes, name, tmp); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("xray geodata: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("install %s: %w", name, err)
		}
	}
	return nil
}

// Present reports whether an engine's binary is already installed, WITHOUT
// downloading it.
//
// The distinction matters: Ensure fetches ~60MB when the binary is absent, which
// is right for a reload and completely wrong for validating an edit. A routing
// rule save that silently triggered a download would block the request for as
// long as the transfer took, on a panel that had not asked for the core yet.
func (m *Manager) Present(e Engine) bool {
	st, err := os.Stat(m.Path(e))
	return err == nil && !st.IsDir() && st.Size() > 0
}

// GeoAssetDir is the directory holding the geodata for an engine's binary.
func (m *Manager) GeoAssetDir(e Engine) string { return filepath.Dir(m.Path(e)) }

// GeoAssetsPresent reports whether both geodata files are installed.
//
// Used to tell "this rule names a category that does not exist" apart from "this
// panel has no geodata at all" — two failures with the same core error message
// and completely different fixes.
func (m *Manager) GeoAssetsPresent(e Engine) bool {
	dir := m.GeoAssetDir(e)
	for _, name := range GeoAssetNames {
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.Size() == 0 {
			return false
		}
	}
	return true
}

// installSingbox downloads the tar.gz, extracts the binary, and verifies the
// reported version.
func (m *Manager) installSingbox(dst string) error {
	host := hostPlatform()
	ver, dg := m.version(EngineSingbox), m.digestFn()
	asset, err := assetForPin(EngineSingbox, host, ver, dg)
	if err != nil {
		return err
	}
	member := binaryName(EngineSingbox, host.os)
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", ver, asset)
	archive, err := download(url)
	if err != nil {
		return fmt.Errorf("download sing-box: %w", err)
	}
	// Upstream ships Windows as a zip and every other platform as a tar.gz. The
	// suffix of the asset we resolved is the authority on which it is, so a
	// future platform that changes container type cannot be mis-extracted.
	extract := func(tmp string) error { return extractTarGzFile(archive, member, tmp) }
	if strings.HasSuffix(asset, ".zip") {
		extract = func(tmp string) error { return extractZipFile(archive, member, tmp) }
	}
	return finalizeInstall(dst, asset, archive, extract, "sing-box version "+ver, dg)
}

// platform is the OS/CPU pair a release asset is published for.
//
// arch is runtime.GOARCH except for 32-bit ARM, which every upstream project
// splits into ARMv5/v6/v7 builds; see armLevel for how that is resolved.
type platform struct {
	os   string
	arch string
}

func (p platform) String() string { return p.os + "/" + p.arch }

// hostPlatform is the platform this panel process is running on.
//
// It exists so asset selection is a pure function of an explicit value rather
// than of runtime.GOARCH read three times in three places. That indirection is
// the whole point: the previous code could only be exercised on the machine the
// test ran on, so the arch mapping for every other machine was untested — and
// wrong, silently, for sing-box and brook.
func hostPlatform() platform {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv" + armLevel()
	}
	return platform{os: runtime.GOOS, arch: arch}
}

// armLevel reports which ARM level ("5", "6" or "7") a 32-bit ARM core may be
// built for on this host.
//
// There is no runtime API for the CPU's ARM level, but there does not need to
// be: this panel binary is itself a Go program compiled with some GOARM, and it
// is running, so the CPU satisfies at least that level. The build settings
// recorded in the executable therefore give a floor we know is safe.
//
// When the setting is missing (a binary stripped of build info) we fall back to
// ARMv5, which runs on every ARM CPU Go targets. That costs some performance on
// a v7 board; guessing high instead would hand an ARMv5 board a core that dies
// with SIGILL on its first instruction, which is not a trade worth making.
func armLevel() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOARM" {
				return normalizeGOARM(s.Value)
			}
		}
	}
	return "5"
}

// normalizeGOARM turns a recorded GOARM build setting into a bare ARM level.
// Go 1.23 and later append a floating-point mode ("7,hardfloat"); older
// toolchains record just the digit. Anything unrecognized falls back to the
// ARMv5 floor for the reason armLevel explains.
func normalizeGOARM(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	switch v {
	case "5", "6", "7":
		return v
	}
	return "5"
}

// xrayAssets maps a host platform to the exact Xray-core release archive for it.
// Xray names its 32-bit x86 build "32", its 64-bit build "64", and macOS
// "macos", so none of these can be derived from GOOS/GOARCH by string surgery.
var xrayAssets = map[platform]string{
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
	// Upstream publishes only a v7a build for 32-bit ARM FreeBSD, so an ARMv5 or
	// ARMv6 FreeBSD host has no Xray and gets told so rather than handed a
	// binary its CPU cannot run.
	{"freebsd", "armv7"}: "Xray-freebsd-arm32-v7a.zip",
	{"freebsd", "arm64"}: "Xray-freebsd-arm64-v8a.zip",
	{"windows", "386"}:   "Xray-windows-32.zip",
	{"windows", "amd64"}: "Xray-windows-64.zip",
	{"windows", "arm64"}: "Xray-windows-arm64-v8a.zip",
}

// singboxAssets maps a host platform to the platform-specific tail of the
// sing-box release filename, which is sing-box-<version>-<tail>. The version sits
// in the middle of the name, so the table holds the tail and singboxAsset splices
// the pinned version in.
//
// sing-box publishes no FreeBSD build at all; that platform is absent on purpose.
var singboxAssets = map[platform]string{
	{"linux", "386"}:     "linux-386.tar.gz",
	{"linux", "amd64"}:   "linux-amd64.tar.gz",
	{"linux", "armv5"}:   "linux-armv5.tar.gz",
	{"linux", "armv6"}:   "linux-armv6.tar.gz",
	{"linux", "armv7"}:   "linux-armv7.tar.gz",
	{"linux", "arm64"}:   "linux-arm64.tar.gz",
	{"linux", "riscv64"}: "linux-riscv64.tar.gz",
	{"darwin", "amd64"}:  "darwin-amd64.tar.gz",
	{"darwin", "arm64"}:  "darwin-arm64.tar.gz",
	// Windows is the one platform sing-box ships as a zip; installSingbox picks
	// the extractor from this suffix rather than from GOOS.
	{"windows", "386"}:   "windows-386.zip",
	{"windows", "amd64"}: "windows-amd64.zip",
	{"windows", "arm64"}: "windows-arm64.zip",
}

func singboxAsset(p platform) (string, bool) { return singboxAssetVer(p, SingboxVersion) }

// singboxAssetVer splices an arbitrary version into the release name. sing-box
// is the one engine whose asset FILENAME carries the version, so an operator pin
// changes the name here and not only the URL.
func singboxAssetVer(p platform, ver string) (string, bool) {
	tail, ok := singboxAssets[p]
	if !ok {
		return "", false
	}
	return "sing-box-" + ver + "-" + tail, true
}

// brookAssets maps a host platform to brook's bare-binary release name. brook
// publishes no riscv64 build, and no 32-bit FreeBSD or FreeBSD ARM build, so
// those platforms are absent on purpose.
var brookAssets = map[platform]string{
	{"linux", "386"}:     "brook_linux_386",
	{"linux", "amd64"}:   "brook_linux_amd64",
	{"linux", "armv5"}:   "brook_linux_arm5",
	{"linux", "armv6"}:   "brook_linux_arm6",
	{"linux", "armv7"}:   "brook_linux_arm7",
	{"linux", "arm64"}:   "brook_linux_arm64",
	{"darwin", "amd64"}:  "brook_darwin_amd64",
	{"darwin", "arm64"}:  "brook_darwin_arm64",
	{"freebsd", "amd64"}: "brook_freebsd_amd64",
	{"freebsd", "arm64"}: "brook_freebsd_arm64",
	{"windows", "386"}:   "brook_windows_386.exe",
	{"windows", "amd64"}: "brook_windows_amd64.exe",
	{"windows", "arm64"}: "brook_windows_arm64.exe",
}

// assetFor returns the release filename to download for e on platform p.
//
// It replaces three separate arch mappings that all ended in an amd64 fallback:
// sing-box and brook took whatever GOARCH they were given and downloaded the
// x86-64 Linux build for it, so a 386, ARMv7, riscv64, macOS or Windows host
// installed a binary it could not execute. The failure surfaced much later, as
// "cannot run <path>: exec format error" from the version check — or, on a host
// with binfmt/qemu registered, as a core that ran under emulation at a fraction
// of the speed with nobody the wiser. An explicit error naming the platform is
// the only honest answer for a combination upstream does not publish.
func assetFor(e Engine, p platform) (string, error) {
	return assetForPin(e, p, versionFor(e), compiledDigest)
}

// assetNameFor resolves the release FILENAME only, with no opinion about whether
// anything can verify it. It is split out because the pin API has to tell an
// operator which file to supply a digest for, and at that moment there is by
// definition no digest yet.
func assetNameFor(e Engine, p platform, ver string) (string, error) {
	var (
		name string
		ok   bool
	)
	switch e {
	case EngineXray:
		name, ok = xrayAssets[p]
	case EngineSingbox:
		name, ok = singboxAssetVer(p, ver)
	case EngineBrook:
		name, ok = brookAssets[p]
	default:
		return "", fmt.Errorf("binmgr: unknown engine %q", e)
	}
	if !ok {
		return "", fmt.Errorf("binmgr: upstream publishes no %s %s build for %s", e, ver, p)
	}
	return name, nil
}

// assetForPin is assetFor for an arbitrary version and digest source. The
// refusal below is the one thing an operator pin must never be able to route
// around, so it lives here rather than in the compiled-only wrapper.
func assetForPin(e Engine, p platform, ver string, digest func(string) (string, bool)) (string, error) {
	name, err := assetNameFor(e, p, ver)
	if err != nil {
		return "", err
	}
	// Refuse before downloading rather than after. verifyPinned would catch an
	// unpinned asset anyway, but only once ~20MB had already been fetched, and
	// its message ("no pinned checksum for X") reads like tampering when the real
	// cause is that this build of ForgePanel never pinned that platform.
	if _, pinned := digest(name); !pinned {
		return "", fmt.Errorf("binmgr: %s has no pinned checksum in this build of ForgePanel — "+
			"refusing to download a %s core for %s that it cannot verify", name, e, p)
	}
	return name, nil
}

// HostAssetName is the release file this host would download for e at ver. The
// pin API serves it so an operator is told the exact filename to hash instead of
// guessing at the platform naming of three different upstream projects.
func HostAssetName(e Engine, ver string) (string, error) {
	if ver == "" {
		ver = versionFor(e)
	}
	return assetNameFor(e, hostPlatform(), ver)
}

// ValidatePins reports whether every pin could actually be installed ON THIS
// HOST: upstream must publish a build for this platform, and the operator must
// have supplied the digest for it.
//
// Separate from SetPins so the API can refuse a bad pin BEFORE it writes any
// rows. Persisting a selection that the manager will then reject leaves the
// database claiming a version the panel is not running, which is the exact lie
// this feature exists to stop telling.
func ValidatePins(pins map[Engine]Pin) error {
	for e, p := range pins {
		if p.Version == "" {
			return fmt.Errorf("binmgr: %s pin has no version", e)
		}
		digest := func(asset string) (string, bool) {
			want, ok := p.SHA256[asset]
			return want, ok
		}
		if _, err := assetForPin(e, hostPlatform(), p.Version, digest); err != nil {
			return err
		}
	}
	return nil
}

// SetPins replaces the operator's version selection wholesale.
//
// It REFUSES a pin with no digest for the asset this host would download, so an
// unverifiable version can never reach finalizeInstall. The map is replaced
// rather than mutated because a reload goroutine may be inside Path or Ensure
// reading the old one.
func (m *Manager) SetPins(pins map[Engine]Pin) error {
	if err := ValidatePins(pins); err != nil {
		return err
	}
	next := make(map[Engine]Pin, len(pins))
	for e, p := range pins {
		sums := make(map[string]string, len(p.SHA256))
		for k, v := range p.SHA256 {
			sums[k] = v
		}
		next[e] = Pin{Version: p.Version, SHA256: sums}
	}
	m.mu.Lock()
	m.Pins = next
	m.mu.Unlock()
	return nil
}

// InstalledVersions lists the versions of e already present under BinDir, sorted
// so the list is stable between calls.
//
// This is what makes rollback free: Path keys the cache directory by version, so
// the version an operator moved off is still there and Ensure returns it with no
// download at all.
func (m *Manager) InstalledVersions(e Engine) []string {
	entries, err := os.ReadDir(m.BinDir)
	if err != nil {
		return nil
	}
	prefix := string(e) + "-"
	bin := binaryName(e, runtime.GOOS)
	var out []string
	for _, ent := range entries {
		if !ent.IsDir() || !strings.HasPrefix(ent.Name(), prefix) {
			continue
		}
		fi, err := os.Stat(filepath.Join(m.BinDir, ent.Name(), bin))
		if err != nil || fi.Mode()&0o111 == 0 {
			continue
		}
		out = append(out, strings.TrimPrefix(ent.Name(), prefix))
	}
	sort.Strings(out)
	return out
}

func download(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func extractZipFile(data []byte, want, dst string) error {
	zr, err := zip.NewReader(bytesReaderAt(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeExec(dst, rc)
	}
	return fmt.Errorf("binmgr: %q not found in zip", want)
}

func extractTarGzFile(data []byte, want, dst string) error {
	gz, err := gzip.NewReader(bytesReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == want && hdr.Typeflag == tar.TypeReg {
			return writeExec(dst, tr)
		}
	}
	return fmt.Errorf("binmgr: %q not found in tar.gz", want)
}

func writeExec(dst string, r io.Reader) error {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// verifyVersion runs "<bin> version" and checks the output contains want. This
// is a post-extraction integrity/identity check (spec §6).
func verifyVersion(bin, want string) error {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		// sing-box uses "version"; xray uses "version" too, but be lenient.
		out2, err2 := exec.Command(bin, "-version").CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("binmgr: cannot run %s: %v", bin, err)
		}
		out = out2
	}
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("binmgr: %s version check failed; wanted %q, got %q", bin, want, firstLine(string(out)))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// installBrook downloads the raw brook binary (a single ELF, not an archive).
func (m *Manager) installBrook(dst string) error {
	ver, dg := m.version(EngineBrook), m.digestFn()
	asset, err := assetForPin(EngineBrook, hostPlatform(), ver, dg)
	if err != nil {
		return err
	}
	url := "https://github.com/txthinking/brook/releases/download/" + ver + "/" + asset
	raw, err := download(url)
	if err != nil {
		return fmt.Errorf("download brook: %w", err)
	}
	// brook's self-report carries no version, so unlike the other two there is
	// nothing here to thread the pinned version into.
	return finalizeInstall(dst, asset, raw,
		func(tmp string) error { return writeExec(tmp, bytesReader(raw)) },
		"Brook version", dg)
}
