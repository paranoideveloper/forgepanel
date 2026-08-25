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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// Manager resolves and caches core binaries under BinDir.
type Manager struct {
	BinDir string
}

// New returns a Manager rooted at dataDir/bin.
func New(dataDir string) *Manager { return &Manager{BinDir: filepath.Join(dataDir, "bin")} }

// Path returns the on-disk path a resolved engine binary would have (whether or
// not it is present yet).
func (m *Manager) Path(e Engine) string {
	ver := versionFor(e)
	name := "xray"
	switch e {
	case EngineSingbox:
		name = "sing-box"
	case EngineBrook:
		name = "brook"
	}
	return filepath.Join(m.BinDir, string(e)+"-"+ver, name)
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
		if adopted, err := adoptForgePanelSingbox(p, runtime.GOARCH); err != nil {
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
	"Xray-linux-64.zip":                   "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
	"Xray-linux-arm64-v8a.zip":            "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
	"sing-box-1.13.15-linux-amd64.tar.gz": "a3a3ff223b23c3f4731d0a17cb0ef94c97ce257c70721a5b07dc7ca079203c9f",
	// The sing-box ForgePanel builds and ships (scripts/build-singbox.sh): the
	// same upstream version, the official tag set plus with_v2ray_api, built
	// reproducibly. These are NOT the upstream archives above and must never
	// share an entry with them — they are different artifacts.
	//
	// Reproduce with:  TARGETS="amd64 arm64" scripts/build-singbox.sh
	// and compare; two independent builds are byte-identical.
	"sing-box-1.13.15-linux-amd64":        "bb4d1b057836e2d955020b4be6c8084023cb6c91f330b50e485e6b8b02dc7563",
	"sing-box-1.13.15-linux-arm64":        "f163bae1ac31e80fed67a9e51463ef943ed4a13ffba35db591546220073eab0a",
	"sing-box-1.13.15-linux-arm64.tar.gz": "f0810bbb5722ae36635687c421019defcc8b328d31a0b3c287901f331747ca93",
	"brook_linux_amd64":                   "7853250042877716376fab14a3a99be44bf242cd69dec11cfa71fada915db372",
	"brook_linux_arm64":                   "5c720698f811ecc265311574140c20d912037ca36aecccd7e8536d03e581a2db",
}

// verifyPinned enforces the mandatory checksum: it fails if the artifact has no
// pinned entry (unknown filename) or if the SHA-256 does not match.
func verifyPinned(asset string, data []byte) error {
	want, ok := pinnedSHA256[asset]
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
func finalizeInstall(dst, asset string, data []byte, extract func(tmp string) error, wantVersion string) error {
	if err := verifyPinned(asset, data); err != nil {
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

// installXray downloads Xray-<os>-<arch>.zip, verifies its pinned SHA-256, and
// atomically installs the "xray" binary.
func (m *Manager) installXray(dst string) error {
	asset, err := xrayAsset()
	if err != nil {
		return err
	}
	base := "https://github.com/XTLS/Xray-core/releases/download/" + XrayVersion + "/"
	zipBytes, err := download(base + asset)
	if err != nil {
		return fmt.Errorf("download xray: %w", err)
	}
	if err := finalizeInstall(dst, asset, zipBytes,
		func(tmp string) error { return extractZipFile(zipBytes, "xray", tmp) },
		"Xray "+strings.TrimPrefix(XrayVersion, "v")); err != nil {
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
	asset := fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", SingboxVersion, goarchToSB())
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", SingboxVersion, asset)
	tgz, err := download(url)
	if err != nil {
		return fmt.Errorf("download sing-box: %w", err)
	}
	return finalizeInstall(dst, asset, tgz,
		func(tmp string) error { return extractTarGzFile(tgz, "sing-box", tmp) },
		"sing-box version "+SingboxVersion)
}

func xrayAsset() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	default:
		return "", fmt.Errorf("binmgr: unsupported arch %q", runtime.GOARCH)
	}
}

func goarchToSB() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
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
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	url := "https://github.com/txthinking/brook/releases/download/" + BrookVersion + "/brook_linux_" + arch
	raw, err := download(url)
	if err != nil {
		return fmt.Errorf("download brook: %w", err)
	}
	return finalizeInstall(dst, "brook_linux_"+arch, raw,
		func(tmp string) error { return writeExec(tmp, bytesReader(raw)) },
		"Brook version")
}
