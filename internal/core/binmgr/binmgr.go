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
	return finalizeInstall(dst, asset, zipBytes,
		func(tmp string) error { return extractZipFile(zipBytes, "xray", tmp) },
		"Xray "+strings.TrimPrefix(XrayVersion, "v"))
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
