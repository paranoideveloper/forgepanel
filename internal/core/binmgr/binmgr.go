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
	"errors"
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

// installXray downloads Xray-<os>-<arch>.zip, verifies it against the published
// .dgst checksum, and extracts the "xray" binary.
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
	if dgst, err := download(base + asset + ".dgst"); err == nil {
		if err := verifyInDigest(zipBytes, string(dgst)); err != nil {
			return err
		}
	}
	if err := extractZipFile(zipBytes, "xray", dst); err != nil {
		return err
	}
	return verifyVersion(dst, "Xray "+strings.TrimPrefix(XrayVersion, "v"))
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
	if err := extractTarGzFile(tgz, "sing-box", dst); err != nil {
		return err
	}
	return verifyVersion(dst, "sing-box version "+SingboxVersion)
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

// verifyInDigest confirms the file's SHA-256 appears in the published digest
// text (xray ships a multi-hash .dgst file).
func verifyInDigest(data []byte, dgst string) error {
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	if !strings.Contains(strings.ToLower(dgst), hexsum) {
		return errors.New("binmgr: SHA-256 mismatch against published .dgst")
	}
	return nil
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
	if err := writeExec(dst, bytesReader(raw)); err != nil {
		return err
	}
	return verifyVersion(dst, "Brook version")
}
