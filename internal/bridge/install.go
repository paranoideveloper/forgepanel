package bridge

// Fetching a backend's binary, and refusing to run one that is not the binary
// we pinned.

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

	"github.com/forgepanel/forgepanel/internal/netegress"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxAssetBytes caps what the installer will read. The pinned assets are
// 1–14 MB; 128 MB refuses a hostile or garbage response without being a limit
// anyone legitimately hits.
const maxAssetBytes = 128 << 20

// Install is an extracted, digest-checked backend build.
type Install struct {
	Backend   string    `json:"backend"`
	Version   string    `json:"version"`
	Dir       string    `json:"dir"`
	Exe       string    `json:"exe"`
	PeerExe   string    `json:"peer_exe,omitempty"`
	SHA256    string    `json:"sha256"`
	Installed time.Time `json:"installed_at"`
}

// Installer caches backend builds under <dataDir>/bin/bridge/<backend>/<ver>/.
type Installer struct {
	Root string
	// HTTP is the client used for downloads; nil takes a 5-minute default.
	HTTP *http.Client

	mu   sync.Mutex
	seen map[string]*Install
}

// NewInstaller roots an installer at <dataDir>/bin/bridge.
func NewInstaller(dataDir string) *Installer {
	return &Installer{Root: filepath.Join(dataDir, "bin", "bridge"), seen: map[string]*Install{}}
}

func (i *Installer) httpClient() *http.Client {
	if i.HTTP != nil {
		return i.HTTP
	}
	return netegress.Client(5 * time.Minute)
}

func (i *Installer) dir(b Backend) string {
	return filepath.Join(i.Root, b.Name, b.PinnedVersion)
}

// ErrDigestMismatch means the downloaded asset is not the one that was pinned.
var ErrDigestMismatch = errors.New("bridge: the downloaded asset does not match its pinned checksum")

// Ensure returns an installed backend, downloading it on first use.
func (i *Installer) Ensure(b Backend) (*Install, error) {
	i.mu.Lock()
	if got, ok := i.seen[b.Name+b.PinnedVersion]; ok {
		i.mu.Unlock()
		return got, nil
	}
	i.mu.Unlock()

	dir := i.dir(b)
	exe := filepath.Join(dir, b.Exe)
	if st, err := os.Stat(exe); err == nil && st.Mode()&0o111 != 0 {
		got := &Install{Backend: b.Name, Version: b.PinnedVersion, Dir: dir, Exe: exe,
			SHA256: b.SHA256, Installed: st.ModTime()}
		if b.PeerExe != "" {
			got.PeerExe = filepath.Join(dir, b.PeerExe)
		}
		i.mu.Lock()
		i.seen[b.Name+b.PinnedVersion] = got
		i.mu.Unlock()
		return got, nil
	}

	raw, err := i.download(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != b.SHA256 {
		// Never fall back to running it anyway. This binary runs as root on a
		// machine the operator is probably not sitting at.
		return nil, fmt.Errorf("%w: %s %s is %s, expected %s",
			ErrDigestMismatch, b.Name, b.PinnedVersion, got, b.SHA256)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("bridge: create %s: %w", dir, err)
	}
	if err := extract(b, raw, dir); err != nil {
		return nil, err
	}
	if st, err := os.Stat(exe); err != nil || st.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("bridge: %s was extracted but %s is missing or not executable", b.Name, b.Exe)
	}
	got := &Install{Backend: b.Name, Version: b.PinnedVersion, Dir: dir, Exe: exe,
		SHA256: b.SHA256, Installed: time.Now().UTC()}
	if b.PeerExe != "" {
		got.PeerExe = filepath.Join(dir, b.PeerExe)
	}
	i.mu.Lock()
	i.seen[b.Name+b.PinnedVersion] = got
	i.mu.Unlock()
	return got, nil
}

func (i *Installer) download(b Backend) ([]byte, error) {
	resp, err := i.httpClient().Get(b.DownloadURL())
	if err != nil {
		return nil, fmt.Errorf("bridge: download %s: %w", b.DownloadURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bridge: %s returned HTTP %d — the pinned release or asset name may have changed",
			b.DownloadURL(), resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAssetBytes))
}

// extract unpacks the asset, keeping only the executables the backend declares.
//
// Only those: an archive is attacker-influenced input, and writing every entry
// it names is how a path-traversal entry ("../../etc/…") lands outside the
// install directory.
func extract(b Backend, raw []byte, dir string) error {
	wanted := map[string]bool{b.Exe: true}
	if b.PeerExe != "" {
		wanted[b.PeerExe] = true
	}
	if strings.HasSuffix(b.Asset(), ".zip") {
		return extractZip(raw, dir, wanted)
	}
	return extractTarGz(raw, dir, wanted)
}

func extractTarGz(raw []byte, dir string, wanted map[string]bool) error {
	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		return fmt.Errorf("bridge: the asset is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("bridge: reading the archive: %w", err)
		}
		name := filepath.Base(h.Name)
		if h.Typeflag != tar.TypeReg || !wanted[name] {
			continue
		}
		if err := writeExe(filepath.Join(dir, name), tr); err != nil {
			return err
		}
	}
}

func extractZip(raw []byte, dir string, wanted map[string]bool) error {
	zr, err := zip.NewReader(strings.NewReader(string(raw)), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("bridge: the asset is not a zip: %w", err)
	}
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if f.FileInfo().IsDir() || !wanted[name] {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("bridge: reading %s: %w", name, err)
		}
		err = writeExe(filepath.Join(dir, name), rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeExe(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("bridge: writing %s: %w", path, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(r, maxAssetBytes)); err != nil {
		return fmt.Errorf("bridge: writing %s: %w", path, err)
	}
	return nil
}
