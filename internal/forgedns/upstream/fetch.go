package upstream

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// This file implements §4a "Fetch / install each binary". It deliberately does
// NOT curl-pipe the upstream `server_linux_install.sh`: those installers create
// their own systemd unit and own the process, which would fight the panel's
// supervisor. The panel resolves the release itself, verifies the SHA-256 from
// the published SHA256SUMS.txt, and keeps the binary in its own cache.
//
// It also does not live in internal/core/binmgr: binmgr pins exactly one
// version per engine as a compile-time constant, whereas these releases are
// datestamped tags resolved at runtime and pinned per zone in panel state, so
// the cache key is <adapter>/<tag> rather than <engine>-<const>.

// httpClient bounds download time so a zone sync can never hang forever.
var httpClient = netegress.Client(5 * time.Minute)

// maxArchiveBytes caps what the installer will read from a release asset. The
// verified server archives are 1.7–4 MB (§0); 64 MB is a generous ceiling that
// still refuses a hostile or truncated-to-garbage response.
const maxArchiveBytes = 64 << 20

// Install is a resolved, verified, extracted upstream server build.
type Install struct {
	Adapter   string    `json:"adapter"`
	Tag       string    `json:"tag"`
	Dir       string    `json:"dir"`
	Exe       string    `json:"exe"`
	Asset     string    `json:"asset"`
	SHA256    string    `json:"sha256"`
	Installed time.Time `json:"installed_at"`
}

// Installer downloads and caches upstream server builds under
// <dataDir>/bin/forgedns/<adapter>/<tag>/.
type Installer struct {
	Root string

	mu   sync.Mutex
	seen map[string]*Install // adapter+tag -> install (in-process memo)
}

// NewInstaller roots an installer at <dataDir>/bin/forgedns.
func NewInstaller(dataDir string) *Installer {
	return &Installer{Root: filepath.Join(dataDir, "bin", "forgedns"), seen: map[string]*Install{}}
}

// dir is the cache directory for one adapter+tag.
func (i *Installer) dir(d Descriptor, tag string) string {
	return filepath.Join(i.Root, d.Adapter, tag)
}

// LatestTag resolves the newest release tag via the GitHub API (§4a step 1).
// The caller pins the returned tag in panel state so an upgrade is an explicit
// action, never a silent side effect of a restart.
func (i *Installer) LatestTag(d Descriptor) (string, error) {
	req, err := http.NewRequest(http.MethodGet, d.LatestReleaseAPI(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ForgePanel-ForgeDNS")
	// An optional token only raises the anonymous rate limit; none is required.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("forgedns: resolve %s latest release: %w", d.Repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("forgedns: resolve %s latest release: status %d", d.Repo, resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", fmt.Errorf("forgedns: decode %s release: %w", d.Repo, err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("forgedns: %s latest release has no tag_name", d.Repo)
	}
	return rel.TagName, nil
}

// Lookup returns an already-installed build without touching the network.
func (i *Installer) Lookup(d Descriptor, tag string) (*Install, bool) {
	if tag == "" {
		return nil, false
	}
	i.mu.Lock()
	if in, ok := i.seen[d.Adapter+"@"+tag]; ok {
		i.mu.Unlock()
		return in, true
	}
	i.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(i.dir(d, tag), "install.json"))
	if err != nil {
		return nil, false
	}
	var in Install
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, false
	}
	if fi, err := os.Stat(in.Exe); err != nil || fi.Mode()&0o111 == 0 {
		return nil, false
	}
	i.mu.Lock()
	i.seen[d.Adapter+"@"+tag] = &in
	i.mu.Unlock()
	return &in, true
}

// Ensure makes the server binary for (adapter, tag) available and returns it.
// An empty tag resolves the latest release. This is the only place that touches
// the network, so tests exercise the renderer and descriptors without it.
func (i *Installer) Ensure(d Descriptor, tag string) (*Install, error) {
	if in, ok := i.Lookup(d, tag); ok {
		return in, nil
	}
	if tag == "" {
		latest, err := i.LatestTag(d)
		if err != nil {
			return nil, err
		}
		tag = latest
		if in, ok := i.Lookup(d, tag); ok {
			return in, nil
		}
	}
	arch, err := HostArch()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("forgedns: upstream server builds are Linux-only (host is %s)", runtime.GOOS)
	}

	asset := d.ServerAsset(arch) + ".tar.gz"
	archive, err := get(d.AssetURL(tag, asset))
	if err != nil {
		return nil, fmt.Errorf("forgedns: download %s: %w", asset, err)
	}
	sum := sha256.Sum256(archive)
	got := hex.EncodeToString(sum[:])

	// §4a step 2: verify against the SHA256SUMS.txt published beside the asset.
	sums, err := get(d.AssetURL(tag, "SHA256SUMS.txt"))
	if err != nil {
		return nil, fmt.Errorf("forgedns: %s %s has no SHA256SUMS.txt to verify against: %w", d.Repo, tag, err)
	}
	want, ok := lookupSum(string(sums), asset)
	if !ok {
		return nil, fmt.Errorf("forgedns: %s not listed in %s SHA256SUMS.txt", asset, tag)
	}
	if !strings.EqualFold(want, got) {
		return nil, fmt.Errorf("forgedns: SHA-256 mismatch for %s (want %s, got %s)", asset, want, got)
	}

	dir := i.dir(d, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	exe, err := extractTarGz(archive, dir, d.ExeGlobPrefix(arch))
	if err != nil {
		return nil, fmt.Errorf("forgedns: extract %s: %w", asset, err)
	}

	in := &Install{
		Adapter: d.Adapter, Tag: tag, Dir: dir, Exe: exe, Asset: asset,
		SHA256: got, Installed: time.Now().UTC(),
	}
	if raw, err := json.MarshalIndent(in, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "install.json"), raw, 0o644)
	}
	i.mu.Lock()
	i.seen[d.Adapter+"@"+tag] = in
	i.mu.Unlock()
	return in, nil
}

// get fetches a release file with a bounded body.
func get(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ForgePanel-ForgeDNS")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxArchiveBytes))
}

// lookupSum finds a filename's digest in a "sha256sum"-format listing
// ("<hex>  <name>"). Names may be bare or path-prefixed.
func lookupSum(listing, file string) (string, bool) {
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 {
			continue
		}
		name := strings.TrimPrefix(f[len(f)-1], "*")
		if filepath.Base(name) == file {
			return f[0], true
		}
	}
	return "", false
}

// extractTarGz unpacks an archive into dir and returns the absolute path of the
// executable whose basename starts with exePrefix, chmod'ed +x. The exe name
// carries the release tag, so it is matched by prefix rather than exact name
// (§4a step 3). Entries escaping dir are refused (tar-slip).
func extractTarGz(data []byte, dir, exePrefix string) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	exe := ""
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		name := filepath.Base(hdr.Name)
		if name == "" || name == "." || name == ".." || strings.Contains(hdr.Name, "..") {
			continue // refuse traversal; the archives are flat anyway
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join(dir, name)
		mode := os.FileMode(0o644)
		isExe := strings.HasPrefix(name, exePrefix)
		if isExe {
			mode = 0o755
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, maxArchiveBytes)); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		if isExe {
			_ = os.Chmod(dst, 0o755)
			exe = dst
		}
	}
	if exe == "" {
		return "", fmt.Errorf("no %s* executable in archive", exePrefix)
	}
	return exe, nil
}
