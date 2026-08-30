package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/netegress"
)

// downloadTimeout matches internal/core/binmgr's: a release binary over a
// filtered link is slow, and a boot-time timeout would fail it every time.
const downloadTimeout = 5 * time.Minute

// maxBinary caps the download. The panel binary is tens of megabytes; anything
// approaching this is not the artifact we asked for.
const maxBinary = 256 << 20

// checksumsAsset is GoReleaser's checksum file name (.goreleaser.yaml's
// checksum.name_template), and assetName is its artifact name_template
// "{{ .Binary }}-{{ .Os }}-{{ .Arch }}" resolved for this host.
const checksumsAsset = "checksums.txt"

func assetName() string { return "forgepanel-linux-" + runtime.GOARCH }

// Staged records a candidate binary that has been downloaded, checksum-verified
// and proved to RUN on this host, ready for the installer to move into place.
type Staged struct {
	Path        string `json:"path"`
	Tag         string `json:"tag"`
	SHA256      string `json:"sha256"`
	SmokeOutput string `json:"smoke_output"`
	StagedAt    string `json:"staged_at"`
}

// Stage downloads rel's binary for this architecture, verifies it against the
// release's own checksums.txt, writes it under <dataDir>/updates/<tag>/ and
// runs it once with --version to prove it executes here.
//
// The smoke test is the part that earns the whole step: a checksum proves the
// bytes arrived intact, and says nothing about whether the binary's libc, its
// architecture or this host's seccomp policy will let it start. Finding that
// out AFTER swapping the live binary is the failure mode this exists to remove.
//
// Nothing that fails any of these checks is left on disk: a rejected binary
// sitting executable under the data dir is exactly what a later apply step
// would pick up.
func Stage(ctx context.Context, dataDir string, rel *Release) (*Staged, error) {
	if rel == nil || rel.Tag == "" {
		return nil, apierr.Validation("update-stage", "no release to stage", "run the update check first.")
	}
	want := assetName()
	binURL, err := assetURL(rel, want)
	if err != nil {
		return nil, err
	}
	sumURL, err := assetURL(rel, checksumsAsset)
	if err != nil {
		return nil, err
	}

	client := netegress.Client(downloadTimeout)
	body, err := get(ctx, binURL, client, maxBinary)
	if err != nil {
		return nil, restage(err)
	}
	sums, err := get(ctx, sumURL, client, 1<<20)
	if err != nil {
		return nil, restage(err)
	}

	expected, err := checksumFor(sums, want)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != expected {
		return nil, apierr.Validation("update-stage",
			fmt.Sprintf("%s checksum mismatch: the download hashes to %s, the release says %s", want, got, expected),
			"the download was truncated or tampered with; try again, and if it repeats do not install this release.")
	}

	dir := filepath.Join(dataDir, "updates", rel.Tag)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, apierr.Server("update-stage", err)
	}
	path := filepath.Join(dir, "forgepanel")
	if err := writeExec(path, body); err != nil {
		os.RemoveAll(dir)
		return nil, apierr.Server("update-stage", err)
	}

	out, runErr := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	smoke := strings.TrimSpace(string(out))
	if runErr != nil {
		os.RemoveAll(dir)
		return nil, apierr.Validation("update-stage",
			fmt.Sprintf("the staged %s binary would not run on this host: %v (%s)", rel.Tag, runErr, truncate(smoke, 200)),
			"this release may be built for a different architecture or libc than this host provides.")
	}
	// install.sh applies the same test to the binary it just installed, against
	// the raw tag. Matching it here means a mismatch is caught before anything
	// is swapped rather than during the rollback window.
	if !strings.Contains(smoke, rel.Tag) {
		os.RemoveAll(dir)
		return nil, apierr.Validation("update-stage",
			fmt.Sprintf("the staged binary reports %q, which does not contain %s", truncate(smoke, 200), rel.Tag),
			"the release asset does not identify itself as the release it is attached to; do not install it.")
	}

	st := &Staged{Path: path, Tag: rel.Tag, SHA256: got, SmokeOutput: smoke,
		StagedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := writeRecord(dataDir, st); err != nil {
		os.RemoveAll(dir)
		return nil, apierr.Server("update-stage", err)
	}
	return st, nil
}

// StagedRecord reads back what Stage last recorded, or nil when nothing is
// staged. A missing file is the normal state, not an error.
func StagedRecord(dataDir string) (*Staged, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "updates", "staged.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st Staged
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func assetURL(rel *Release, name string) (string, error) {
	for _, a := range rel.Assets {
		if a.Name == name && a.URL != "" {
			return a.URL, nil
		}
	}
	return "", apierr.Validation("update-stage",
		fmt.Sprintf("release %s has no %s asset", rel.Tag, name),
		"this release has no build for "+runtime.GOARCH+"/linux; update with the installer instead.")
}

// checksumFor pulls one artifact's SHA-256 out of a checksums.txt, in the same
// shape cmd/forgectl/local.go's installerChecksum parses it.
func checksumFor(checksums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		if len(fields[0]) != 64 || !isHex(fields[0]) {
			return "", apierr.Validation("update-stage",
				"the checksum listed for "+name+" is not a SHA-256",
				"the release's checksums.txt is malformed; do not install this release.")
		}
		return strings.ToLower(fields[0]), nil
	}
	return "", apierr.Validation("update-stage",
		"the release's checksums.txt does not list "+name,
		"an artifact with no published checksum cannot be verified and will not be installed.")
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// writeExec writes then renames, so a download interrupted halfway never leaves
// a short binary at the path something else is about to run.
func writeExec(dst string, body []byte) error {
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeRecord(dataDir string, st *Staged) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, "updates", "staged.json"), raw, 0o600)
}

// restage relabels a download failure, whose op still says "update-check"
// because it came through the shared getter.
func restage(err error) error {
	if e, ok := apierr.As(err); ok && e != nil {
		e.Op = "update-stage"
	}
	return err
}
