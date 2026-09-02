// Package lifecycle records every host resource ForgePanel owns and provides
// conservative, manifest-backed cleanup. It intentionally never guesses an
// original system state: an overwritten file is restored only from a recorded
// backup, and a changed file is left in place for the operator to inspect.
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const ManifestSchemaVersion = 1

// DefaultManifestPath is intentionally outside the mutable data directory:
// default uninstall preserves data, but it must still retain ownership records
// for a later repair or explicit purge.
const DefaultManifestPath = "/etc/forgepanel/install-manifest.json"

type FileState struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	IsDir  bool   `json:"is_dir,omitempty"`
}

// Resource is one installer-owned host path. Installed records the exact file
// placed by ForgePanel; Original describes the backup, never a reconstructed
// guess. Created distinguishes a newly-created path from a replacement.
type Resource struct {
	Kind      string     `json:"kind"`
	Path      string     `json:"path"`
	Created   bool       `json:"created"`
	Installed FileState  `json:"installed"`
	Original  *FileState `json:"original,omitempty"`
	Backup    string     `json:"backup,omitempty"`
}

type Manifest struct {
	SchemaVersion    int        `json:"schema_version"`
	InstallMethod    string     `json:"install_method"`
	Version          string     `json:"version"`
	InstalledAt      time.Time  `json:"installed_at"`
	InstallerVersion string     `json:"installer_version"`
	DataDir          string     `json:"data_dir"`
	Resources        []Resource `json:"resources"`
	Firewall         []string   `json:"firewall,omitempty"`
	SystemChanges    []string   `json:"system_changes,omitempty"`
}

func NewManifest(method, version, dataDir string) *Manifest {
	return &Manifest{
		SchemaVersion: ManifestSchemaVersion,
		InstallMethod: method,
		Version:       version,
		InstalledAt:   time.Now().UTC(),
		DataDir:       filepath.Clean(dataDir),
	}
}

func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("lifecycle: parse manifest: %w", err)
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return nil, fmt.Errorf("lifecycle: unsupported manifest schema %d", m.SchemaVersion)
	}
	if m.DataDir == "" {
		return nil, errors.New("lifecycle: manifest has no data directory")
	}
	return &m, nil
}

// Save writes a manifest atomically with owner-only permissions.
func (m *Manifest) Save(path string) error {
	if m == nil {
		return errors.New("lifecycle: nil manifest")
	}
	if m.SchemaVersion == 0 {
		m.SchemaVersion = ManifestSchemaVersion
	}
	if m.InstalledAt.IsZero() {
		m.InstalledAt = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Inspect(path string) (FileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileState{Path: path}, err
	}
	state := FileState{Path: path, Mode: uint32(info.Mode().Perm()), IsDir: info.IsDir()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		state.UID, state.GID = int(sys.Uid), int(sys.Gid)
	}
	if info.Mode().IsRegular() {
		sum, err := checksum(path)
		if err != nil {
			return state, err
		}
		state.SHA256 = sum
	}
	return state, nil
}

func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AddResource captures the installed file after a successful install. backup is
// the preserved old file, if the installer overwrote one.
func (m *Manifest) AddResource(kind, path string, created bool, backup string) error {
	installed, err := Inspect(path)
	if err != nil {
		return fmt.Errorf("lifecycle: inspect installed %s: %w", path, err)
	}
	r := Resource{Kind: kind, Path: path, Created: created, Installed: installed}
	if backup != "" {
		original, err := Inspect(backup)
		if err != nil {
			return fmt.Errorf("lifecycle: inspect backup %s: %w", backup, err)
		}
		r.Original, r.Backup = &original, backup
	}
	for i := range m.Resources {
		if m.Resources[i].Path == path {
			m.Resources[i] = r
			return nil
		}
	}
	m.Resources = append(m.Resources, r)
	return nil
}

// AddOrUpdateResource retains the first install's ownership proof during an
// upgrade. In particular, a binary ForgePanel originally created must still be
// removed, rather than restored to the immediately preceding release; and a
// file ForgePanel originally replaced must still be restored to its pre-install
// backup, not to a previous ForgePanel version.
func (m *Manifest) AddOrUpdateResource(kind, path string, created bool, backup string) error {
	for _, previous := range m.Resources {
		if previous.Path != path {
			continue
		}
		created = previous.Created
		if previous.Original != nil && previous.Backup != "" {
			backup = previous.Backup
		} else {
			backup = ""
		}
		break
	}
	return m.AddResource(kind, path, created, backup)
}

type Action struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

type CleanupSummary struct {
	Actions    []Action `json:"actions"`
	Incomplete bool     `json:"incomplete"`
}

func (s *CleanupSummary) add(path, action, reason string) {
	s.Actions = append(s.Actions, Action{Path: path, Action: action, Reason: reason})
}

// CleanupFiles restores overwritten files and removes unchanged resources that
// the manifest proves ForgePanel created. Data is intentionally skipped unless
// purge is requested. Files changed after installation are never removed unless
// force is explicit, preserving operator modifications.
func (m *Manifest) CleanupFiles(purge, dryRun, force bool) (CleanupSummary, error) {
	var out CleanupSummary
	resources := append([]Resource(nil), m.Resources...)
	sort.SliceStable(resources, func(i, j int) bool { return len(resources[i].Path) > len(resources[j].Path) })
	for _, r := range resources {
		if samePath(r.Path, m.DataDir) && !purge {
			out.add(r.Path, "kept", "data is preserved by default")
			continue
		}
		state, err := Inspect(r.Path)
		if errors.Is(err, os.ErrNotExist) {
			out.add(r.Path, "absent", "already removed")
			continue
		}
		if err != nil {
			out.add(r.Path, "skipped", err.Error())
			out.Incomplete = true
			continue
		}
		unchanged := sameInstalled(state, r.Installed)
		if !unchanged && !force {
			out.add(r.Path, "kept", "changed since ForgePanel installed it")
			out.Incomplete = true
			continue
		}
		if r.Original != nil && r.Backup != "" {
			if _, err := os.Stat(r.Backup); err != nil {
				out.add(r.Path, "kept", "recorded original backup is unavailable")
				out.Incomplete = true
				continue
			}
			if dryRun {
				out.add(r.Path, "would_restore", r.Backup)
				continue
			}
			if err := restore(r.Backup, r.Path, *r.Original); err != nil {
				return out, err
			}
			out.add(r.Path, "restored", r.Backup)
			continue
		}
		if !r.Created {
			out.add(r.Path, "kept", "manifest cannot prove ForgePanel created it")
			out.Incomplete = true
			continue
		}
		if dryRun {
			out.add(r.Path, "would_remove", "manifest-owned")
			continue
		}
		if state.IsDir {
			if samePath(r.Path, m.DataDir) && purge {
				err = os.RemoveAll(r.Path)
			} else {
				err = os.Remove(r.Path)
			}
		} else {
			err = os.Remove(r.Path)
		}
		if err != nil {
			out.add(r.Path, "kept", err.Error())
			out.Incomplete = true
			continue
		}
		out.add(r.Path, "removed", "manifest-owned")
	}
	return out, nil
}

func sameInstalled(current, installed FileState) bool {
	if current.IsDir != installed.IsDir {
		return false
	}
	if current.IsDir {
		return true
	}
	return installed.SHA256 != "" && current.SHA256 == installed.SHA256
}

func samePath(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }

func restore(src, dst string, original FileState) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".forgepanel-restore"
	if err := os.WriteFile(tmp, data, os.FileMode(original.Mode)); err != nil {
		return err
	}
	if err := os.Chmod(tmp, os.FileMode(original.Mode)); err != nil {
		return err
	}
	if err := os.Chown(tmp, original.UID, original.GID); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return nil
}

// LegacyInventory deliberately records only well-known paths as unproven. A
// legacy uninstall can stop services and remove ForgePanel firewall ownership,
// but it will not delete files merely because their names look familiar.
func LegacyInventory(dataDir string) *Manifest {
	m := NewManifest("legacy", "unknown", dataDir)
	for kind, path := range map[string]string{
		"binary":   "/usr/local/bin/forgepanel",
		"cli":      "/usr/local/bin/forgectl",
		"node":     "/usr/local/bin/forgenode",
		"unit":     "/etc/systemd/system/forgepanel.service",
		"env":      "/etc/forgepanel/forgepanel.env",
		"config":   "/etc/forgepanel",
		"data_dir": dataDir,
	} {
		state, err := Inspect(path)
		if err == nil {
			m.Resources = append(m.Resources, Resource{Kind: kind, Path: path, Installed: state})
		}
	}
	return m
}

// IsManagedRule accepts only the exact, namespaced comments ForgePanel writes.
// It exists here so every removal path uses the same ownership predicate.
func IsManagedRule(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "forgepanel-porthop-")
}
