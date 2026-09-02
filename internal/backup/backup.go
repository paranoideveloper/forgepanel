// Package backup implements encrypted backup and restore (spec §12): it packs the
// panel's SQLite database (and any extra files) into a tar, encrypts it with
// AES-256-GCM under a key derived from the panel master secret, and can restore
// it with one call. Destinations (local/S3/Telegram) layer on top of the raw
// Create/Restore bytes.
package backup

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// magic prefixes an encrypted backup so restore can sanity-check it.
var magic = []byte("FPBK1")

// deriveKey turns an arbitrary master secret into a 32-byte AES key.
func deriveKey(master string) []byte {
	sum := sha256.Sum256([]byte("forgepanel-backup:" + master))
	return sum[:]
}

// PanelFiles enumerates everything a backup must contain to restore a WORKING
// panel, not merely its data.
//
// The database alone is not enough. secrets.json holds the master key and the
// token signing secret, so a restore without it cannot decrypt its own next
// backup or validate an existing session. panel.json holds the address the panel
// serves on. And the ACME cache holds ISSUED CERTIFICATES: losing those means
// re-issuing, and Let's Encrypt rate limits mean a panel can be unable to get a
// certificate for days — the one failure a backup is supposed to prevent.
//
// The list was previously hardcoded to three files at the call site, so anything
// added to the data directory since was silently outside every backup.
func PanelFiles(dataDir string) []string {
	files := []string{
		filepath.Join(dataDir, "forgepanel.db"),
		filepath.Join(dataDir, "secrets.json"),
		filepath.Join(dataDir, "panel.json"),
	}
	// Certificates and the node CA live in directories, so they are walked
	// rather than named.
	//
	// nodeca holds the CA that SIGNS every node's client certificate. Losing it
	// does not lose a certificate that can be re-issued — it invalidates the
	// identity of every node at once, and the whole fleet has to be re-enrolled
	// by hand. It was outside every backup, which is a strange thing for a file
	// whose loss is less recoverable than the database's.
	for _, dir := range []string{"acme", "certs", "nodeca"} {
		root := filepath.Join(dataDir, dir)
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			// Regular files only: a symlink captured here would be restored as
			// a link pointing somewhere this panel does not control.
			if !info.Mode().IsRegular() {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	return files
}

// Create packs the named files into an encrypted blob.
//
// Paths are stored RELATIVE to root when they sit inside it, so a certificate at
// acme/live/panel.crt restores to the same place rather than being flattened
// into the data directory next to the database. A file outside root keeps its
// base name, which is what the old format did for everything.
//
// Missing files are skipped so a partial data dir still backs up cleanly.
func CreateFrom(master, root string, files []string) ([]byte, error) {
	return create(master, root, files, nil)
}

// CreateWithManifest is CreateFrom plus the self-description a restore needs to
// refuse an unsafe overwrite. Panel backups take this path; the manifest's
// Files count is filled in here so it cannot disagree with the blob.
func CreateWithManifest(master, root string, files []string, m Manifest) ([]byte, error) {
	return create(master, root, files, &m)
}

// Create is the flat-name form, kept for callers that have no root to relativise
// against.
func Create(master string, files []string) ([]byte, error) {
	return create(master, "", files, nil)
}

func create(master, root string, files []string, manifest *Manifest) ([]byte, error) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	included := 0
	// Expand files to include WAL and SHM sidecars for SQLite databases to ensure zero backup corruption
	var expanded []string
	for _, f := range files {
		expanded = append(expanded, f)
		if filepath.Ext(f) == ".db" {
			if _, err := os.Stat(f + "-wal"); err == nil {
				expanded = append(expanded, f+"-wal")
			}
			if _, err := os.Stat(f + "-shm"); err == nil {
				expanded = append(expanded, f+"-shm")
			}
		}
	}

	for _, f := range expanded {
		data, err := os.ReadFile(f)
		if err != nil {
			continue // skip absent files
		}
		name := filepath.Base(f)
		if root != "" {
			if rel, relErr := filepath.Rel(root, f); relErr == nil &&
				!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
				name = filepath.ToSlash(rel)
			}
		}
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
		included++
	}
	if included == 0 {
		// Checked BEFORE the manifest is written, so an empty backup cannot
		// become a one-member archive that looks like a successful one.
		_ = tw.Close()
		return nil, errors.New("backup: nothing to back up")
	}
	if manifest != nil {
		manifest.Format = ManifestFormat
		manifest.Files = included
		mb, err := json.Marshal(manifest)
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(mb))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(mb); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return encrypt(deriveKey(master), tarBuf.Bytes())
}

// Restore decrypts a blob and writes each contained file into destDir.
func Restore(master string, blob []byte, destDir string) ([]string, error) {
	plain, err := decrypt(deriveKey(master), blob)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	var restored []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		// A backup blob is untrusted input: it may have been supplied by whoever
		// is doing the restoring, and a tar entry named "../../etc/cron.d/x" or
		// a symlink would otherwise be an arbitrary file write as root.
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// The manifest describes the backup; it is not part of the data
		// directory and must not be written into it.
		if hdr.Name == ManifestName {
			continue
		}
		dst, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, err
		}
		restored = append(restored, dst)
	}
	return restored, nil
}

// RestoreChecked refuses to overwrite a live data directory with a backup from a
// panel whose schema is ahead of this build, then restores.
//
// Restore itself is left unguarded on purpose: it is the primitive, and a
// disaster-recovery path that cannot be forced is its own kind of failure. This
// is the one every caller with a running panel behind it should use.
func RestoreChecked(master string, blob []byte, destDir string, thisSchemaVersion uint64) ([]string, error) {
	m, err := ReadManifest(master, blob)
	if err != nil {
		return nil, err
	}
	if err := CheckRestorable(m, thisSchemaVersion); err != nil {
		return nil, err
	}
	return Restore(master, blob, destDir)
}

// safeJoin resolves a tar entry name inside destDir, refusing anything that
// tries to escape it.
//
// It REFUSES a traversing name rather than normalising it. Cleaning
// "../../etc/passwd" into "<dest>/etc/passwd" would be contained and therefore
// safe, but it silently restores a file to a path the operator never expected —
// and a legitimate ForgePanel backup never contains a parent reference at all,
// so the only way to see one is a blob that was tampered with or built
// elsewhere. That is worth stopping on, not quietly rewriting.
//
// The Rel check afterwards is the belt to those braces: containment must not
// depend on one string operation being right.
func safeJoin(destDir, name string) (string, error) {
	slashed := filepath.ToSlash(name)
	if slashed == ".." || strings.HasPrefix(slashed, "../") ||
		strings.Contains(slashed, "/../") || strings.HasSuffix(slashed, "/..") {
		return "", fmt.Errorf("backup: entry %q contains a parent reference; refusing to restore it", name)
	}
	if filepath.IsAbs(name) || strings.HasPrefix(slashed, "/") {
		return "", fmt.Errorf("backup: entry %q is an absolute path; refusing to restore it", name)
	}
	clean := strings.TrimPrefix(filepath.Clean("/"+filepath.FromSlash(name)), string(filepath.Separator))
	if clean == "" || clean == "." {
		return "", fmt.Errorf("backup: entry has no usable name")
	}
	dst := filepath.Join(destDir, clean)
	rel, err := filepath.Rel(destDir, dst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backup: entry %q escapes the destination directory", name)
	}
	return dst, nil
}

// Inspect decrypts a blob and reports what it contains WITHOUT writing anything.
//
// This is how an operator finds out whether a backup is restorable before they
// need it. Backups that were never verified are the ones that turn out to be
// empty, truncated or encrypted under a key nobody has any more — and that is
// discovered at the worst possible moment.
func Inspect(master string, blob []byte) ([]string, error) {
	plain, err := decrypt(deriveKey(master), blob)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			names = append(names, hdr.Name)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("backup: contains no files")
	}
	return names, nil
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, magic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, magic), nil
}

func decrypt(key, blob []byte) ([]byte, error) {
	if len(blob) < len(magic) || !bytes.Equal(blob[:len(magic)], magic) {
		return nil, errors.New("backup: not a ForgePanel backup (bad magic)")
	}
	blob = blob[len(magic):]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("backup: truncated")
	}
	nonce, ct := blob[:ns], blob[ns:]
	return gcm.Open(nil, nonce, ct, magic)
}

// --- scheduled local backups -----------------------------------------------
//
// A backup that only happens when someone remembers is not a backup policy. The
// panel writes one on a schedule and prunes old ones, so the failure mode is
// "the newest is a day old" rather than "there isn't one".

// LocalDir is where scheduled backups are written.
func LocalDir(dataDir string) string { return filepath.Join(dataDir, "backups") }

// WriteLocal takes a backup and stores it under LocalDir, returning its path.
func WriteLocal(master, dataDir string, now time.Time, m Manifest) (string, error) {
	if strings.TrimSpace(master) == "" {
		return "", errors.New("backup: no master key")
	}
	m.CreatedAt = now.UTC()
	blob, err := CreateWithManifest(master, dataDir, PanelFiles(dataDir), m)
	if err != nil {
		return "", err
	}
	dir := LocalDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "forgepanel-"+now.UTC().Format("20060102-150405")+".fpbk")
	// Write through a temp file: a reader (or the pruner) must never see a
	// half-written backup and count it as a good one.
	tmp := path + ".part"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// PruneLocal keeps the newest `keep` backups and removes the rest.
//
// keep <= 0 removes nothing: read as "keep zero" it would delete every backup,
// which is the exact opposite of what a retention setting is for.
func PruneLocal(dataDir string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	entries, err := backupFiles(dataDir)
	if err != nil || len(entries) <= keep {
		return 0, err
	}
	removed := 0
	for _, e := range entries[keep:] {
		if err := os.Remove(e.path); err == nil {
			removed++
		}
	}
	return removed, nil
}

// LatestLocal reports when the newest backup was taken and how many exist.
func LatestLocal(dataDir string) (time.Time, int, error) {
	entries, err := backupFiles(dataDir)
	if err != nil || len(entries) == 0 {
		return time.Time{}, len(entries), err
	}
	return entries[0].mod, len(entries), nil
}

type backupEntry struct {
	path string
	mod  time.Time
}

// backupFiles lists finished backups, newest first. Partial writes (.part) are
// excluded so an in-progress backup is never mistaken for a complete one.
func backupFiles(dataDir string) ([]backupEntry, error) {
	dir := LocalDir(dataDir)
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []backupEntry
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".fpbk") {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, backupEntry{path: filepath.Join(dir, de.Name()), mod: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	return out, nil
}
