package backup

// What a backup says about itself.
//
// A backup was a bag of files and nothing else, so a restore could not answer
// the one question that decides whether it is safe: is this database from a
// schema this binary understands? Restoring a NEWER database under an OLDER
// panel is the dangerous direction — the binary does not know the columns that
// were added, its own migration runner sees versions it has no entry for, and
// the first write puts the database into a state neither version can read. The
// operator finds out after the live database has already been overwritten.
//
// The manifest is a plain JSON member at the root of the tar. It is written
// first so a reader can stop at the first entry, and a blob without one is
// treated as a pre-manifest backup rather than as an error.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ManifestName is the tar member holding the manifest. The forgepanel- prefix
// keeps it from colliding with anything in the data directory, which is
// restored into the same namespace.
const ManifestName = "forgepanel-backup.json"

// ManifestFormat is the manifest's own version, separate from the panel's.
const ManifestFormat = 1

// Manifest describes the backup well enough to refuse an unsafe restore.
type Manifest struct {
	Format int `json:"format"`
	// CreatedAt is informational; it is never used to decide anything, because
	// a clock is not an ordering of schemas.
	CreatedAt time.Time `json:"created_at"`
	// PanelVersion is the build that wrote the backup, for the operator.
	PanelVersion string `json:"panel_version,omitempty"`
	// SchemaVersion is the highest migration recorded in the backed-up
	// database. This is the field that decides a restore: migration versions
	// are append-only and strictly ascending, so they compare meaningfully in a
	// way a build string does not.
	SchemaVersion uint64 `json:"schema_version"`
	// Files is the count of data files in the blob, so "restored 0 files"
	// cannot look like success.
	Files int `json:"files"`
}

// ErrNewerSchema reports a backup written by a panel whose database schema is
// ahead of this build.
type ErrNewerSchema struct {
	BackupVersion uint64
	ThisVersion   uint64
}

func (e *ErrNewerSchema) Error() string {
	return fmt.Sprintf(
		"this backup is from a newer panel: its database is at schema version %d and this build only knows up to %d. "+
			"Restoring it would put the database into a state this binary cannot migrate. Upgrade the panel first, then restore.",
		e.BackupVersion, e.ThisVersion)
}

// ReadManifest returns the manifest inside an encrypted blob.
//
// A blob with no manifest returns (nil, nil): backups written before manifests
// existed are still restorable, and treating them as corrupt would destroy the
// only copy some operator has.
func ReadManifest(master string, blob []byte) (*Manifest, error) {
	plain, err := decrypt(deriveKey(master), blob)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != ManifestName {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("backup: manifest is not readable: %w", err)
		}
		return &m, nil
	}
}

// CheckRestorable reports whether a blob may be restored under a panel whose
// own latest migration is thisSchemaVersion.
//
// Older or equal is fine: the migration runner brings an older database forward
// on the next start, which is the ordinary upgrade path. Newer is refused.
func CheckRestorable(m *Manifest, thisSchemaVersion uint64) error {
	if m == nil {
		// Pre-manifest backup. Unknown, and unknown is not the same as unsafe:
		// every backup written before this existed is from an OLDER panel by
		// definition, which is the safe direction.
		return nil
	}
	if m.SchemaVersion > thisSchemaVersion {
		return &ErrNewerSchema{BackupVersion: m.SchemaVersion, ThisVersion: thisSchemaVersion}
	}
	return nil
}
