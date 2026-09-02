package api

// Backup from the panel, not only from a terminal.
//
// The crypto has always been real — AES-256-GCM under a key derived from the
// master secret — and it was reachable only from `forgectl`. An operator who
// never opens a shell therefore had no backups at all, which is the case where
// losing the database costs the most.
//
// RESTORE IS DELIBERATELY NOT HERE. Restoring overwrites the SQLite file the
// running panel holds open; doing that in-process corrupts it. The CLI stops the
// service first, which an HTTP handler cannot honestly do to itself. So the panel
// offers the two things it CAN do safely — take a backup, and verify one — and
// names the exact command for the third rather than shipping a footgun.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/version"
)

func (s *Server) masterKey() string {
	if s.cfg == nil {
		return ""
	}
	return s.cfg.MasterKey
}

// handleCreateBackup streams an encrypted backup as a download.
func (s *Server) handleCreateBackup(c *gin.Context) {
	master := s.masterKey()
	if master == "" {
		fail(c, 500, "this data directory has no master key, so nothing can be encrypted")
		return
	}
	files := backup.PanelFiles(s.cfg.DataDir)
	blob, err := backup.CreateWithManifest(master, s.cfg.DataDir, files, s.backupManifest())
	if err != nil {
		failErr(c, 500, err)
		return
	}
	name := fmt.Sprintf("forgepanel-%s.fpbk", time.Now().UTC().Format("20060102-150405"))
	s.audit(c, "backup.create", name)
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Data(200, "application/octet-stream", blob)
}

// handleVerifyBackup decrypts an uploaded backup and reports its contents
// WITHOUT writing anything.
//
// Backups nobody verified are the ones that turn out to be empty, truncated, or
// encrypted under a key that no longer exists — discovered at the worst possible
// moment. This makes checking cheap enough to actually do.
func (s *Server) handleVerifyBackup(c *gin.Context) {
	master := s.masterKey()
	if master == "" {
		fail(c, 500, "this data directory has no master key")
		return
	}
	file, err := c.FormFile("backup")
	if err != nil {
		fail(c, 400, "attach the backup as the form field 'backup'")
		return
	}
	// A backup is a few MB; a much larger upload is not one, and reading it
	// would be a memory exhaustion the panel does not need to accept.
	const maxUpload = 256 << 20
	if file.Size > maxUpload {
		fail(c, http.StatusRequestEntityTooLarge,
			"that file is larger than any panel backup; refusing to read it")
		return
	}
	f, err := file.Open()
	if err != nil {
		failErr(c, 400, err)
		return
	}
	defer f.Close()
	blob := make([]byte, file.Size)
	if _, err := io.ReadFull(f, blob); err != nil {
		fail(c, 400, "could not read the upload: "+err.Error())
		return
	}

	names, err := backup.Inspect(master, blob)
	if err != nil {
		// The most common cause by far, and the least obvious.
		apierr.Fail(c, &apierr.Error{Op: "backup-restore", Kind: apierr.KindValidation,
			Message: "this backup could not be opened: " + err.Error() +
				". The usual cause is that it was taken on a different panel, whose master key this one does not have.",
			Cause:   err,
			Details: map[string]any{"ok": false}})
		return
	}
	s.audit(c, "backup.verify", fmt.Sprintf("%s (%d files)", file.Filename, len(names)))
	out := gin.H{
		"ok":    true,
		"files": names,
		"note": "This backup opens with this panel's master key and contains the files listed. " +
			"To restore it, stop the panel and run: forgectl backup restore <file> — " +
			"restoring into a running panel would corrupt the database it currently holds open.",
	}
	// Verifying is exactly when an operator wants to know whether this backup
	// can be restored HERE, not only whether it decrypts. A backup from a newer
	// panel decrypts perfectly and would still ruin the database.
	if m, mErr := backup.ReadManifest(master, blob); mErr == nil && m != nil {
		out["manifest"] = m
		if err := backup.CheckRestorable(m, store.LatestSchemaVersion()); err != nil {
			out["restorable"] = false
			out["restore_error"] = err.Error()
		} else {
			out["restorable"] = true
		}
	} else {
		// A pre-manifest backup. Say so rather than leaving the field absent and
		// letting a UI read "not restorable" into a missing key.
		out["manifest"] = nil
		out["restorable"] = true
		out["manifest_note"] = "this backup predates backup manifests, so its schema version is unknown; " +
			"it is from an older panel by definition, which is the safe direction to restore from"
	}
	c.JSON(200, out)
}

// handleBackupStatus reports what the scheduled backups are doing.
func (s *Server) handleBackupStatus(c *gin.Context) {
	dir := ""
	if s.cfg != nil {
		dir = s.cfg.DataDir
	}
	last, count, err := backup.LatestLocal(dir)
	out := gin.H{"directory": backup.LocalDir(dir), "count": count}
	if err != nil {
		out["error"] = err.Error()
	}
	if !last.IsZero() {
		out["last_backup"] = last
		out["age_hours"] = int(time.Since(last).Hours())
	}
	out["has_master_key"] = strings.TrimSpace(s.masterKey()) != ""
	c.JSON(200, out)
}

// backupManifest describes the database this panel is backing up.
//
// Best-effort in every field: a backup must never fail because the schema
// version could not be read, and a manifest with a zero schema version still
// carries the panel version and the file count.
func (s *Server) backupManifest() backup.Manifest {
	m := backup.Manifest{CreatedAt: time.Now().UTC(), PanelVersion: version.Version}
	if s.db != nil {
		if v, err := s.db.SchemaVersion(); err == nil {
			m.SchemaVersion = v
		}
	}
	return m
}
