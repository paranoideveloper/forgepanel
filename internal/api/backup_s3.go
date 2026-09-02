package api

// Off-box backups to an S3-compatible bucket.
//
// The panel took a backup every day and left it in a directory on the machine
// it had just backed up. That covers a bad migration and a fat-fingered delete
// and nothing else: the disk dying, the VPS being wiped, or the provider
// account going away takes the panel and every backup of it at the same moment.
// Telegram delivery existed, but a chat history is not a place an operator can
// keep months of a fleet's state, and plenty of the people running this cannot
// reach Telegram at all.
//
// The credentials are panel-level secrets: the bucket holds the database, the
// master key and every certificate. They live behind /api/admin/settings, which
// the authz table already resolves to owner-only.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/settings"
)

const (
	settingS3Enabled   = "backup_s3_enabled"
	settingS3Endpoint  = "backup_s3_endpoint"
	settingS3Region    = "backup_s3_region"
	settingS3Bucket    = "backup_s3_bucket"
	settingS3Prefix    = "backup_s3_prefix"
	settingS3AccessKey = "backup_s3_access_key"
	settingS3SecretKey = "backup_s3_secret_key"
	settingS3PathStyle = "backup_s3_path_style"
)

func (s *Server) backupS3Enabled() bool { return s.knobs().Bool(settingS3Enabled) }

// resolveBackupS3 reads the destination the uploader will actually use, so a
// handler and the scheduler cannot disagree about what is configured.
func (s *Server) resolveBackupS3() backup.S3Config {
	k := s.knobs()
	return backup.S3Config{
		Endpoint:  k.String(settingS3Endpoint),
		Region:    k.String(settingS3Region),
		Bucket:    k.String(settingS3Bucket),
		Prefix:    k.String(settingS3Prefix),
		AccessKey: k.String(settingS3AccessKey),
		SecretKey: k.String(settingS3SecretKey),
		PathStyle: k.Bool(settingS3PathStyle),
	}
}

// deliverBackup is the fan-out the scheduler's single delivery hook calls.
//
// job.Config.DeliverBackup is ONE func value, copied into the scheduler at
// construction, so this is the only place a second destination can be attached
// at all. Neither destination can skip the other: they are separate failures and
// an operator who configured both is asking for two copies, not for whichever
// one happens to answer first.
func (s *Server) deliverBackup(path string) {
	s.deliverBackupToTelegram(path)
	s.deliverBackupToS3(path)
}

// deliverBackupToS3 uploads a written backup to the configured bucket.
//
// Errors go to the log and nowhere else, deliberately, for the same reason the
// Telegram delivery does it: this runs on the scheduler, the backup itself has
// already succeeded and is on disk, and failing the backup because a bucket
// refused an upload would trade a working local copy for no copy at all.
func (s *Server) deliverBackupToS3(path string) {
	if !s.backupS3Enabled() {
		return
	}
	cfg := s.resolveBackupS3()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: s3 backup delivery: %v\n", err)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: s3 backup delivery: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	name := filepath.Base(path)
	if err := backup.PutObject(ctx, cfg, cfg.Key(name), data, s.backupObjectMeta()); err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: s3 backup delivery of %s: %v\n", name, err)
		return
	}
}

// backupObjectMeta is what travels OUTSIDE the ciphertext.
//
// The manifest is a tar member inside the encrypted blob, so an object sitting
// in a bucket cannot say which key opens it. After a master-key rotation that
// makes a dead backup look exactly like a live one, and the difference is found
// during a restore.
func (s *Server) backupObjectMeta() map[string]string {
	return map[string]string{"key-fingerprint": backup.KeyFingerprint(s.masterKey())}
}

// --- endpoints ------------------------------------------------------------

type backupS3View struct {
	Enabled      bool   `json:"enabled"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	AccessKey    string `json:"access_key"`
	HasSecretKey bool   `json:"has_secret_key"`
	PathStyle    bool   `json:"path_style"`
	Configured   bool   `json:"configured"`
	// KeyFingerprint is shown so an operator can tell which objects in the
	// bucket this panel can still decrypt. It names the key; it is not the key.
	KeyFingerprint string `json:"key_fingerprint"`
}

// handleGetBackupS3Settings reports the destination WITHOUT the secret key.
//
// The secret key is a bearer credential for a bucket holding the panel's whole
// state, so it is write-only from the panel's point of view — the same
// treatment the bot token and the webhook secrets get.
func (s *Server) handleGetBackupS3Settings(c *gin.Context) {
	cfg := s.resolveBackupS3()
	c.JSON(200, backupS3View{
		Enabled:        s.backupS3Enabled(),
		Endpoint:       cfg.Endpoint,
		Region:         cfg.Region,
		Bucket:         cfg.Bucket,
		Prefix:         cfg.Prefix,
		AccessKey:      cfg.AccessKey,
		HasSecretKey:   cfg.SecretKey != "",
		PathStyle:      cfg.PathStyle,
		Configured:     cfg.Validate() == nil,
		KeyFingerprint: backup.KeyFingerprint(s.masterKey()),
	})
}

type backupS3Request struct {
	Enabled   *bool   `json:"enabled"`
	Endpoint  *string `json:"endpoint"`
	Region    *string `json:"region"`
	Bucket    *string `json:"bucket"`
	Prefix    *string `json:"prefix"`
	AccessKey *string `json:"access_key"`
	// SecretKey is optional on update: omitted, blank or left at the sentinel
	// keeps the stored one, so saving a bucket name does not require re-typing
	// a credential the panel deliberately never showed back.
	SecretKey *string `json:"secret_key"`
	PathStyle *bool   `json:"path_style"`
}

// merge applies the supplied fields to the stored configuration.
func (r backupS3Request) merge(cur backup.S3Config) backup.S3Config {
	if r.Endpoint != nil {
		cur.Endpoint = strings.TrimSpace(*r.Endpoint)
	}
	if r.Region != nil {
		cur.Region = strings.TrimSpace(*r.Region)
	}
	if r.Bucket != nil {
		cur.Bucket = strings.TrimSpace(*r.Bucket)
	}
	if r.Prefix != nil {
		cur.Prefix = strings.TrimSpace(*r.Prefix)
	}
	if r.AccessKey != nil {
		cur.AccessKey = strings.TrimSpace(*r.AccessKey)
	}
	if r.SecretKey != nil && *r.SecretKey != redactionSentinel && strings.TrimSpace(*r.SecretKey) != "" {
		cur.SecretKey = strings.TrimSpace(*r.SecretKey)
	}
	if r.PathStyle != nil {
		cur.PathStyle = *r.PathStyle
	}
	return cur
}

func (s *Server) handleSetBackupS3Settings(c *gin.Context) {
	if s.db == nil {
		fail(c, 501, "no store")
		return
	}
	var req backupS3Request
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	cfg := req.merge(s.resolveBackupS3())
	enabled := s.backupS3Enabled()
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// Refuse to switch the destination ON while it cannot work. Stored broken
	// and enabled, it fails once a day on the scheduler where the only trace is
	// a log line nobody reads, and the settings card looks configured.
	if enabled {
		if err := cfg.Validate(); err != nil {
			apierr.Fail(c, &apierr.Error{Op: "backup-s3-settings", Kind: apierr.KindValidation,
				Message: err.Error(), Cause: err,
				Remediation: "Fill in the endpoint, bucket, access key and secret key, or leave uploads switched off."})
			return
		}
	}

	// One batch through the registry: a half-applied save would leave the panel
	// uploading to a new bucket with the old credentials, and there is no state
	// there that anybody chose.
	if err := s.knobs().SetAll(map[string]string{
		settingS3Enabled:   strconv.FormatBool(enabled),
		settingS3Endpoint:  cfg.Endpoint,
		settingS3Region:    cfg.Region,
		settingS3Bucket:    cfg.Bucket,
		settingS3Prefix:    cfg.Prefix,
		settingS3AccessKey: cfg.AccessKey,
		settingS3SecretKey: cfg.SecretKey,
		settingS3PathStyle: strconv.FormatBool(cfg.PathStyle),
	}); err != nil {
		var ve *settings.ValidationError
		if errors.As(err, &ve) {
			failFields(c, 400, ve.Error(), ve.Fields())
			return
		}
		failErr(c, 500, err)
		return
	}
	// The bucket, never the credential.
	s.audit(c, "settings.backup_s3.update", cfg.Bucket)
	s.handleGetBackupS3Settings(c)
}

// probeObjectName is what the connectivity check writes.
//
// It writes a REAL object with the real credentials, because a check that only
// validated the form would pass on a bucket that refuses every PutObject — and
// this endpoint exists precisely so an operator learns that here rather than
// from a restore.
const probeObjectName = "forgepanel-connectivity-probe"

func (s *Server) handleTestBackupS3(c *gin.Context) {
	var req backupS3Request
	_ = c.ShouldBindJSON(&req)
	cfg := req.merge(s.resolveBackupS3())
	if err := cfg.Validate(); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "backup-s3-test", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Remediation: "Fill in the endpoint, bucket, access key and secret key before testing."})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	body := []byte("forgepanel connectivity probe " + time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := backup.PutObject(ctx, cfg, cfg.Key(probeObjectName), body, s.backupObjectMeta()); err != nil {
		apierr.Fail(c, apierr.From(err))
		return
	}
	s.audit(c, "settings.backup_s3.test", cfg.Bucket)
	c.JSON(200, gin.H{"ok": true, "bucket": cfg.Bucket, "object": cfg.Key(probeObjectName)})
}
