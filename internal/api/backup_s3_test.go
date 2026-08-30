package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/forgepanel/forgepanel/internal/backup"
	"github.com/forgepanel/forgepanel/internal/netegress"
)

// recordingBucket stands in for an S3-compatible endpoint and keeps every
// request it was sent.
type recordingBucket struct {
	mu     sync.Mutex
	reqs   []*http.Request
	bodies [][]byte
	status int
}

func (b *recordingBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.reqs = append(b.reqs, r.Clone(context.Background()))
	b.bodies = append(b.bodies, body)
	status := b.status
	b.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func (b *recordingBucket) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.reqs)
}

func startBucket(t *testing.T) (*recordingBucket, string) {
	t.Helper()
	// netegress.Set is PROCESS-GLOBAL and proxies loopback too, unlike
	// http.ProxyFromEnvironment, so a proxy left behind by another test in this
	// package would silently route this PUT away from the fixture.
	_ = netegress.Set("")
	t.Cleanup(func() { _ = netegress.Set("") })
	b := &recordingBucket{}
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	return b, srv.URL
}

func configureS3(t *testing.T, s *Server, endpoint string) {
	t.Helper()
	if err := s.knobs().SetAll(map[string]string{
		settingS3Enabled:   "1",
		settingS3Endpoint:  endpoint,
		settingS3Region:    "us-east-1",
		settingS3Bucket:    "fp",
		settingS3Prefix:    "panel/",
		settingS3AccessKey: "AKIAFIXTURE",
		settingS3SecretKey: "s3cr3tfixture",
		settingS3PathStyle: "1",
	}); err != nil {
		t.Fatalf("store the S3 settings: %v", err)
	}
}

// The row this test exists for: the panel advertised an S3 destination, wrote
// its backups to the local disk only, and an operator who lost the machine lost
// the backups with it. This drives the REAL scheduler the server constructed,
// so it fails if the destination is built but never attached to the delivery
// hook — which is how the Telegram destination nearly shipped, and how a
// "Test upload" button can report success on a panel that never uploads.
func TestAScheduledBackupIsUploadedToS3(t *testing.T) {
	bucket, endpoint := startBucket(t)
	s, _ := adminAPI(t)
	configureS3(t, s, endpoint)

	if err := s.sched.RunScheduledBackupForTest(); err != nil {
		t.Fatalf("run the scheduled backup: %v", err)
	}

	if n := bucket.count(); n != 1 {
		t.Fatalf("the bucket received %d request(s), want exactly 1 — "+
			"the scheduled backup never reached the S3 destination", n)
	}
	req, body := bucket.reqs[0], bucket.bodies[0]

	if req.Method != http.MethodPut {
		t.Errorf("method = %s, want PUT", req.Method)
	}
	// Path-style: /<bucket>/<prefix><object>.
	if !strings.HasPrefix(req.URL.Path, "/fp/panel/forgepanel-") || !strings.HasSuffix(req.URL.Path, ".fpbk") {
		t.Errorf("object path = %q, want /fp/panel/forgepanel-<stamp>.fpbk", req.URL.Path)
	}
	// The name must match the file on disk, so the bucket and the local
	// directory can be reconciled by eye.
	local := newestLocalBackup(t, s.cfg.DataDir)
	if got, want := req.URL.Path, "/fp/panel/"+local; got != want {
		t.Errorf("object path = %q, want %q", got, want)
	}

	// Signed, not anonymous. A permissive bucket accepts an unsigned PUT, so
	// nothing else here would notice the request carried no credentials.
	if auth := req.Header.Get("Authorization"); !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAFIXTURE/") {
		t.Errorf("Authorization = %q, want an AWS4-HMAC-SHA256 signature by AKIAFIXTURE", auth)
	}
	sum := sha256.Sum256(body)
	if got, want := req.Header.Get("x-amz-content-sha256"), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("x-amz-content-sha256 = %q, want %q — the digest does not describe the bytes sent", got, want)
	}

	// The uploaded bytes must be a decryptable backup, not an empty or
	// truncated file. A bucket full of unopenable objects is the failure this
	// whole feature exists to prevent.
	if _, err := backup.Inspect(s.cfg.MasterKey, body); err != nil {
		t.Errorf("the uploaded object is not a valid backup: %v", err)
	}

	// The manifest is inside the ciphertext, so the object itself cannot say
	// which key opens it. The fingerprint rides on the metadata for exactly the
	// case where it matters: after a master-key rotation.
	fp := backup.KeyFingerprint(s.cfg.MasterKey)
	if fp == "" {
		t.Fatal("the panel's master key has no fingerprint")
	}
	if got := req.Header.Get("x-amz-meta-key-fingerprint"); got != fp {
		t.Errorf("x-amz-meta-key-fingerprint = %q, want %q", got, fp)
	}
}

// Off by default, and off means off: shipping the panel's whole state to a
// third party's bucket without being asked is the one behaviour this must never
// have.
func TestNothingIsUploadedWhenS3IsDisabled(t *testing.T) {
	bucket, endpoint := startBucket(t)
	s, _ := adminAPI(t)
	configureS3(t, s, endpoint)
	if err := s.knobs().Set(settingS3Enabled, "0"); err != nil {
		t.Fatal(err)
	}

	if err := s.sched.RunScheduledBackupForTest(); err != nil {
		t.Fatalf("run the scheduled backup: %v", err)
	}
	if n := bucket.count(); n != 0 {
		t.Errorf("the bucket received %d request(s) with the destination switched off", n)
	}
	// And the local backup still happened: a disabled destination must not
	// disable backups.
	newestLocalBackup(t, s.cfg.DataDir)
}

// A bucket that refuses the upload must not take the local backup down with it.
// The local copy already exists on disk; trading it for nothing because a
// remote endpoint was unreachable is strictly worse than keeping it.
func TestAFailedUploadDoesNotFailTheScheduledBackup(t *testing.T) {
	bucket, endpoint := startBucket(t)
	bucket.status = http.StatusForbidden
	s, _ := adminAPI(t)
	configureS3(t, s, endpoint)

	if err := s.sched.RunScheduledBackupForTest(); err != nil {
		t.Fatalf("a refused upload failed the whole scheduled backup: %v", err)
	}
	if bucket.count() != 1 {
		t.Fatalf("the bucket received %d request(s), want 1", bucket.count())
	}
	newestLocalBackup(t, s.cfg.DataDir)
}

// Saving the bucket name must not require re-typing a secret the panel
// deliberately never showed back. The Telegram form already works this way, and
// a settings card that silently clears the credential looks identical to one
// that saved correctly — until the next backup fails with a 403 nobody is
// watching for.
func TestSavingWithoutTheSecretKeyKeepsTheStoredOne(t *testing.T) {
	_, endpoint := startBucket(t)
	s, token := adminAPI(t)
	configureS3(t, s, endpoint)

	code, body := realPost(t, s, "/api/admin/settings/backup/s3", token, map[string]any{
		"enabled": true, "endpoint": endpoint, "region": "us-east-1",
		"bucket": "other-bucket", "prefix": "panel/", "access_key": "AKIAFIXTURE",
		"path_style": true,
		// secret_key deliberately absent, which is what the form sends when the
		// operator did not touch the field.
	})
	if code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	cfg := s.resolveBackupS3()
	if cfg.SecretKey != "s3cr3tfixture" {
		t.Errorf("stored secret key = %q, want the stored one kept", cfg.SecretKey)
	}
	if cfg.Bucket != "other-bucket" {
		t.Errorf("bucket = %q, want the save to have applied", cfg.Bucket)
	}

	// The sentinel means the same thing, because that is what a GET hands the
	// form back for a secret that is set.
	if code, body := realPost(t, s, "/api/admin/settings/backup/s3", token, map[string]any{
		"enabled": true, "endpoint": endpoint, "region": "us-east-1",
		"bucket": "other-bucket", "access_key": "AKIAFIXTURE",
		"secret_key": redactionSentinel, "path_style": true,
	}); code != 200 {
		t.Fatalf("POST with the sentinel returned %d: %s", code, body)
	}
	if got := s.resolveBackupS3().SecretKey; got != "s3cr3tfixture" {
		t.Errorf("stored secret key = %q after a sentinel save", got)
	}
}

// The secret key is a bearer credential for a bucket holding the panel's whole
// state. It goes in and never comes back out.
func TestTheS3SecretKeyIsNeverReturned(t *testing.T) {
	_, endpoint := startBucket(t)
	s, token := adminAPI(t)
	configureS3(t, s, endpoint)

	code, body := doGET(t, s, "/api/admin/settings/backup/s3", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	if strings.Contains(body, "s3cr3tfixture") {
		t.Fatalf("the settings response contains the secret key: %s", body)
	}
	if !strings.Contains(body, `"has_secret_key":true`) {
		t.Errorf("the response does not say a secret key is set: %s", body)
	}
}

// The probe writes a real object with the real credentials, because a check
// that only validates the form tells an operator nothing about the bucket.
func TestTheConnectivityProbeUploadsAndReportsTheBucketsRefusal(t *testing.T) {
	bucket, endpoint := startBucket(t)
	s, token := adminAPI(t)
	configureS3(t, s, endpoint)

	code, body := realPost(t, s, "/api/admin/settings/backup/s3/test", token, map[string]any{})
	if code != 200 {
		t.Fatalf("the probe returned %d: %s", code, body)
	}
	if bucket.count() != 1 {
		t.Fatalf("the probe sent %d request(s) to the bucket", bucket.count())
	}
	if got := bucket.reqs[0].URL.Path; !strings.HasPrefix(got, "/fp/panel/") {
		t.Errorf("probe object = %q, want it under the configured prefix", got)
	}

	// A refusal must reach the operator as a classified failure, not as a 200
	// with a cheerful body: a probe that always says "ok" is worse than none.
	bucket.mu.Lock()
	bucket.status = http.StatusForbidden
	bucket.mu.Unlock()
	code, body = realPost(t, s, "/api/admin/settings/backup/s3/test", token, map[string]any{})
	if code == 200 {
		t.Fatalf("a 403 from the bucket was reported as success: %s", body)
	}
	if !strings.Contains(body, `"kind"`) {
		t.Errorf("the refusal is not a typed apierr body: %s", body)
	}
}

func newestLocalBackup(t *testing.T, dataDir string) string {
	t.Helper()
	entries, err := os.ReadDir(backup.LocalDir(dataDir))
	if err != nil {
		t.Fatalf("read the local backup directory: %v", err)
	}
	var name string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".fpbk") && e.Name() > name {
			name = e.Name()
		}
	}
	if name == "" {
		t.Fatalf("no local backup was written into %s", backup.LocalDir(dataDir))
	}
	return name
}
