package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/apierr"
)

// releaseServer serves one asset and one checksums.txt, and hands back a
// *Release pointing at itself. checksum is what checksums.txt CLAIMS; pass
// something other than the real hash to model a tampered or truncated download.
func releaseServer(t *testing.T, tag string, body []byte, checksum string) *Release {
	t.Helper()
	asset := "forgepanel-linux-" + runtime.GOARCH
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch strings.TrimPrefix(req.URL.Path, "/") {
		case asset:
			_, _ = w.Write(body)
		case "checksums.txt":
			_, _ = w.Write([]byte(checksum + "  " + asset + "\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &Release{Tag: tag, Assets: []Asset{
		{Name: asset, URL: srv.URL + "/" + asset, Size: int64(len(body))},
		{Name: "checksums.txt", URL: srv.URL + "/checksums.txt"},
	}}
}

func TestStageRefusesABinaryWhoseChecksumDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	// The payload is deliberately one that would pass every OTHER gate: it runs,
	// exits 0 and reports the right tag. Only the checksum is wrong. A body that
	// could not execute would be refused by the smoke test instead, and the
	// assertions below would pass with the checksum comparison deleted.
	body := []byte("#!/bin/sh\necho \"forgepanel v9.9.9 linux/amd64\"\n")
	rel := releaseServer(t, "v9.9.9", body,
		"0000000000000000000000000000000000000000000000000000000000000000")

	staged, err := Stage(context.Background(), dir, rel)
	if err == nil {
		t.Fatalf("Stage accepted a binary whose checksum did not match: %+v", staged)
	}
	if k := apierr.From(err).Kind; k != apierr.KindValidation {
		t.Errorf("kind = %q, want %q — a bad checksum is the artifact being wrong, not the panel",
			k, apierr.KindValidation)
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("refusal %q does not say the checksum is why", err.Error())
	}
	// The point of the refusal: nothing executable is left behind for a later
	// apply step to pick up.
	if _, statErr := os.Stat(filepath.Join(dir, "updates", rel.Tag, "forgepanel")); !os.IsNotExist(statErr) {
		t.Errorf("a rejected binary was left on disk at updates/%s/forgepanel (stat err %v)", rel.Tag, statErr)
	}
}

// A verified download that cannot run on this host is just as unusable as a
// tampered one, and must leave the same nothing behind.
func TestStageRefusesABinaryThatFailsItsSmokeTest(t *testing.T) {
	dir := t.TempDir()
	// Runs, exits 0, and reports a version that is not the tag we asked for.
	body := []byte("#!/bin/sh\necho 'forgepanel v0.0.1 linux/amd64'\n")
	sum := sha256.Sum256(body)
	rel := releaseServer(t, "v9.9.9", body, hex.EncodeToString(sum[:]))

	if staged, err := Stage(context.Background(), dir, rel); err == nil {
		t.Fatalf("Stage accepted a binary that does not report its own tag: %+v", staged)
	} else if k := apierr.From(err).Kind; k != apierr.KindValidation {
		t.Errorf("kind = %q, want %q", k, apierr.KindValidation)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "updates", "v9.9.9")); !os.IsNotExist(statErr) {
		t.Errorf("the staging directory survived a failed smoke test (stat err %v)", statErr)
	}
}

// The happy path, end to end: verified, written 0755, run, and recorded.
func TestStageWritesAndRecordsAVerifiedBinary(t *testing.T) {
	dir := t.TempDir()
	body := []byte("#!/bin/sh\necho \"forgepanel v9.9.9 linux/amd64\"\n")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	rel := releaseServer(t, "v9.9.9", body, want)

	staged, err := Stage(context.Background(), dir, rel)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if staged.SHA256 != want {
		t.Errorf("recorded sha256 = %q, want %q", staged.SHA256, want)
	}
	fi, err := os.Stat(staged.Path)
	if err != nil {
		t.Fatalf("stat staged binary: %v", err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("staged binary mode %v is not executable", fi.Mode().Perm())
	}
	if !strings.Contains(staged.SmokeOutput, "v9.9.9") {
		t.Errorf("smoke output %q does not carry the tag it was matched against", staged.SmokeOutput)
	}
	if _, err := os.Stat(filepath.Join(dir, "updates", "staged.json")); err != nil {
		t.Errorf("staged.json was not written: %v", err)
	}
}

// The arch check happens before anything is downloaded: a release with no build
// for this host is a refusal the operator can act on, not a 404 from GitHub.
func TestStageRefusesAReleaseWithNoBuildForThisArch(t *testing.T) {
	rel := &Release{Tag: "v9.9.9", Assets: []Asset{{Name: "forgepanel-windows-386", URL: "http://127.0.0.1:1/x"}}}
	_, err := Stage(context.Background(), t.TempDir(), rel)
	if err == nil {
		t.Fatal("Stage accepted a release with no asset for this architecture")
	}
	if k := apierr.From(err).Kind; k != apierr.KindValidation {
		t.Errorf("kind = %q, want %q", k, apierr.KindValidation)
	}
	if !strings.Contains(err.Error(), "forgepanel-linux-"+runtime.GOARCH) {
		t.Errorf("refusal %q does not name the asset it wanted", err.Error())
	}
}
