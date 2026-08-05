package version

import (
	"strings"
	"testing"
)

// TestUnstampedBuildSaysDev is the invariant the release pipeline asserts
// against: a build that was not stamped must never claim a release version it
// is not. CI checks the inverse on a tag — that the published binary does NOT
// report "dev" — and the two together catch a mis-wired ldflags change in
// either direction.
func TestUnstampedBuildSaysDev(t *testing.T) {
	if Version != "dev" {
		t.Fatalf("default Version is %q; an unstamped build must report \"dev\"", Version)
	}
	if IsRelease() {
		t.Fatal("an unstamped build must not report itself as a release")
	}
}

func TestStampedBuildIsARelease(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v1.2.3"
	if !IsRelease() {
		t.Fatal("a stamped version must report as a release")
	}
	s := String("forgepanel")
	if !strings.Contains(s, "v1.2.3") || !strings.HasPrefix(s, "forgepanel ") {
		t.Fatalf("unexpected version line: %q", s)
	}
}

// TestInfoAlwaysCarriesRuntimeIdentity: the API surfaces this so an operator can
// confirm what is running without shelling in, so the platform fields must be
// populated even on an unstamped build.
func TestInfoAlwaysCarriesRuntimeIdentity(t *testing.T) {
	i := Get()
	if i.Go == "" || i.OS == "" || i.Arch == "" {
		t.Fatalf("incomplete build info: %+v", i)
	}
	if i.Version == "" {
		t.Fatal("version must never be empty")
	}
}

// TestLongCommitIsAbbreviated keeps the startup banner readable.
func TestLongCommitIsAbbreviated(t *testing.T) {
	oc, ov := Commit, Version
	defer func() { Commit, Version = oc, ov }()

	Commit = "0123456789abcdef0123456789abcdef01234567"
	Version = "v1.0.0"
	s := String("forgepanel")
	if strings.Contains(s, Commit) {
		t.Fatalf("full 40-char commit rendered in the banner: %q", s)
	}
	if !strings.Contains(s, "0123456789ab") {
		t.Fatalf("abbreviated commit missing: %q", s)
	}
}
