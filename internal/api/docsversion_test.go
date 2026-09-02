package api

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func repoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestTheReadmeInstallsTheVersionWeActuallyShip.
//
// Every install path in the README pins a version: the verified installer, the
// deb, the rpm, the Docker image tag, compose, the standalone binaries and the
// source checkout. They went two releases stale — the README told people to
// install v1.20.0 while v1.22.0 was current, so anyone following it got a panel
// missing every fix since, including a privilege escalation. Nothing noticed,
// because nothing was looking.
//
// CHANGELOG's newest heading is the anchor: it is in the repo, it is written
// per release, and a release without an entry is itself a defect.
func TestTheReadmeInstallsTheVersionWeActuallyShip(t *testing.T) {
	changelog := repoFile(t, "CHANGELOG.md")
	m := regexp.MustCompile(`(?m)^## (v\d+\.\d+\.\d+)`).FindStringSubmatch(changelog)
	if m == nil {
		t.Fatal("CHANGELOG.md has no '## vX.Y.Z' heading to anchor the README against")
	}
	current := m[1]

	readme := repoFile(t, "README.md")
	found := regexp.MustCompile(`v\d+\.\d+\.\d+`).FindAllString(readme, -1)
	if len(found) == 0 {
		t.Fatal("README.md pins no version at all; the install instructions cannot work")
	}
	var stale []string
	for _, v := range found {
		if v != current {
			stale = append(stale, v)
		}
	}
	if len(stale) > 0 {
		t.Errorf("README.md pins %v but the newest CHANGELOG entry is %s — following the "+
			"README would install a release we no longer ship", uniqueStrings(stale), current)
	}
}

// TestTheChangelogCoversEveryReleasedVersion: a release with no changelog entry
// leaves no record of what changed, and v1.21.0 shipped exactly that way.
// goreleaser does not write one and nothing else checks.
func TestTheChangelogCoversEveryReleasedVersion(t *testing.T) {
	changelog := repoFile(t, "CHANGELOG.md")
	notes := repoFile(t, "RELEASE_NOTES.md")

	cm := regexp.MustCompile(`(?m)^## (v\d+\.\d+\.\d+)`).FindStringSubmatch(changelog)
	if cm == nil {
		t.Fatal("CHANGELOG.md has no version heading")
	}
	// RELEASE_NOTES leads with the same version, or the two disagree about what
	// the current release even is.
	nm := regexp.MustCompile(`(?m)^# ForgePanel (v\d+\.\d+\.\d+)`).FindStringSubmatch(notes)
	if nm == nil {
		t.Fatal("RELEASE_NOTES.md has no '# ForgePanel vX.Y.Z' heading")
	}
	if cm[1] != nm[1] {
		t.Errorf("CHANGELOG leads with %s and RELEASE_NOTES with %s", cm[1], nm[1])
	}
}
