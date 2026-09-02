package binmgr

import "testing"

// Managed and Ensure must answer from the same list. A core added to one and not
// the other is the difference between "nothing to download" and an "unknown
// engine" error at an operator's first reload — and the caller cannot tell those
// apart, so it reports the wrong thing either way.
func TestManagedMatchesWhatEnsureCanInstall(t *testing.T) {
	for _, e := range ManagedEngines() {
		if !Managed(e) {
			t.Errorf("%s is in ManagedEngines but Managed() says otherwise", e)
		}
		// Path is defined for every engine Ensure can install; an engine Ensure
		// does not know produces an empty-ish path under the bin dir.
		if Path := (&Manager{BinDir: t.TempDir()}).Path(e); Path == "" {
			t.Errorf("%s has no resolvable path", e)
		}
	}
	for _, e := range []Engine{"amneziawg", "forgedns", "nonsense"} {
		if Managed(e) {
			t.Errorf("%s is not downloadable and must not be reported as managed", e)
		}
	}
}

// AmneziaWG is the case this exists for: a real engine with no binary to fetch.
func TestAmneziaWGIsNotAManagedDownload(t *testing.T) {
	if Managed(Engine("amneziawg")) {
		t.Fatal("AmneziaWG runs from the host kernel module; there is nothing to download")
	}
}
