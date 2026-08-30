package settings_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every operator setting must be reached through the registry.
//
// This is the guard the row lives or dies by. internal/settings can hold a
// perfect typed, defaulted, validated table with a full test suite of its own —
// and if one handler still calls db.SetSetting directly, that handler still
// stores whatever it was handed, still carries its own copy of the default, and
// the registry is a package with tests rather than a settings surface. Every
// existing test stays green in that state, because they all drive the OLD path.
// That is exactly how this ledger got stale.
//
// The two methods are named here as text rather than as types on purpose: the
// point is that no call site anywhere reaches the settings table, and a
// type-aware check would still miss a copy made through a fresh *store.Store.
var mayReachTheSettingsTable = map[string]string{
	"internal/store/store.go":       "defines the two methods; this is the table",
	"internal/store/interface.go":   "declares them as SettingRepository so *Store satisfies settings.KV by contract",
	"internal/settings/values.go":   "the one adapter: every typed read and validated write goes through it",
	"internal/settings/registry.go": "documents the pair in the package comment",
}

func TestNoOneReachesTheSettingsTableWithoutTheRegistry(t *testing.T) {
	root := filepath.FromSlash("../..")
	direct := regexp.MustCompile(`\.(Get|Set)Setting\(`)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "frontend", "third_party", "test", "e2e", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		// Tests legitimately poke the table directly: asserting on the STORED
		// form is how the bool-encoding regression is caught at all.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		b, rerr := os.ReadFile(path)
		if rerr != nil || !direct.Match(b) {
			return nil
		}
		if reason, ok := mayReachTheSettingsTable[rel]; ok {
			if reason == "" {
				offenders = append(offenders, rel+" (exempt with no reason given)")
			}
			return nil
		}
		offenders = append(offenders, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these read or write the settings table directly, so they keep their own copy of "+
			"the default and store whatever they are handed without validating it:\n  %s\n\n"+
			"Go through settings.Values (api.Server.knobs()). If a file genuinely must not, add it to "+
			"mayReachTheSettingsTable with the reason.", strings.Join(offenders, "\n  "))
	}
}
