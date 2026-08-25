// This file lives in the external test package on purpose. internal/core must
// stay free to adopt internal/core/adapter later, and it cannot do that if the
// adapter package imports it — the import would be a cycle. An external test
// package may import both, so the conformance assertions below can be made here
// without closing that door.
package adapter_test

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/core/adapter"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// The narrow runner interfaces exist so the adapters can drive the managers that
// already work, unchanged. If a manager's signature moves, this fails at compile
// time — which is the whole point of writing the interfaces to fit the existing
// code rather than making the existing code fit new interfaces.
var (
	_ adapter.BrookRunner     = (*core.BrookManager)(nil)
	_ adapter.InterfaceRunner = (*core.AWGManager)(nil)
	_ adapter.BinaryResolver  = (*binmgr.Manager)(nil)
)

// A registry built from the REAL managers must resolve every protocol exactly as
// one built from test doubles does. The doubles could otherwise be hiding a
// mismatch between what the adapters expect and what the managers provide.
func TestDefaultRegistryAcceptsTheRealManagers(t *testing.T) {
	dir := t.TempDir()
	bins := binmgr.New(dir)
	r, err := adapter.DefaultRegistry(
		adapter.Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins},
		core.NewBrookManager(bins),
		core.NewAWGManager(dir),
	)
	if err != nil {
		t.Fatalf("DefaultRegistry with the real managers: %v", err)
	}
	want := []string{"xray", "sing-box", "brook", "amneziawg"}
	got := r.Engines()
	if len(got) != len(want) {
		t.Fatalf("engines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("engines = %v, want %v", got, want)
		}
	}
	// Health must be answerable before anything has been applied: the panel
	// renders engine status on a fresh install, and a nil-map dereference there
	// would take the dashboard down on first load.
	for _, a := range r.All() {
		if _, err := a.HealthCheck(t.Context()); err != nil {
			t.Errorf("%s.HealthCheck on a fresh panel: %v", a.Name(), err)
		}
	}
}
