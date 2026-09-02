package adapter

import (
	"path/filepath"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// pinnableBins is fakeBins with a version segment the test can move, which is
// exactly what SetCorePins does to the real binmgr: it changes what Path
// resolves to without touching anything the adapter holds.
type pinnableBins struct {
	fakeBins
	version string
}

func (p *pinnableBins) Path(e binmgr.Engine) string {
	return filepath.Join(p.dir, string(e)+"-"+p.version, string(e))
}

func (p *pinnableBins) Ensure(e binmgr.Engine) (string, error) {
	p.fakeBins.mu.Lock()
	p.fakeBins.ensured = append(p.fakeBins.ensured, e)
	p.fakeBins.mu.Unlock()
	return p.Path(e), nil
}

// Pinning a core version downloaded the pinned binary and then restarted the OLD
// one, while GET /cores reported the new version — the panel lying in exactly
// the way the pin feature exists to stop.
//
// The cause is memoisation: process() builds supervisor.NewProcess(a.spec())
// once and the supervisor copies that spec BY VALUE, so BinPath is frozen at
// whatever the resolver returned the first time this core was asked to run.
// spec() itself re-reads it correctly, which is why every test of spec() passed;
// and on a panel that has never served an inbound the memo is empty and the pin
// appears to work. On every panel that has, it does not.
func TestAPinnedCoreReachesTheRunningProcess(t *testing.T) {
	dir := t.TempDir()
	bins := &pinnableBins{fakeBins: fakeBins{dir: filepath.Join(dir, "bin")}, version: "v26.3.27"}
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	a := NewXray(Options{DataDir: dir, XrayAPIPort: 10085, Bins: bins}).(*supervised)

	was := a.process().BinPath()
	if was != bins.Path(binmgr.EngineXray) {
		t.Fatalf("initial BinPath = %q, want the resolved one", was)
	}

	// The operator pins a different version.
	bins.version = "v25.1.1"
	writeFakeCore(t, bins.Path(binmgr.EngineXray), fakeCore)
	if bins.Path(binmgr.EngineXray) == was {
		t.Fatal("the resolver did not move; the test would prove nothing")
	}

	got := a.process().BinPath()
	if got == was {
		t.Fatalf("the process still execs %q after the pin moved to %q — the pin "+
			"downloads a core the panel never runs", got, bins.Path(binmgr.EngineXray))
	}
	if got != bins.Path(binmgr.EngineXray) {
		t.Fatalf("BinPath = %q, want %q", got, bins.Path(binmgr.EngineXray))
	}
}
