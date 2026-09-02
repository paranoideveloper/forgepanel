package api

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/nettune"
)

type nettuneCalls struct {
	applied  atomic.Int32
	reverted atomic.Int32
}

// stubNetTune swaps the host-mutating seam for counters.
//
// Call it BEFORE the server is created: t.Cleanup runs last-registered-first,
// and the restore has to happen after Server.Close has waited for the boot
// goroutines, or a background apply lands on the real /proc of the machine
// running the tests.
func stubNetTune(t *testing.T) *nettuneCalls {
	t.Helper()
	c := &nettuneCalls{}
	oa, or, ost := nettuneApply, nettuneRevert, nettuneStatus
	nettuneApply = func() error { c.applied.Add(1); return nil }
	nettuneRevert = func() error { c.reverted.Add(1); return nil }
	nettuneStatus = func() nettune.Status {
		return nettune.Status{Congestion: "bbr", Qdisc: "fq", BBRAvailable: true, Active: true, Persisted: true}
	}
	t.Cleanup(func() { nettuneApply, nettuneRevert, nettuneStatus = oa, or, ost })
	return c
}

// The wiring: a congestion-control setting written once to /proc is gone at the
// next reboot, and gone the moment anything else on the host rewrites it. If
// only the toggle handler applies it, the feature demos perfectly and is dead
// by morning.
func TestRunMaintenanceReappliesCongestionControl(t *testing.T) {
	calls := stubNetTune(t)
	s, _ := adminAPI(t)
	if err := s.db.SetSetting("net_tune_bbr", "1"); err != nil {
		t.Fatal(err)
	}
	before := calls.applied.Load()
	s.runMaintenance()
	if calls.applied.Load() == before {
		t.Error("runMaintenance did not re-apply the congestion-control setting, so nothing ever will")
	}
}

// The other half of the same claim: the panel restarts with the host, and the
// boot after a reboot is the one that has to put the sysctl back.
func TestNetTuneIsAppliedAtBoot(t *testing.T) {
	calls := stubNetTune(t)
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.DataDir = dir

	// First boot stores the operator's choice, exactly as the toggle would.
	first, err := NewWithStore(cfg)
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	if err := first.db.SetSetting("net_tune_bbr", "1"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	before := calls.applied.Load()
	second, err := NewWithStore(cfg)
	if err != nil {
		t.Fatalf("NewWithStore (restart): %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	// Close waits for the boot background work, so the counter is settled.
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.applied.Load() == before {
		t.Error("a restart did not re-apply the stored congestion-control setting: after a reboot the host is back on cubic and the panel still says BBR is on")
	}
}

// A panel with the toggle off must not touch the host at all — an operator who
// never asked for BBR should not find their sysctls rewritten.
func TestNetTuneIsNotAppliedWhenTheToggleIsOff(t *testing.T) {
	calls := stubNetTune(t)
	s, _ := adminAPI(t)
	s.runMaintenance()
	if calls.applied.Load() != 0 {
		t.Errorf("applied the congestion-control setting %d time(s) with the toggle off", calls.applied.Load())
	}
}

func TestNetTuneToggleRoundTripsThroughTheAPI(t *testing.T) {
	calls := stubNetTune(t)
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/settings/nettune", token, map[string]any{"enabled": true})
	if code != 200 {
		t.Fatalf("enabling returned %d: %s", code, body)
	}
	if calls.applied.Load() == 0 {
		t.Error("the toggle persisted the setting without applying it, so nothing changes until the next restart")
	}
	if s.db.GetSetting("net_tune_bbr") != "1" {
		t.Errorf("net_tune_bbr = %q, want 1", s.db.GetSetting("net_tune_bbr"))
	}

	code, body = doGET(t, s, "/api/admin/settings/nettune", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	var got struct {
		Enabled      bool   `json:"enabled"`
		Congestion   string `json:"congestion"`
		BBRAvailable bool   `json:"bbr_available"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Congestion != "bbr" || !got.BBRAvailable {
		t.Errorf("GET /settings/nettune = %s, want the stored toggle plus the live host state", body)
	}

	code, body = realPost(t, s, "/api/admin/settings/nettune", token, map[string]any{"enabled": false})
	if code != 200 {
		t.Fatalf("disabling returned %d: %s", code, body)
	}
	if calls.reverted.Load() == 0 {
		t.Error("turning the toggle off left the host on BBR and the drop-in in place")
	}
	if s.db.GetSetting("net_tune_bbr") != "0" {
		t.Errorf("net_tune_bbr = %q, want 0", s.db.GetSetting("net_tune_bbr"))
	}
}

// Maintenance runs every minute. A host that refuses the sysctl — an old
// install whose unit still has ProtectKernelTunables=true, a container with a
// read-only /proc — would otherwise write the same line to the journal 1440
// times a day, which is how operators learn to ignore the journal.
func TestAPersistentNetTuneFailureIsReportedOnceNotEveryMinute(t *testing.T) {
	stubNetTune(t)
	logged := 0
	oldLog := netTuneLog
	netTuneLog = func(format string, args ...any) { logged++ }
	t.Cleanup(func() { netTuneLog = oldLog })

	s, _ := adminAPI(t)
	if err := s.db.SetSetting("net_tune_bbr", "1"); err != nil {
		t.Fatal(err)
	}

	nettuneApply = func() error { return errors.New("read-only file system") }
	s.applyNetTune()
	s.applyNetTune()
	s.applyNetTune()
	if logged != 1 {
		t.Errorf("the same failure was reported %d times, want 1", logged)
	}

	// A DIFFERENT failure is news and must be reported.
	nettuneApply = func() error { return errors.New("no such device") }
	s.applyNetTune()
	if logged != 2 {
		t.Errorf("a new failure was reported %d times in total, want 2", logged)
	}

	// So is recovery: the operator who read the failure needs to see it end.
	nettuneApply = func() error { return nil }
	s.applyNetTune()
	s.applyNetTune()
	if logged != 3 {
		t.Errorf("recovery was reported %d times in total, want 3", logged)
	}
}
