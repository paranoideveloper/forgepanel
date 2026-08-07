package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The manager is driven here with throwaway shell scripts standing in for the
// upstream server binaries and a pre-seeded binary cache standing in for a
// GitHub release, so the whole reconcile path — install, render, bind probe,
// start, settle, roll back, stop — runs without a network or a real DNS server.

// seedInstall writes a cache entry the installer will find without any HTTP,
// exactly as a completed Ensure would have left it.
func seedInstall(t *testing.T, dataDir string, d Descriptor, tag, exe string) {
	t.Helper()
	dir := filepath.Join(dataDir, "bin", "forgedns", d.Adapter, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(&Install{
		Adapter: d.Adapter, Tag: tag, Dir: dir, Exe: exe,
		Asset: "seeded.tar.gz", SHA256: "seeded", Installed: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "install.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// freeUDPPort returns a UDP port that was free a moment ago. The zones below
// never actually bind it; it only has to survive the manager's bind probe.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// managerZone is a valid zone bound to a scratch port.
func managerZone(port int) ZoneConfig {
	return ZoneConfig{
		Zone: "v.example.com", Adapter: AdapterCottenDNS, EncryptKey: "deadbeefdeadbeef",
		BindHost: "127.0.0.1", BindPort: port,
	}
}

// TestManagerSyncLifecycle walks a zone through start, no-op resync and removal.
func TestManagerSyncLifecycle(t *testing.T) {
	// Nothing in this test may reach the network: the binary is already cached.
	pinClient(t, errTransport{err: errors.New("the manager must not download here")})

	data := t.TempDir()
	d, _ := Lookup(AdapterCottenDNS)
	exe := writeScript(t, data, "server.sh", `while :; do sleep 0.1; done`)
	const tag = "v2026.01.01-seed"
	seedInstall(t, data, d, tag, exe)

	m := NewManager(data)
	t.Cleanup(m.StopAll)
	if m.Installer() == nil {
		t.Fatal("Installer() must expose the binary cache")
	}
	if want := filepath.Join(data, "forgedns", "v.example.com"); m.ZoneDir("V.Example.com.") != want {
		t.Fatalf("ZoneDir = %q, want %q", m.ZoneDir("V.Example.com."), want)
	}

	z := managerZone(freeUDPPort(t))
	spec := Spec{Config: z, PinnedTag: tag}
	if err := m.Sync([]Spec{spec}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	all := m.Status()
	if len(all) != 1 {
		t.Fatalf("Status = %+v, want one zone", all)
	}
	st := all[0]
	if st.State != StateRunning || st.PID <= 0 {
		t.Fatalf("zone status = %+v, want a running process", st)
	}
	if st.Tag != tag || st.Exe != exe || st.Adapter != AdapterCottenDNS {
		t.Fatalf("status does not describe what is running: %+v", st)
	}
	if st.HealthURL != d.HealthURL || st.Listen == "" || len(st.RecentLogs) == 0 {
		t.Fatalf("status is missing supervision detail: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(m.ZoneDir(z.Zone), "server_config.toml")); err != nil {
		t.Fatalf("server config was not written: %v", err)
	}
	key, err := os.ReadFile(filepath.Join(m.ZoneDir(z.Zone), EncryptKeyFile))
	if err != nil || strings.TrimSpace(string(key)) != z.EncryptKey {
		t.Fatalf("key file = %q, %v", key, err)
	}
	if got := m.Tag("V.Example.com"); got != tag {
		t.Fatalf("Tag = %q, want %q", got, tag)
	}
	if _, ok := m.ZoneStatusFor("v.example.com"); !ok {
		t.Fatal("ZoneStatusFor must find a supervised zone")
	}
	if _, ok := m.ZoneStatusFor("other.example.com"); ok {
		t.Fatal("ZoneStatusFor must not invent zones")
	}
	if m.Tag("other.example.com") != "" {
		t.Fatal("Tag must be empty for an unsupervised zone")
	}

	// Re-syncing the identical spec must be a no-op: the signature is unchanged,
	// so the tunnel keeps its process instead of being bounced.
	pid := st.PID
	if err := m.Sync([]Spec{spec}); err != nil {
		t.Fatalf("idempotent Sync: %v", err)
	}
	if again, _ := m.ZoneStatusFor(z.Zone); again.PID != pid {
		t.Fatalf("an unchanged spec restarted the zone (pid %d -> %d)", pid, again.PID)
	}

	// Dropping the zone from the desired set stops it.
	if err := m.Sync(nil); err != nil {
		t.Fatalf("Sync(nil): %v", err)
	}
	if len(m.Status()) != 0 {
		t.Fatalf("a removed zone is still supervised: %+v", m.Status())
	}
	if alive(pid) {
		t.Fatalf("pid %d survived removal", pid)
	}
}

// TestManagerSyncRecordsPerZoneFailures: one bad zone must never take the others
// down, and every failure has to be visible in that zone's status.
func TestManagerSyncRecordsPerZoneFailures(t *testing.T) {
	pinClient(t, errTransport{err: errors.New("no network in this test")})
	data := t.TempDir()
	d, _ := Lookup(AdapterCottenDNS)
	exe := writeScript(t, data, "server.sh", `while :; do sleep 0.1; done`)
	const tag = "v2026.01.01-seed"
	seedInstall(t, data, d, tag, exe)

	m := NewManager(data)
	t.Cleanup(m.StopAll)

	good := Spec{Config: managerZone(freeUDPPort(t)), PinnedTag: tag}
	bad := []Spec{
		{Config: ZoneConfig{Zone: "", Adapter: AdapterCottenDNS, EncryptKey: "x"}},
		{Config: ZoneConfig{Zone: "a.example.com", Adapter: "not-an-adapter", EncryptKey: "x"}, PinnedTag: tag},
		{Config: ZoneConfig{Zone: "b.example.com", Adapter: AdapterCottenDNS}, PinnedTag: tag},
		{Config: ZoneConfig{Zone: "c.example.com", Adapter: AdapterCottenDNS, EncryptKey: "x"}, PinnedTag: "v-never-installed"},
	}
	err := m.Sync(append([]Spec{good}, bad...))
	if err == nil {
		t.Fatal("Sync must report the zones it could not bring up")
	}
	for _, want := range []string{
		"zone with empty name",
		"not a real-binary adapter",
		"no encryption key",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error is missing %q:\n%v", want, err)
		}
	}

	if st, ok := m.ZoneStatusFor("v.example.com"); !ok || st.State != StateRunning {
		t.Fatalf("a healthy zone must survive its neighbours' failures: %+v / %v", st, ok)
	}
	for _, zone := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		st, ok := m.ZoneStatusFor(zone)
		if !ok {
			t.Errorf("%s: a failed zone must still appear in status, not vanish", zone)
			continue
		}
		if st.State != StateError || st.LastError == "" {
			t.Errorf("%s: status = %+v, want an error state with a reason", zone, st)
		}
	}

	// A zone that is already running keeps running when a later edit is invalid:
	// a bad form submission must not take a working tunnel down.
	broken := good
	broken.Config.Mode = ModeTCP // TCP with no forward target -> validation error
	if err := m.Sync([]Spec{broken}); err == nil {
		t.Fatal("an invalid edit must be reported")
	}
	st, _ := m.ZoneStatusFor("v.example.com")
	if st.State != StateRunning {
		t.Fatalf("a running zone was taken down by an invalid edit: %+v", st)
	}
	if !strings.Contains(st.LastError, "FORWARD_IP") {
		t.Fatalf("the zone should carry the reason it could not be updated: %q", st.LastError)
	}
}

// TestManagerRollsBackAFailedReplacement: a replacement that dies immediately
// must leave the zone on its previous working config, not crash-looping.
func TestManagerRollsBackAFailedReplacement(t *testing.T) {
	pinClient(t, errTransport{err: errors.New("no network in this test")})
	data := t.TempDir()
	d, _ := Lookup(AdapterCottenDNS)
	good := writeScript(t, data, "good.sh", `while :; do sleep 0.1; done`)
	bad := writeScript(t, data, "bad.sh", `echo "CONFIG_VERSION rejected" >&2; exit 1`)
	seedInstall(t, data, d, "v-good", good)
	seedInstall(t, data, d, "v-bad", bad)

	m := NewManager(data)
	t.Cleanup(m.StopAll)

	z := managerZone(freeUDPPort(t))
	if err := m.Sync([]Spec{{Config: z, PinnedTag: "v-good"}}); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}
	cfgPath := filepath.Join(m.ZoneDir(z.Zone), "server_config.toml")
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), `LOG_LEVEL = "INFO"`) {
		t.Fatalf("unexpected starting config:\n%s", before)
	}

	// A new config AND a new binary, both of which fail to start.
	next := z
	next.LogLevel = "DEBUG"
	err = m.Sync([]Spec{{Config: next, PinnedTag: "v-bad"}})
	if err == nil {
		t.Fatal("a replacement that dies immediately must be reported")
	}
	if !strings.Contains(err.Error(), "failed to start") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("error should say what happened and that it was undone: %v", err)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the previous working config was not restored:\n%s", after)
	}

	// The zone is back on the old binary rather than left down.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := m.ZoneStatusFor(z.Zone); ok && st.State == StateRunning && st.Exe == good {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, _ := m.ZoneStatusFor(z.Zone)
	t.Fatalf("zone did not return to the previous binary: %+v", st)
}

// TestManagerRefusesToStartOnABusyPort: when something else already holds the
// zone's UDP port the manager must fail the reload with an actionable message
// instead of leaving a crash-loop behind.
func TestManagerRefusesToStartOnABusyPort(t *testing.T) {
	pinClient(t, errTransport{err: errors.New("no network in this test")})
	data := t.TempDir()
	d, _ := Lookup(AdapterCottenDNS)
	exe := writeScript(t, data, "server.sh", `while :; do sleep 0.1; done`)
	seedInstall(t, data, d, "v-good", exe)

	holder, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	port := holder.LocalAddr().(*net.UDPAddr).Port

	m := NewManager(data)
	t.Cleanup(m.StopAll)

	err = m.Sync([]Spec{{Config: managerZone(port), PinnedTag: "v-good"}})
	if err == nil {
		t.Fatal("binding an occupied port must fail loudly")
	}
	if !strings.Contains(err.Error(), "cannot bind") {
		t.Fatalf("unhelpful error: %v", err)
	}
	st, ok := m.ZoneStatusFor("v.example.com")
	if !ok || st.State != StateError {
		t.Fatalf("zone status = %+v / %v, want an error state", st, ok)
	}
	// The foreign listener must be untouched.
	if _, werr := holder.WriteTo([]byte("x"), holder.LocalAddr()); werr != nil {
		t.Fatalf("the port holder was disturbed: %v", werr)
	}
}

// TestManagerCheckHealth covers the health poll and the honest answers it gives
// when a fork has no endpoint or the zone is not supervised at all.
func TestManagerCheckHealth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("  ok  \n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	m := NewManager(t.TempDir())
	m.procs["healthy.example.com"] = &proc{
		zone: "healthy.example.com", adapter: AdapterCottenDNS,
		healthURL: ts.URL + "/healthz", state: StateRunning, logs: newRing(5),
	}
	m.procs["sick.example.com"] = &proc{
		zone: "sick.example.com", adapter: AdapterCottenDNS,
		healthURL: ts.URL + "/down", state: StateRunning, logs: newRing(5),
	}
	m.procs["gone.example.com"] = &proc{
		zone: "gone.example.com", adapter: AdapterCottenDNS,
		healthURL: "http://127.0.0.1:1/healthz", state: StateRunning, logs: newRing(5),
	}
	m.procs["plain.example.com"] = &proc{
		zone: "plain.example.com", adapter: AdapterStormDNS,
		state: StateRunning, logs: newRing(5),
	}

	body, err := m.CheckHealth("healthy.example.com")
	if err != nil || body != "ok" {
		t.Fatalf("CheckHealth = %q, %v", body, err)
	}
	if _, err := m.CheckHealth("sick.example.com"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a failing endpoint must surface its status, got %v", err)
	}
	if _, err := m.CheckHealth("gone.example.com"); err == nil {
		t.Fatal("an unreachable endpoint must be an error")
	}
	_, err = m.CheckHealth("plain.example.com")
	if err == nil || !strings.Contains(err.Error(), "no health endpoint") {
		t.Fatalf("a fork without an endpoint must say so rather than fake an OK, got %v", err)
	}
	_, err = m.CheckHealth("nobody.example.com")
	if err == nil || !strings.Contains(err.Error(), "not supervised") {
		t.Fatalf("an unknown zone must be reported, got %v", err)
	}
}

// TestManagerStopAllReapsEveryZone: the panel must not outlive its children.
func TestManagerStopAllReapsEveryZone(t *testing.T) {
	pinClient(t, errTransport{err: errors.New("no network in this test")})
	data := t.TempDir()
	d, _ := Lookup(AdapterCottenDNS)
	exe := writeScript(t, data, "server.sh", `while :; do sleep 0.1; done`)
	seedInstall(t, data, d, "v-good", exe)

	m := NewManager(data)
	specs := []Spec{
		{Config: managerZone(freeUDPPort(t)), PinnedTag: "v-good"},
	}
	second := managerZone(freeUDPPort(t))
	second.Zone = "w.example.com"
	specs = append(specs, Spec{Config: second, PinnedTag: "v-good"})

	if err := m.Sync(specs); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	pids := []int{}
	for _, st := range m.Status() {
		pids = append(pids, st.PID)
	}
	if len(pids) != 2 {
		t.Fatalf("expected two supervised zones, got %v", pids)
	}

	m.StopAll()
	if len(m.Status()) != 0 {
		t.Fatalf("StopAll left zones behind: %+v", m.Status())
	}
	for _, pid := range pids {
		if alive(pid) {
			t.Errorf("pid %d survived StopAll", pid)
		}
	}
}

// TestSignatureTracksConfigAndBinary is what decides whether a sync restarts a
// tunnel, so it must react to both inputs and to neither anything else.
func TestSignatureTracksConfigAndBinary(t *testing.T) {
	base := signature("CONFIG_VERSION = \"14\"\n", "/opt/forgedns/cotten_v1")
	if base != signature("CONFIG_VERSION = \"14\"\n", "/opt/forgedns/cotten_v1") {
		t.Fatal("signature must be deterministic; a wobble restarts every tunnel on every sync")
	}
	if base == signature("CONFIG_VERSION = \"12\"\n", "/opt/forgedns/cotten_v1") {
		t.Error("a config change must change the signature")
	}
	if base == signature("CONFIG_VERSION = \"14\"\n", "/opt/forgedns/cotten_v2") {
		t.Error("a binary upgrade must change the signature")
	}
}

// TestRingBuffer covers the bounded log buffer behind RecentLogs.
func TestRingBuffer(t *testing.T) {
	r := newRing(3)
	if r.last() != "" || len(r.snapshot()) != 0 {
		t.Fatal("an empty ring must report nothing")
	}
	for _, line := range []string{"one", "two", "three", "four"} {
		r.add(line)
	}
	if got := r.snapshot(); len(got) != 3 || got[0] != "two" || got[2] != "four" {
		t.Fatalf("snapshot = %v, want the last three lines", got)
	}
	if r.last() != "four" {
		t.Fatalf("last = %q", r.last())
	}
}

func TestMinDur(t *testing.T) {
	if minDur(time.Second, 2*time.Second) != time.Second {
		t.Error("minDur must return the smaller duration")
	}
	if minDur(3*time.Second, 2*time.Second) != 2*time.Second {
		t.Error("minDur must return the smaller duration")
	}
}

// TestWaitSettledReportsWhyAZoneIsNotUp covers the outcomes that decide whether
// a replacement is accepted or rolled back.
func TestWaitSettledReportsWhyAZoneIsNotUp(t *testing.T) {
	// Never started: the window expires with no process and the error has to say
	// what state it was actually in.
	p := &proc{zone: "v.example.com", state: StateStopped, logs: newRing(5)}
	err := p.waitSettled(60 * time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not reach running state") {
		t.Fatalf("waitSettled = %v, want a timeout explanation", err)
	}

	// Crashed with a reason: that reason is what the operator needs to see.
	p = &proc{zone: "v.example.com", state: StateCrashed, lastErr: "CONFIG_VERSION rejected", logs: newRing(5)}
	if err := p.waitSettled(time.Second); err == nil || err.Error() != "CONFIG_VERSION rejected" {
		t.Fatalf("waitSettled = %v, want the crash reason verbatim", err)
	}

	// Crashed with nothing recorded still has to produce a usable message.
	p = &proc{zone: "v.example.com", state: StateError, logs: newRing(5)}
	if err := p.waitSettled(time.Second); err == nil || !strings.Contains(err.Error(), "exited immediately") {
		t.Fatalf("waitSettled = %v, want a fallback explanation", err)
	}

	// A process that stays up for the whole window is accepted.
	p = &proc{zone: "v.example.com", state: StateRunning, logs: newRing(5)}
	if err := p.waitSettled(60 * time.Millisecond); err != nil {
		t.Fatalf("a process that stayed running was rejected: %v", err)
	}
}

// TestStopWithoutStart: stopping a zone that never launched must be a clean
// no-op, since Sync calls stop() on entries it recorded but never started.
func TestStopWithoutStart(t *testing.T) {
	p := &proc{zone: "v.example.com", state: StateError, logs: newRing(5)}
	if err := p.stop(0); err != nil {
		t.Fatalf("stop on an unstarted zone = %v, want nil", err)
	}
	if p.snapshotState() != StateStopped {
		t.Fatalf("state = %s, want %s", p.snapshotState(), StateStopped)
	}
	// A nil log pipe must not panic the pump goroutine.
	p.pump(nil)
}

// TestSignalGroupIgnoresNonGroups: the manager only ever signals process groups
// it started, so a zero/negative pgid must be a no-op rather than a broadcast.
func TestSignalGroupIgnoresNonGroups(t *testing.T) {
	if err := signalGroup(0, syscall.SIGTERM); err != nil {
		t.Errorf("signalGroup(0) = %v, want nil", err)
	}
	if err := signalGroup(-1, syscall.SIGKILL); err != nil {
		t.Errorf("signalGroup(-1) = %v, want nil", err)
	}
}

func TestSleepCtxStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Error("a cancelled context must abort the backoff immediately")
	}
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Error("an uncancelled sleep must report that it completed")
	}
}

// TestProbeUDPMessages: the two failure modes need different fixes, so they get
// different messages.
func TestProbeUDPMessages(t *testing.T) {
	if err := probeUDP("127.0.0.1", 70000); err == nil || !strings.Contains(err.Error(), "cannot bind") {
		t.Fatalf("an unusable address must be reported, got %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; no port is privileged")
	}
	// 1013 is below the unprivileged range and is not a service port anything
	// here would already hold.
	err := probeUDP("127.0.0.1", 1013)
	if err == nil {
		t.Skip("this host allows unprivileged binds below 1024")
	}
	if !strings.Contains(err.Error(), "CAP_NET_BIND_SERVICE") {
		t.Fatalf("a privileged port should point at the capability fix, got %v", err)
	}
}

// TestExtractTarGzRefusesAnUnwritableDir: a cache directory the panel cannot
// write must fail the install rather than report a half-extracted binary.
func TestExtractTarGzRefusesAnUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; directory permissions do not apply")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	archive := buildTarGz(t, tarEntry{name: "Server_AMD64_v1", body: "#!/bin/sh\n"})
	if _, err := extractTarGz(archive, dir, "Server_"); err == nil {
		t.Fatal("extraction into an unwritable directory must fail")
	}
}

// TestValidateOptionUnknownType guards the manifest itself: a key declared with
// a type the validator does not implement must be an error, never a pass.
func TestValidateOptionRejectsUnknownType(t *testing.T) {
	err := ValidateOption(Option{Key: "X", Type: OptionType("mystery")}, "anything")
	if err == nil || !strings.Contains(err.Error(), "unknown option type") {
		t.Fatalf("ValidateOption = %v, want an unknown-type error", err)
	}
}
