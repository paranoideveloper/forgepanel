package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file is the per-zone process supervisor described in §4c. It is modelled
// on internal/core/brook.go (the panel already runs an external process that
// way) with two additions the upstream tools need:
//
//   - the process CWD is the zone's config directory, because the config points
//     at a RELATIVE ENCRYPTION_KEY_FILE ("encrypt_key.txt") and the binary
//     resolves it against the working directory;
//   - a bind probe before start, because UDP/53 is privileged AND commonly held
//     by systemd-resolved; without the probe a zone would silently crash-loop.
//
// systemd is deliberately NOT required. The doc's unit file (§4c) is one way to
// survive a panel restart, but the os/exec path works everywhere, including
// containers, and keeps the panel the single owner of the process.

// State is a supervised zone's lifecycle state.
type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting" // launched, not yet observed running
	StateRunning  State = "running"
	StateStopping State = "stopping" // shutdown requested, process not yet reaped
	StateCrashed  State = "crashed"
	StateError    State = "error" // could not install/render/bind — never started
)

// Spec is one zone the manager should be running.
type Spec struct {
	Config ZoneConfig
	// PinnedTag is the release tag recorded in panel state. Empty means "resolve
	// the latest and pin it" — an upgrade is then an explicit act of clearing or
	// changing this field, never a side effect of a restart (§4a step 1).
	PinnedTag string
}

// ZoneStatus is a snapshot of one supervised zone, surfaced by the API.
type ZoneStatus struct {
	Zone       string   `json:"zone"`
	Adapter    string   `json:"adapter"`
	State      State    `json:"state"`
	PID        int      `json:"pid"`
	Tag        string   `json:"tag,omitempty"`
	Exe        string   `json:"exe,omitempty"`
	ConfigPath string   `json:"config_path,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	Listen     string   `json:"listen,omitempty"`
	// DoTListen / DoHListen are the zone's private TLS listeners, empty when the
	// zone serves neither. The front router needs them to fan 853 and 443 out by
	// SNI; empty means "this zone does not serve that protocol", which the
	// router refuses explicitly rather than dialling nothing.
	DoTListen  string   `json:"dot_listen,omitempty"`
	DoHListen  string   `json:"doh_listen,omitempty"`
	HealthURL  string   `json:"health_url,omitempty"`
	Restarts   int      `json:"restarts"`
	LastError  string   `json:"last_error,omitempty"`
	RecentLogs []string `json:"recent_logs,omitempty"`
}

// Manager supervises one upstream server process per zone.
type Manager struct {
	dir  string // <dataDir>/forgedns — per-zone config directories
	inst *Installer

	mu    sync.Mutex
	procs map[string]*proc
}

// NewManager roots a manager at <dataDir>/forgedns with its own binary cache.
func NewManager(dataDir string) *Manager {
	return &Manager{
		dir:   filepath.Join(dataDir, "forgedns"),
		inst:  NewInstaller(dataDir),
		procs: map[string]*proc{},
	}
}

// Installer exposes the binary cache (explicit install/upgrade endpoints).
func (m *Manager) Installer() *Installer { return m.inst }

// ZoneDir is where a zone's config and key live. The zone name is a domain, so
// it is sanitised before it becomes a path element.
func (m *Manager) ZoneDir(zone string) string { return filepath.Join(m.dir, sanitize(zone)) }

// EffectiveKey returns the encryption key the running upstream server actually
// uses, read from the zone's key file. It matters because some upstreams
// (MasterDNS) reject a key whose length does not fit the cipher and silently
// write their own — so the key the panel handed the client would never decrypt.
// Reading the file back lets the caller re-sync the client bundle to the key the
// server truly holds. Returns "" when the file is absent or unreadable.
func (m *Manager) EffectiveKey(zone string) string {
	b, err := os.ReadFile(filepath.Join(m.ZoneDir(zone), EncryptKeyFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// proc is one supervised zone process.
type proc struct {
	zone, adapter string
	sig           string // config+binary signature; a change forces a restart
	tag, exe      string
	cfgPath       string
	domains       []string
	listen        string
	// dotListen / dohListen are the zone's private TLS listeners, empty unless
	// the operator moved them off the public ports for front routing.
	dotListen string
	dohListen string
	healthURL string

	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{} // closed when supervise() returns; stop() waits on it
	stopping bool
	state    State
	pid      int
	pgid     int
	restarts int
	lastErr  string
	logs     *ring
}

// plan is one zone resolved far enough to apply: descriptor, normalised config
// and an installed binary — or the error that stopped it getting there.
type plan struct {
	d   Descriptor
	z   ZoneConfig
	in  *Install
	err error
}

// Sync reconciles the running processes with the desired zone set: it installs
// the binary, rewrites the config, restarts zones whose config or binary
// changed, starts new zones and stops removed ones. Per-zone failures are
// recorded in that zone's status and joined into the returned error so one bad
// zone can never take the others down.
//
// Resolution (which downloads from GitHub) happens BEFORE the lock is taken:
// holding the manager mutex across a multi-megabyte download would block
// Status() and stall the whole panel UI for the duration.
func (m *Manager) Sync(specs []Spec) error {
	plans := make([]plan, 0, len(specs))
	for _, sp := range specs {
		plans = append(plans, m.resolve(sp))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]bool{}
	var errs []error
	for _, pl := range plans {
		zone := normDomain(pl.z.Zone)
		if zone == "" {
			errs = append(errs, errors.New("forgedns: zone with empty name"))
			continue
		}
		want[zone] = true
		if err := m.apply(pl); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", zone, err))
		}
	}
	for zone, p := range m.procs {
		if !want[zone] {
			if err := p.stop(defaultStopTimeout); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", zone, err))
			}
			delete(m.procs, zone)
		}
	}
	return errors.Join(errs...)
}

// resolve does the lock-free half: descriptor lookup, normalisation, validation
// and binary install.
func (m *Manager) resolve(sp Spec) plan {
	pl := plan{z: sp.Config}
	// Normalise the name up front so the zone keys the same map entry whether or
	// not the rest of the resolution succeeds.
	pl.z.Zone = normDomain(pl.z.Zone)
	d, err := Lookup(sp.Config.Adapter)
	if err != nil {
		pl.err = err
		return pl
	}
	pl.d = d
	pl.z.Normalize(d)
	if err := pl.z.Validate(); err != nil {
		pl.err = err
		return pl
	}
	in, err := m.inst.Ensure(d, sp.PinnedTag)
	if err != nil {
		pl.err = err
		return pl
	}
	pl.in = in
	return pl
}

// apply brings a single resolved zone to the desired state. Caller holds m.mu.
func (m *Manager) apply(pl plan) error {
	d, z, install := pl.d, pl.z, pl.in
	if pl.err != nil {
		return m.fail(z, d, pl.err)
	}

	dir := m.ZoneDir(z.Zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return m.fail(z, d, err)
	}
	// Resolve the real bind target before rendering, so the emitted UDP_HOST, the
	// bind probe and the reported listen address all agree. On a stock systemd
	// host, systemd-resolved holds :53 on loopback, which makes a wildcard bind
	// fail; effectiveBindHost falls back to the public IP so the tunnel starts
	// without the operator having to free port 53 by hand. (Port is defaulted here
	// too — RenderServer would otherwise be the first place it becomes 53, leaving
	// the probe checking port 0.)
	if z.BindPort == 0 {
		z.BindPort = DefaultUDPPort
	}
	z.BindHost = effectiveBindHost(z.BindHost, z.BindPort)
	cfg, err := RenderServer(d, z)
	if err != nil {
		return m.fail(z, d, err)
	}
	cfgPath := filepath.Join(dir, "server_config.toml")
	// Keep the currently-installed config so a replacement that fails to start
	// can be rolled back to it rather than leaving the zone down.
	prevCfg, _ := os.ReadFile(cfgPath)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return m.fail(z, d, err)
	}
	// The key file is the server half of the shared secret; the client half is
	// handed out in the bundle (§4b — the panel is the key authority).
	if err := os.WriteFile(filepath.Join(dir, EncryptKeyFile), []byte(z.EncryptKey+"\n"), 0o600); err != nil {
		return m.fail(z, d, err)
	}

	sig := signature(cfg, install.Exe)
	cur := m.procs[z.Zone]
	if cur != nil && cur.sig == sig && cur.snapshotState() == StateRunning {
		return nil // already running exactly this
	}

	// Stop the old process and WAIT for it. Starting a replacement while the
	// previous one still owns the zone's UDP port is what produced "address
	// already in use" crash-loops and orphaned children.
	if cur != nil {
		if err := cur.stop(defaultStopTimeout); err != nil {
			// Unclean, but the process is gone; record it and carry on.
			cur.logf("zone=%s unclean shutdown: %v", z.Zone, err)
		}
		delete(m.procs, z.Zone)
	}

	// Anything still holding the port now is not ours.
	if err := waitPortFree(z.BindHost, z.BindPort, 5, 200*time.Millisecond); err != nil {
		if hint := portHolderHint(z.BindPort); hint != "" {
			err = fmt.Errorf("%w%s", err, hint)
		}
		m.rollback(dir, cfgPath, prevCfg, cur, "port unavailable")
		return m.fail(z, d, err)
	}

	listen := net.JoinHostPort(z.BindHost, strconv.Itoa(z.BindPort))
	// Only a zone whose TLS listener was actually moved to a private port is
	// offered to the front router. One left on the public port is not a backend
	// — it IS the thing on 853 — and routing to it would have the router dial
	// itself.
	dotListen, dohListen := "", ""
	if d.HasListenerToggles {
		if z.DoTListener && z.DoTPort > 0 {
			dotListen = net.JoinHostPort(tlsFrontHost, strconv.Itoa(z.DoTPort))
		}
		if z.DoHListener && z.DoHPort > 0 {
			dohListen = net.JoinHostPort(tlsFrontHost, strconv.Itoa(z.DoHPort))
		}
	}
	p := &proc{
		zone: z.Zone, adapter: d.Adapter, sig: sig, tag: install.Tag, exe: install.Exe,
		cfgPath: cfgPath, domains: z.Domains, listen: listen, healthURL: d.HealthURL,
		dotListen: dotListen, dohListen: dohListen,
		state: StateStopped, logs: newRing(200),
	}
	m.procs[z.Zone] = p
	p.start(dir)

	// A replacement that dies immediately (bad config, missing key, wrong
	// version) must not leave the zone crash-looping on the new settings: put
	// the previous working config back and run that instead.
	if err := p.waitSettled(settleWindow); err != nil {
		_ = p.stop(defaultStopTimeout)
		delete(m.procs, z.Zone)
		restored := m.rollback(dir, cfgPath, prevCfg, cur, err.Error())
		wrapped := fmt.Errorf("new config failed to start: %w", err)
		if restored {
			wrapped = fmt.Errorf("%w (rolled back to the previous working config)", wrapped)
		}
		return m.fail(z, d, wrapped)
	}
	return nil
}

// rollback restores the previous config and relaunches the previous binary after
// a failed replacement, so a bad edit degrades to "still running the old
// settings" rather than "zone down". It reports whether it restored anything.
func (m *Manager) rollback(dir, cfgPath string, prevCfg []byte, prev *proc, reason string) bool {
	if prev == nil || len(prevCfg) == 0 || prev.exe == "" {
		return false
	}
	if err := os.WriteFile(cfgPath, prevCfg, 0o600); err != nil {
		return false
	}
	p := &proc{
		zone: prev.zone, adapter: prev.adapter, sig: prev.sig, tag: prev.tag, exe: prev.exe,
		cfgPath: cfgPath, domains: prev.domains, listen: prev.listen, healthURL: prev.healthURL,
		state: StateStopped, logs: newRing(200),
	}
	p.logf("zone=%s rolled back to the previous working config: %s", p.zone, reason)
	m.procs[p.zone] = p
	p.start(dir)
	return true
}

// fail records a zone-level error as a status entry so the UI can show WHY a
// zone is not running, instead of the zone silently disappearing. A zone that is
// already running keeps running on its last good config — a bad edit or an
// unreachable GitHub must not take a working tunnel down — and only picks up the
// error text.
func (m *Manager) fail(z ZoneConfig, d Descriptor, err error) error {
	p := m.procs[z.Zone]
	if p == nil {
		p = &proc{zone: z.Zone, adapter: d.Adapter, domains: z.Domains, logs: newRing(20)}
		m.procs[z.Zone] = p
	}
	p.mu.Lock()
	if p.state != StateRunning {
		p.state = StateError
	}
	p.lastErr = err.Error()
	p.mu.Unlock()
	return err
}

// Status snapshots every supervised zone.
func (m *Manager) Status() []ZoneStatus {
	m.mu.Lock()
	procs := make([]*proc, 0, len(m.procs))
	for _, p := range m.procs {
		procs = append(procs, p)
	}
	m.mu.Unlock()
	out := make([]ZoneStatus, 0, len(procs))
	for _, p := range procs {
		out = append(out, p.status())
	}
	return out
}

// ZoneStatusFor returns one zone's status.
func (m *Manager) ZoneStatusFor(zone string) (ZoneStatus, bool) {
	m.mu.Lock()
	p := m.procs[normDomain(zone)]
	m.mu.Unlock()
	if p == nil {
		return ZoneStatus{}, false
	}
	return p.status(), true
}

// Tag returns the release tag a zone is running, so the API can pin it back
// into panel state after the first successful install.
func (m *Manager) Tag(zone string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.procs[normDomain(zone)]; p != nil {
		return p.tag
	}
	return ""
}

// StopAll terminates every supervised zone (panel shutdown) and does not return
// until each process has exited, so the panel does not outlive its children.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for zone, p := range m.procs {
		_ = p.stop(defaultStopTimeout)
		delete(m.procs, zone)
	}
}

// CheckHealth polls a zone's health endpoint. Only CottenDNS has one (§4c); for
// the others the honest answer is "no endpoint", not a fabricated OK.
func (m *Manager) CheckHealth(zone string) (string, error) {
	st, ok := m.ZoneStatusFor(zone)
	if !ok {
		return "", fmt.Errorf("forgedns: zone %q is not supervised", zone)
	}
	if st.HealthURL == "" {
		return "", fmt.Errorf("forgedns: %s exposes no health endpoint; use process state and logs", st.Adapter)
	}
	cli := &http.Client{Timeout: 2 * time.Second}
	resp, err := cli.Get(st.HealthURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("health %s: status %d", st.HealthURL, resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}
