package adapter

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/core/supervisor"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// supervised is the adapter for a core that reads ONE aggregate config file and
// runs as a supervised subprocess: xray and sing-box today, and any future core
// with the same shape (config file + validate subcommand + run subcommand).
//
// The two differ only in data — binary, argv, config filename, which half of the
// bundle they own, what they can serve — so they share one implementation. The
// previous arrangement had that data spread across Controller.xraySpec,
// Controller.singboxSpec, EnsureBinaries' switch and BuildMulti's switch, which
// is four places to edit for one core and four places to forget.
type supervised struct {
	name       string
	binEngine  binmgr.Engine
	configFile string
	runArgs    []string
	testArgs   []string
	protos     []model.Protocol
	nets       []model.Network
	// pick selects this core's half of a rendered bundle: the config bytes and
	// how many inbounds actually made it in.
	pick func(*engine.Bundle) ([]byte, int)

	opts Options
	bins BinaryResolver

	mu   sync.Mutex
	proc *supervisor.Process
	last Plan
}

// NewXray returns the adapter for the Xray core: the classic TCP-oriented
// protocol family over the full transport matrix.
func NewXray(opts Options) CoreAdapter {
	return &supervised{
		name:       model.EngineXray,
		binEngine:  binmgr.EngineXray,
		configFile: "xray.json",
		// `xray run -c <file>` / `xray run -test -c <file>`: Xray infers the
		// config format from the file EXTENSION, which is why every path this
		// adapter writes keeps a .json suffix.
		runArgs:  []string{"run", "-c"},
		testArgs: []string{"run", "-test", "-c"},
		protos:   model.ProtocolsForEngine(model.EngineXray),
		// h2, quic and mKCP are absent on purpose. Xray 26 removed all three
		// transports, and model.Validate rejects them for every protocol that
		// uses the transport stack — so an inbound over one of them cannot be
		// stored at all. Listing them here would make Supports admit an inbound
		// that the model refuses, which is a contradiction the resolver would
		// hand to the renderer to discover.
		nets: []model.Network{
			model.NetTCP, model.NetWS, model.NetGRPC, model.NetHTTPUpgrade, model.NetXHTTP,
		},
		pick: func(b *engine.Bundle) ([]byte, int) { return b.Xray, b.XrayN },
		opts: opts,
		bins: opts.bins(),
	}
}

// NewSingbox returns the adapter for the sing-box core: the QUIC/UDP generation
// and the TLS-camouflage family, plus standard WireGuard endpoints.
func NewSingbox(opts Options) CoreAdapter {
	return &supervised{
		name:      model.EngineSingBox,
		binEngine: binmgr.EngineSingbox,
		// "singbox.json", not "sing-box.json": this is the path the supervisor
		// has always written, and renaming it would orphan the config of every
		// panel that upgrades.
		configFile: "singbox.json",
		runArgs:    []string{"run", "-c"},
		testArgs:   []string{"check", "-c"},
		protos:     model.ProtocolsForEngine(model.EngineSingBox),
		// Narrower than xray in one direction and than sing-box itself in the
		// other. sing-box has no xhttp and no mKCP transport at all —
		// render.sbTransport errors on both rather than emitting an approximate
		// key, because sing-box's decoder rejects unknown keys outright and a
		// silently dropped transport is a dead tunnel. Its h2 and quic
		// transports do exist, but only Xray-family protocols use the transport
		// stack in this panel and model.Validate rejects h2/quic for those
		// (removed in Xray 26), so no inbound can reach them.
		nets: []model.Network{
			model.NetTCP, model.NetWS, model.NetHTTPUpgrade, model.NetGRPC,
		},
		pick: func(b *engine.Bundle) ([]byte, int) { return b.Singbox, b.SingboxN },
		opts: opts,
		bins: opts.bins(),
	}
}

func (a *supervised) Name() string { return a.name }

func (a *supervised) SupportedProtocols() []model.Protocol {
	return append([]model.Protocol(nil), a.protos...)
}

func (a *supervised) SupportedTransports() []model.Network {
	return append([]model.Network(nil), a.nets...)
}

func (a *supervised) Supports(n *model.Node) error { return supportsNode(a, n) }

func (a *supervised) configPath() string {
	return filepath.Join(a.opts.DataDir, "engines", a.configFile)
}

// candidatePath is where ValidateConfig parks a config for the core to inspect.
// It keeps the .json extension for the same reason the live config does.
func (a *supervised) candidatePath() string {
	return filepath.Join(a.opts.DataDir, "engines",
		strings.TrimSuffix(a.configFile, ".json")+".candidate.json")
}

func (a *supervised) spec() supervisor.EngineSpec {
	return supervisor.EngineSpec{
		Name:       a.name,
		BinPath:    a.bins.Path(a.binEngine),
		RunArgs:    a.runArgs,
		TestArgs:   a.testArgs,
		ConfigPath: a.configPath(),
		OnLine:     a.opts.OnEngineLine,
		HotApply:   a.opts.HotApply[a.name],
		Probe:      a.opts.Probe[a.name],
		Env:        a.opts.EngineEnv[a.name],
	}
}

// process lazily creates the supervised process. It is lazy so a panel that
// never creates an inbound for this core never allocates a supervisor for it,
// and so Stop on an untouched adapter stays a no-op instead of reporting a
// state for a core that was never asked to run.
func (a *supervised) process() *supervisor.Process {
	if a.proc == nil {
		a.proc = supervisor.NewProcess(a.spec())
		return a.proc
	}
	// Rebuild when the resolved binary has moved under us.
	//
	// The supervisor copies the spec BY VALUE at construction, so BinPath is
	// frozen at whatever the resolver returned the first time this core ran.
	// An operator pinning a core version repoints the binary manager and
	// nothing here noticed: Apply downloaded the pinned core and then restarted
	// the OLD one, while the API reported the new version — the panel lying in
	// precisely the way the pin exists to prevent. It only reproduces on a panel
	// that has already served an inbound, which is every real one.
	//
	// The old process is stopped first. Dropping the reference without stopping
	// would leave the previous core running, unsupervised and still holding the
	// ports the replacement is about to bind.
	want := a.bins.Path(a.binEngine)
	if a.proc.BinPath() == want {
		return a.proc
	}
	a.proc.Stop()
	a.proc = supervisor.NewProcess(a.spec())
	return a.proc
}

func (a *supervised) Detect() (bool, string, error) {
	return detectBinary(a.bins.Path(a.binEngine))
}

func (a *supervised) GenerateConfig(nodes []*model.Node) ([]byte, error) {
	specs := make([]engine.InboundSpec, 0, len(nodes))
	for _, n := range nodes {
		specs = append(specs, engine.InboundSpec{Node: n})
	}
	cp, kp := a.opts.certs()
	cfg, _, _, err := a.GenerateMultiUser(specs, cp, kp)
	return cfg, err
}

// GenerateMultiUser renders the specs through the shared aggregator and keeps
// only this core's half. Feeding the aggregator a subset is safe: it routes each
// inbound by engine internally, so the bytes are identical to what it produces
// from the full inbound list — which is exactly what makes splitting the reload
// across adapters a refactor and not a change.
func (a *supervised) GenerateMultiUser(specs []engine.InboundSpec, certPath, keyPath string) ([]byte, int, []engine.SkippedInbound, error) {
	b, err := engine.BuildMulti(specs, a.opts.XrayAPIPort, certPath, keyPath)
	if err != nil {
		return nil, 0, nil, err
	}
	cfg, n := a.pick(b)
	return cfg, n, b.Skipped, nil
}

// HasLivenessProbe reports whether this adapter was given a probe. It exists so
// the wiring can be asserted from outside this package: a probe that is built
// but never handed to the registry is dead code that ships green, which is the
// exact shape of the bug this feature was added to fix.
func (a *supervised) HasLivenessProbe() bool { return a.opts.Probe[a.name] != nil }

// Provisioned reports whether this core's binary is already installed. It lets
// a caller skip validation rather than pay for a download inside a check.
func (a *supervised) Provisioned() bool { return a.bins.Present(a.binEngine) }

// Provision downloads and checksum-verifies the pinned binary if it is missing.
func (a *supervised) Provision(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := a.bins.Ensure(a.binEngine); err != nil {
		return fmt.Errorf("%s binary: %w", a.name, err)
	}
	return nil
}

func (a *supervised) ValidateConfig(cfg []byte) error {
	// ValidateConfig has no context of its own, and the fetch it guards is the
	// same one Apply pays; Background matches the precedent in dispatch.go.
	if err := a.Provision(context.Background()); err != nil {
		return err
	}
	a.mu.Lock()
	p := a.process()
	a.mu.Unlock()
	return p.ValidateBytes(cfg, a.candidatePath())
}

func (a *supervised) Apply(ctx context.Context, plan Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	a.last = plan
	a.mu.Unlock()

	// Resolve the binary as soon as the plan names ANY inbound for this core,
	// before knowing whether they all render. That is the established order:
	// deciding after the render would skip the download for a plan whose only
	// inbound is malformed, and the operator's next fix would then pay the
	// download at the worst possible moment.
	if len(plan.Nodes()) > 0 {
		if err := a.Provision(ctx); err != nil {
			return err
		}
	}
	cfg, served, _, err := a.GenerateMultiUser(plan.Specs, plan.CertPath, plan.KeyPath)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if served == 0 {
		// Nothing to serve: stop the core if it was ever started, and do not
		// start one just to run an empty config.
		a.mu.Lock()
		p := a.proc
		a.mu.Unlock()
		if p != nil {
			p.Stop()
		}
		return nil
	}
	a.mu.Lock()
	p := a.process()
	a.mu.Unlock()
	return p.Apply(cfg)
}

func (a *supervised) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	p := a.proc
	a.mu.Unlock()
	if p == nil {
		return nil // nothing applied yet; there is no config to run
	}
	return p.Start()
}

func (a *supervised) Stop(ctx context.Context) error {
	a.mu.Lock()
	p := a.proc
	a.mu.Unlock()
	if p == nil {
		return nil
	}
	// Stop blocks until the process is reaped, so it is deliberately NOT gated
	// on ctx: abandoning the wait would leave the old process holding its listen
	// ports and the next start would fail to bind.
	p.Stop()
	return nil
}

func (a *supervised) Restart(ctx context.Context) error {
	if err := a.Stop(ctx); err != nil {
		return err
	}
	return a.Start(ctx)
}

// Reload re-renders the last plan and re-applies it. Neither xray nor sing-box
// can re-read a config file in place — there is no SIGHUP path in either — so
// "reload" means validate the new config and restart onto it. Restart, by
// contrast, reuses the config already on disk.
func (a *supervised) Reload(ctx context.Context) error {
	a.mu.Lock()
	plan := a.last
	a.mu.Unlock()
	return a.Apply(ctx, plan)
}

func (a *supervised) HealthCheck(context.Context) (Health, error) {
	a.mu.Lock()
	p := a.proc
	a.mu.Unlock()
	if p == nil {
		return Health{Engine: a.name, State: StateStopped}, nil
	}
	st := p.Status()
	return Health{
		Engine:     a.name,
		State:      mapSupervisorState(st.State),
		Running:    st.State == supervisor.StateRunning,
		PID:        st.PID,
		Restarts:   st.Restarts,
		LastError:  st.LastError,
		RecentLogs: st.RecentLogs,
		// Carried across the seam rather than recomputed: the supervisor is the
		// only thing that ever ran the probe.
		Responsive:     st.Responsive,
		LastProbeError: st.LastProbeError,
	}, nil
}

// mapSupervisorState translates the supervisor's lifecycle onto the shared one.
// The two enumerations happen to use the same strings today; converting instead
// of mapping would make a future supervisor state leak through as an adapter
// state nothing handles, so the translation is explicit and TestStateMapping
// fails if a supervisor state is added without a decision here.
func mapSupervisorState(s supervisor.State) State {
	switch s {
	case supervisor.StateRunning:
		return StateRunning
	case supervisor.StateCrashed:
		return StateCrashed
	case supervisor.StateInvalid:
		return StateInvalid
	case supervisor.StateStopped:
		return StateStopped
	case supervisor.StateUnresponsive:
		return StateUnresponsive
	}
	return StateUnavailable
}

// detectBinary reports whether a pinned core binary is installed and what it
// says its version is. A missing file is "not installed", not an error: on a
// fresh panel every core is missing until an inbound needs one.
func detectBinary(path string) (bool, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", err
	}
	if fi.Mode()&0o111 == 0 {
		// Present but not executable — a truncated or half-extracted install.
		// Reporting it as installed-and-broken is what tells the operator to
		// clear the cache rather than wait for a download that already happened.
		return true, "", fmt.Errorf("adapter: %s is not executable", path)
	}
	ver, err := binaryVersion(path)
	if err != nil {
		return true, "", err
	}
	return true, ver, nil
}

// binaryVersion asks a core binary what it is. The cores disagree on the flag —
// xray and sing-box take `version`, some builds only answer `-version` — so both
// are tried before giving up.
func binaryVersion(path string) (string, error) {
	out, err := exec.Command(path, "version").CombinedOutput()
	if err != nil {
		alt, altErr := exec.Command(path, "-version").CombinedOutput()
		if altErr != nil {
			return "", fmt.Errorf("adapter: cannot run %s: %w", path, err)
		}
		out = alt
	}
	return firstLine(string(out)), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
