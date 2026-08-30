// Package adapter is the seam between the panel and the proxy cores it drives.
//
// Before this package, "which core serves this inbound" was a compile-time
// switch repeated in several places: engine.BuildMulti switched on the engine
// name to pick a renderer, core.Controller.ReloadSpecs switched again to pick a
// supervisor, EnsureBinaries switched a third time to pick a download, and
// StopAll/Status enumerated the cores by hand. Adding a core meant finding every
// one of those switches; missing one produced an inbound that generated a config
// but was never started, or was started but never stopped — the same class of
// silent drift that model.EngineFor was created to end.
//
// A CoreAdapter collapses that into one object per core: it knows what it can
// serve, how to find and identify its binary, how to turn inbounds into its own
// configuration, how to validate that configuration with the core's own checker,
// and how to run, stop and report on it. A Registry then resolves an inbound to
// exactly one adapter by BOTH its protocol and its resolved engine, so the same
// protocol can be served by different cores on different nodes without a new
// switch anywhere.
//
// This package deliberately does not import internal/core: the concrete Brook
// and AmneziaWG managers live there, and they are consumed through the narrow
// BrookRunner / InterfaceRunner interfaces below instead. That keeps the
// dependency pointing one way, so internal/core can adopt the registry without
// an import cycle.
package adapter

import (
	"context"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// CoreAdapter is one proxy core behind one interface. A subprocess core (xray,
// sing-box, brook) and a kernel-driven core (amneziawg) look identical here, and
// an in-process core would too.
//
// Contract:
//   - Every method is safe for concurrent use.
//   - Apply is the only method that changes what is being served; it is
//     idempotent for an unchanged Plan (the cores' own reconcilers skip a
//     restart when nothing changed), so a caller may re-apply freely.
//   - Start/Stop/Restart/Reload act on the LAST applied Plan. Calling them
//     before any Apply is a no-op rather than an error: a panel with no inbounds
//     of this kind has nothing to run, and that is a normal state, not a fault.
//   - No method downloads or launches anything when the Plan is empty. A panel
//     that never creates a Brook inbound must never fetch the Brook binary.
type CoreAdapter interface {
	// Name is the engine identifier, and the registry key. It matches one of the
	// model.Engine* constants for the cores that exist today.
	Name() string

	// SupportedProtocols is every protocol this core can serve as an inbound.
	SupportedProtocols() []model.Protocol

	// SupportedTransports is every transport network this core can carry for the
	// protocols that use the transport stack. It is empty for a core whose
	// protocols do not use it (AmneziaWG is a kernel UDP interface).
	SupportedTransports() []model.Network

	// Supports reports whether this adapter can serve the node, naming the
	// reason it cannot. The transport is only checked for protocols that
	// actually use the transport stack (model.Protocol.UsesTransport).
	Supports(n *model.Node) error

	// Detect reports whether the core is present on this host and what version
	// it is. A missing core is (false, "", nil) — absence is a state, not an
	// error. A present-but-unrunnable core is (true, "", err), which is what
	// distinguishes "not installed yet" from "installed and broken".
	Detect() (installed bool, version string, err error)

	// GenerateConfig renders the inbounds this adapter serves into the core's
	// own configuration, with no per-user client expansion. This is the shape
	// the Config Doctor validates and the "generated config" drawer shows.
	GenerateConfig(nodes []*model.Node) ([]byte, error)

	// ValidateConfig asks the CORE ITSELF whether a candidate configuration is
	// acceptable, never a reimplementation of its schema. A core that would
	// reject a config at startup must reject it here, or the supervisor applies
	// a config that takes the engine down.
	ValidateConfig(cfg []byte) error

	// Apply reconciles the core with the plan: generate, validate, and start /
	// reload / stop as the plan requires. An empty plan stops the core.
	Apply(ctx context.Context, plan Plan) error

	// Start runs the core from its last applied plan.
	Start(ctx context.Context) error

	// Stop terminates the core. It must block until the core's listening
	// sockets are released, so a subsequent Start cannot lose the port race.
	Stop(ctx context.Context) error

	// Restart is Stop followed by Start, for a core that cannot pick up changes
	// any other way.
	Restart(ctx context.Context) error

	// Reload re-applies the last plan in the cheapest way the core allows.
	// Neither xray nor sing-box can re-read a config without being restarted,
	// so for those it is a restart; Brook and AmneziaWG reconcile per inbound
	// and genuinely leave untouched inbounds running.
	Reload(ctx context.Context) error

	// HealthCheck reports what the core is doing right now.
	HealthCheck(ctx context.Context) (Health, error)
}

// Reconciler is the OPTIONAL capability of a core whose Reload is a cheap,
// idempotent, per-inbound reconcile rather than a process restart.
//
// The distinction decides whether a core can be reconciled on a TIMER. Brook and
// AmneziaWG bring individual inbounds back without touching the others, so
// running that every few minutes costs nothing and repairs an inbound that went
// away on its own. xray and sing-box cannot re-read a config, so their Reload is
// a restart that drops every live connection — calling THAT on a timer would be
// an outage every cycle.
//
// It exists because nothing reconciled these cores periodically. reloadHook
// fires only after a mutation, so an AmneziaWG interface that went down — a
// reloaded kernel module, a stray `awg-quick down`, a reboot race — stayed down
// until some unrelated edit to some unrelated inbound happened to trigger a
// reload. The panel reported it correctly as down and did nothing about it.
type Reconciler interface {
	// Reconcile re-applies the last plan, doing nothing for the parts already in
	// the desired state. It must be safe to call repeatedly on a healthy core.
	Reconcile(ctx context.Context) error
}

// Provisionable is the OPTIONAL capability of a core that owns its own
// installation.
//
// It is optional because "nothing to fetch" is a normal state, not a failure.
// AmneziaWG deliberately does not implement it: it runs from the host's kernel
// module and distro-installed awg-quick, and a userspace tool downloaded by the
// panel could not be guaranteed to match the loaded module (see amneziawg.go's
// Detect). Before this interface, that fact lived in another package as
// binmgr.managedEngines — an allowlist internal/core consulted to decide what
// the adapter it had ALREADY RESOLVED was allowed to install.
type Provisionable interface {
	// Provisioned reports whether the core can run without a fetch. It must not
	// download: callers use it to skip work inside a cheap check.
	Provisioned() bool
	// Provision installs what the core needs. It is idempotent, and returning
	// nil means the core is ready to run.
	Provision(ctx context.Context) error
}

// MultiUserGenerator is the OPTIONAL capability of rendering a config that
// carries one credential per assigned user, rather than the inbound's template
// credential. Cores that authenticate users individually (xray, sing-box)
// implement it; Brook and AmneziaWG have a single per-inbound secret and do not.
//
// It is separate from CoreAdapter because a caller that only wants a config to
// SHOW must not accidentally get one carrying every user's secret.
type MultiUserGenerator interface {
	// GenerateMultiUser renders the specs into a config with a client per bound
	// user, and reports the inbounds it could not render rather than failing the
	// whole batch — one malformed inbound must not stop the other twenty from
	// serving.
	GenerateMultiUser(specs []engine.InboundSpec, certPath, keyPath string) (cfg []byte, served int, skipped []engine.SkippedInbound, err error)
}

// Plan is one adapter's share of a reload: the inbounds it must serve, plus the
// server certificate the cores that terminate TLS need. It is a value, so a
// caller can hold the plan it applied and compare.
type Plan struct {
	Specs []engine.InboundSpec

	// CertPath/KeyPath are the panel's server certificate. They are passed
	// through to the cores that terminate TLS themselves (Brook wss/quic) and
	// injected into rendered inbounds that need one.
	CertPath string
	KeyPath  string
}

// Nodes returns the plan's inbounds, dropping nil specs so an adapter never
// dereferences one.
func (p Plan) Nodes() []*model.Node {
	out := make([]*model.Node, 0, len(p.Specs))
	for _, sp := range p.Specs {
		if sp.Node != nil {
			out = append(out, sp.Node)
		}
	}
	return out
}

// Empty reports whether the plan carries no inbound at all.
func (p Plan) Empty() bool { return len(p.Nodes()) == 0 }

// State is a core's coarse lifecycle state, shared by every adapter so the panel
// renders one status shape for all of them.
type State string

const (
	StateStopped State = "stopped"
	StateRunning State = "running"
	StateCrashed State = "crashed"
	// StateInvalid means the core rejected the last configuration and is
	// therefore still serving the previous one (or nothing).
	StateInvalid State = "invalid_config"
	// StateUnavailable means the core cannot run on this host at all — the
	// AmneziaWG kernel module is missing, the tools are not installed. It is
	// distinct from StateCrashed: nothing died, the capability is absent.
	StateUnavailable State = "unavailable"
	// StateUnresponsive means the core is RUNNING and not answering its own
	// API. It is neither StateRunning (it is serving nobody) nor StateCrashed
	// (nothing exited) — and it is the state a wedged core sat in, reported as
	// healthy, until the supervisor learned to ask.
	StateUnresponsive State = "unresponsive"
)

// Health is what a core reports about itself.
type Health struct {
	Engine     string   `json:"engine"`
	State      State    `json:"state"`
	Running    bool     `json:"running"`
	PID        int      `json:"pid,omitempty"`
	Restarts   int      `json:"restarts,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	RecentLogs []string `json:"recent_logs,omitempty"`

	// Responsive is the last liveness verdict; nil means this core has no probe
	// or none has run yet. LastProbeError is why it said no — an operator
	// looking at a restarting core needs the reason, not just the label.
	Responsive     *bool  `json:"responsive,omitempty"`
	LastProbeError string `json:"last_probe_error,omitempty"`

	// Details carries the engine-specific facts that do not fit the shared
	// shape: Brook's per-port process table, AmneziaWG's kernel readiness.
	Details map[string]any `json:"details,omitempty"`
}

// BinaryResolver is the part of binmgr an adapter needs: where a pinned core
// binary lives, and how to make sure it is there. *binmgr.Manager implements it.
type BinaryResolver interface {
	// Present reports whether the binary is already installed, without
	// downloading it.
	Present(e binmgr.Engine) bool
	// Path is where the pinned binary would live, whether or not it is present.
	Path(e binmgr.Engine) string
	// Ensure downloads and checksum-verifies the pinned binary if needed.
	Ensure(e binmgr.Engine) (string, error)
}

// BrookRunner is the reconciler the Brook adapter drives. *core.BrookManager
// implements it; the interface exists so this package does not import
// internal/core (see the package doc).
type BrookRunner interface {
	Sync(nodes []*model.Node, certPath, keyPath string) error
	StopAll()
	Status() []map[string]any
}

// InterfaceRunner is the reconciler the AmneziaWG adapter drives.
// *core.AWGManager implements it.
type InterfaceRunner interface {
	Sync(nodes []*model.Node) error
	StopAll()
	Status() []map[string]any
	KernelStatus() map[string]any
}

// Options are the host facts every adapter needs.
type Options struct {
	// DataDir is the panel data root; engine configs live under
	// <DataDir>/engines and binaries under <DataDir>/bin.
	DataDir string
	// XrayAPIPort is the loopback port Xray's stats/handler gRPC API binds.
	XrayAPIPort int
	// Bins resolves core binaries. Nil means "use binmgr rooted at DataDir".
	Bins BinaryResolver
	// Certs returns the panel's server certificate and key for GenerateConfig,
	// which has no Plan to carry them. Nil means "no certificate": a TLS inbound
	// then renders without one, which is exactly what the caller asked for when
	// it only wants to LOOK at the config. Apply always uses the Plan's paths.
	Certs func() (certPath, keyPath string)
	// OnEngineLine, if set, receives every line the supervised core writes.
	//
	// This is the presence tracker's feed: Xray's access log goes to stdout,
	// which the supervisor reads, so "who is connected from where" needs no log
	// file and nothing on disk. It runs on the log-pump goroutine.
	OnEngineLine func(string)
	// HotApply, keyed by engine name, is offered the old and new configs before
	// the supervisor falls back to restarting that core. Returning true means the
	// change reached the RUNNING core and no restart is needed.
	//
	// Keyed by engine because only Xray can do this today: sing-box has no
	// equivalent handler API in the builds the panel ships, and claiming
	// otherwise would leave its users out of sync with its config.
	HotApply map[string]func(oldCfg, newCfg []byte) (bool, error)
	// Probe, keyed by engine name, is asked whether that core is actually
	// answering. A core with no entry is supervised exactly as before: alive
	// means healthy.
	//
	// Keyed by engine for the same reason HotApply is — what "answering" means
	// differs per core, and for sing-box the API may not exist in the installed
	// build at all, in which case the probe must skip rather than fail.
	Probe map[string]func(ctx context.Context) error
	// EngineEnv adds environment entries to a supervised core, keyed by engine
	// name. Used for XRAY_LOCATION_ASSET so the core reads the panel's geodata
	// rather than an unrelated system-wide install's.
	EngineEnv map[string][]string
}

func (o Options) certs() (string, string) {
	if o.Certs == nil {
		return "", ""
	}
	return o.Certs()
}

func (o Options) bins() BinaryResolver {
	if o.Bins != nil {
		return o.Bins
	}
	return binmgr.New(o.DataDir)
}

// supportsNode is the shared Supports implementation. The transport is checked
// only for protocols that use the transport stack: Normalize gives every other
// protocol a nominal tcp transport it never reads, and rejecting an inbound
// over that default would break every hysteria2/tuic/brook inbound on the panel.
func supportsNode(a CoreAdapter, n *model.Node) error {
	if n == nil {
		return errNilNode
	}
	if !containsProtocol(a.SupportedProtocols(), n.Protocol) {
		return &UnsupportedError{Engine: a.Name(), Protocol: n.Protocol, Reason: "protocol not served by this engine"}
	}
	if !n.Protocol.UsesTransport() {
		return nil
	}
	net := n.Transport.Network
	if net == "" {
		net = model.NetTCP // Normalize's default; treat a blank transport as tcp
	}
	if !containsNetwork(a.SupportedTransports(), net) {
		return &UnsupportedError{Engine: a.Name(), Protocol: n.Protocol, Network: net,
			Reason: "transport not carried by this engine"}
	}
	return nil
}

func containsProtocol(list []model.Protocol, p model.Protocol) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}

func containsNetwork(list []model.Network, n model.Network) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}
