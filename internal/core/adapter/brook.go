package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// brookAdapter wraps the Brook reconciler behind the shared interface.
//
// Brook is the awkward case the interface has to accommodate: it takes CLI
// arguments, not a config file, so there is no file for a core validator to
// check and no single process to supervise — one Brook inbound is one process.
// The adapter therefore describes its inbounds rather than pretending to hold a
// config, and reconciles them through the manager that already knows how to
// start, restart and stop them.
type brookAdapter struct {
	run  BrookRunner
	bins BinaryResolver

	mu   sync.Mutex
	last Plan
}

// NewBrook returns the Brook adapter driving the given reconciler.
func NewBrook(opts Options, run BrookRunner) CoreAdapter {
	return &brookAdapter{run: run, bins: opts.bins()}
}

func (a *brookAdapter) Name() string { return model.EngineBrook }

func (a *brookAdapter) SupportedProtocols() []model.Protocol {
	return model.ProtocolsForEngine(model.EngineBrook)
}

// SupportedTransports mirrors Brook's server modes rather than the model's
// transport stack: `server` is raw TCP+UDP, `wsserver`/`wssserver` are
// WebSocket, `quicserver` is QUIC. Brook does not use model.Transport at all
// (model.Protocol.UsesTransport is false for it), so this list is descriptive
// and Supports never rejects an inbound on it.
func (a *brookAdapter) SupportedTransports() []model.Network {
	return []model.Network{model.NetTCP, model.NetWS, model.NetQUIC}
}

func (a *brookAdapter) Supports(n *model.Node) error { return supportsNode(a, n) }

// Detect reports whether the pinned Brook binary is installed, and what it says
// its version is.
func (a *brookAdapter) Detect() (bool, string, error) {
	return detectBinary(a.bins.Path(binmgr.EngineBrook))
}

// Provisioned / Provision: Brook is a single downloaded binary, the same one
// BrookManager runs per inbound. Fetching it here means the reload has it before
// any inbound is started, rather than each process discovering it is missing.
func (a *brookAdapter) Provisioned() bool { return a.bins.Present(binmgr.EngineBrook) }

func (a *brookAdapter) Provision(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := a.bins.Ensure(binmgr.EngineBrook); err != nil {
		return fmt.Errorf("brook binary: %w", err)
	}
	return nil
}

// BrookInbound describes one Brook server process. It is what GenerateConfig
// emits, and it deliberately reports only WHETHER a password is set: this
// document is surfaced in the panel's generated-config drawer, and Brook's
// password is the inbound's entire credential.
type BrookInbound struct {
	Port        int    `json:"port"`
	Mode        string `json:"mode"`
	Path        string `json:"path,omitempty"`
	SNI         string `json:"sni,omitempty"`
	HasPassword bool   `json:"has_password"`
}

// brookModes are the four server modes the panel supports. `brook <mode>` is a
// subcommand, so an unknown mode is not a rejected flag — it makes Brook print
// usage and exit, which looks exactly like a crash loop.
var brookModes = map[string]bool{
	"server": true, "wsserver": true, "wssserver": true, "quicserver": true,
}

// brookModeOf and the "/ws" path default below must agree with the reconciler
// that builds the actual argv, or the Doctor validates a process that is not the
// one that runs. TestBrookDescriptorDefaultsMatchTheRunner pins both.
func brookModeOf(n *model.Node) string {
	if n.Brook != nil && n.Brook.Mode != "" {
		return n.Brook.Mode
	}
	return "server"
}

func (a *brookAdapter) GenerateConfig(nodes []*model.Node) ([]byte, error) {
	out := make([]BrookInbound, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			return nil, errNilNode
		}
		if n.Protocol != model.ProtoBrook {
			return nil, &UnsupportedError{Engine: a.Name(), Protocol: n.Protocol,
				Reason: "protocol not served by this engine"}
		}
		sni := n.Security.ServerName
		if sni == "" {
			sni = n.Address
		}
		path := "/ws"
		if n.Brook != nil && n.Brook.Path != "" {
			path = n.Brook.Path
		}
		out = append(out, BrookInbound{
			Port: n.Port, Mode: brookModeOf(n), Path: path, SNI: sni,
			HasPassword: n.Password != "",
		})
	}
	return json.MarshalIndent(out, "", "  ")
}

// ValidateConfig checks a Brook descriptor for the mistakes that make Brook
// exit immediately instead of serving: an unknown subcommand, a missing
// password, a TLS mode with no domain to put in --domainaddress, or two
// inbounds fighting over one port. Brook has no `check` subcommand — there is no
// core-side validator to defer to the way xray and sing-box have one — so this
// is the whole gate, and it is what the Config Doctor calls before an operator
// commits an inbound that would otherwise crash-loop invisibly.
func (a *brookAdapter) ValidateConfig(cfg []byte) error {
	var ins []BrookInbound
	if err := json.Unmarshal(cfg, &ins); err != nil {
		return fmt.Errorf("brook: config is not a list of inbounds: %w", err)
	}
	seen := map[int]bool{}
	for _, in := range ins {
		if in.Port < 1 || in.Port > 65535 {
			return fmt.Errorf("brook: port %d is out of range", in.Port)
		}
		if seen[in.Port] {
			return fmt.Errorf("brook: port %d is claimed by two inbounds", in.Port)
		}
		seen[in.Port] = true
		if !brookModes[in.Mode] {
			return fmt.Errorf("brook: unknown mode %q on port %d", in.Mode, in.Port)
		}
		if !in.HasPassword {
			return fmt.Errorf("brook: inbound on port %d has no password", in.Port)
		}
		// wssserver and quicserver are given --domainaddress <sni>:<port>, not
		// a listen address. With no SNI Brook is handed ":<port>" and refuses
		// to start.
		if (in.Mode == "wssserver" || in.Mode == "quicserver") && in.SNI == "" {
			return fmt.Errorf("brook: mode %s on port %d needs a server name or address", in.Mode, in.Port)
		}
	}
	return nil
}

func (a *brookAdapter) Apply(ctx context.Context, plan Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nodes := plan.Nodes()
	a.mu.Lock()
	a.last = plan
	a.mu.Unlock()
	return a.run.Sync(nodes, plan.CertPath, plan.KeyPath)
}

func (a *brookAdapter) Start(ctx context.Context) error { return a.Reload(ctx) }

func (a *brookAdapter) Stop(context.Context) error {
	a.run.StopAll()
	return nil
}

func (a *brookAdapter) Restart(ctx context.Context) error {
	a.run.StopAll()
	return a.Reload(ctx)
}

// Reload re-reconciles the last plan. Unlike the file-config cores this is
// genuinely incremental: the reconciler leaves a process alone when its
// arguments are unchanged, so reloading does not drop the connections of
// inbounds nobody edited.
func (a *brookAdapter) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	plan := a.last
	a.mu.Unlock()
	return a.run.Sync(plan.Nodes(), plan.CertPath, plan.KeyPath)
}

// Reconcile re-applies the last plan. For this core Reload is already a
// per-inbound reconcile that leaves healthy inbounds untouched, so this is the
// same work under the name that says it is safe to run on a timer.
func (a *brookAdapter) Reconcile(ctx context.Context) error { return a.Reload(ctx) }

// HealthCheck reports the reconciler's process table. Brook processes are
// launched detached and the table records the pid at start; it is not re-checked
// against the OS, so a Brook process that has since died still appears here.
// The state below therefore says what the panel BELIEVES is running, and the
// per-port entries are included so the operator can verify it.
func (a *brookAdapter) HealthCheck(context.Context) (Health, error) {
	procs := a.run.Status()
	h := Health{Engine: a.Name(), State: StateStopped}
	if len(procs) > 0 {
		h.State = StateRunning
		h.Running = true
		h.Details = map[string]any{"processes": procs}
	}
	return h, nil
}
