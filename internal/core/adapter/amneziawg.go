package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/forgepanel/forgepanel/internal/protocol/export"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// awgAdapter wraps the kernel AmneziaWG reconciler behind the shared interface.
//
// AmneziaWG is the case that proves the interface is not secretly "a subprocess
// with a JSON file": there is no core process at all. Each inbound is a kernel
// network interface brought up by awg-quick from an INI config, and the panel's
// job is to keep those interfaces reconciled with the inbound list. Health here
// is therefore about the KERNEL — module loaded, tools installed — not about a
// pid.
type awgAdapter struct {
	run InterfaceRunner

	mu   sync.Mutex
	last Plan
}

// awgAdapter deliberately does not implement Provisionable. There is nothing to
// fetch: the data plane is the host's kernel module and awg-quick comes from the
// distribution. That ABSENCE is now the signal ensureBinariesFor reads — it used
// to read binmgr.Managed(EngineAmneziaWG) == false, in another package.

// NewAmneziaWG returns the AmneziaWG adapter driving the given reconciler.
func NewAmneziaWG(run InterfaceRunner) CoreAdapter { return &awgAdapter{run: run} }

func (a *awgAdapter) Name() string { return model.EngineAmneziaWG }

func (a *awgAdapter) SupportedProtocols() []model.Protocol {
	return model.ProtocolsForEngine(model.EngineAmneziaWG)
}

// SupportedTransports is empty on purpose: AmneziaWG is a raw UDP kernel
// interface and carries none of the model's transport stack. The model has no
// Network constant for "none", and inventing one would put a value in every
// transport dropdown that no protocol can use.
func (a *awgAdapter) SupportedTransports() []model.Network { return nil }

func (a *awgAdapter) Supports(n *model.Node) error { return supportsNode(a, n) }

// Detect reports the amneziawg userspace tools. Unlike the other cores this
// binary is not managed by the panel — awg/awg-quick are installed from the
// distribution alongside the kernel module, and downloading a userspace tool
// that does not match the loaded module would be worse than not having it.
func (a *awgAdapter) Detect() (bool, string, error) {
	path, err := exec.LookPath("awg")
	if err != nil {
		return false, "", nil
	}
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return true, "", fmt.Errorf("adapter: cannot run %s: %w", path, err)
	}
	return true, firstLine(string(out)), nil
}

// GenerateConfig renders each inbound's awg-quick config, keyed by listen port.
// The port is the key rather than the interface name because the interface name
// is derived from the port by the reconciler; keying on the derived value here
// would be a second copy of that rule, and a second copy is how the engine
// mapping drifted in the first place.
func (a *awgAdapter) GenerateConfig(nodes []*model.Node) ([]byte, error) {
	out := map[string]string{}
	for _, n := range nodes {
		if n == nil {
			return nil, errNilNode
		}
		if n.Protocol != model.ProtoAmneziaWG {
			return nil, &UnsupportedError{Engine: a.Name(), Protocol: n.Protocol,
				Reason: "protocol not served by this engine"}
		}
		// The single client peer lives on the inbound node itself, which is how
		// the panel models WireGuard; passing the node as its own peer list is
		// what the reconciler does too.
		conf, err := export.AmneziaWGServerConf(n, []*model.Node{n})
		if err != nil {
			return nil, err
		}
		key := strconv.Itoa(n.Port)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("amneziawg: port %d is claimed by two inbounds", n.Port)
		}
		out[key] = conf
	}
	return json.MarshalIndent(out, "", "  ")
}

// ValidateConfig checks each rendered awg-quick config for the two fields
// without which `awg-quick up` fails: the interface private key and the listen
// port. It also checks the port actually matches the key it is filed under —
// a mismatch means two inbounds would race for the same interface.
func (a *awgAdapter) ValidateConfig(cfg []byte) error {
	var confs map[string]string
	if err := json.Unmarshal(cfg, &confs); err != nil {
		return fmt.Errorf("amneziawg: config is not a port->conf map: %w", err)
	}
	for key, conf := range confs {
		port, err := strconv.Atoi(key)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("amneziawg: %q is not a listen port", key)
		}
		if !strings.Contains(conf, "[Interface]") {
			return fmt.Errorf("amneziawg: config for port %d has no [Interface] section", port)
		}
		if iniValue(conf, "PrivateKey") == "" {
			return fmt.Errorf("amneziawg: config for port %d has no PrivateKey", port)
		}
		listen := iniValue(conf, "ListenPort")
		if listen == "" {
			return fmt.Errorf("amneziawg: config for port %d has no ListenPort", port)
		}
		if listen != key {
			return fmt.Errorf("amneziawg: config filed under port %d listens on %s", port, listen)
		}
	}
	return nil
}

// iniValue reads a "Key = value" line out of an awg-quick config. It is a
// deliberately small reader: the config is generated by the panel's own
// exporter, so this only has to survive that exact shape plus whatever an
// operator pasted into the Doctor.
func iniValue(conf, key string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// Apply reconciles the kernel interfaces.
//
// A host with no amneziawg module does NOT fail here: the reconciler writes the
// configs, records the shortfall in its status, and returns nil, so HealthCheck
// reports it while every other inbound on the panel keeps serving. Losing the
// whole reload because one kernel module is missing is not an acceptable trade.
// An error the reconciler does return is a real one and is passed on.
func (a *awgAdapter) Apply(ctx context.Context, plan Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	a.last = plan
	a.mu.Unlock()
	return a.run.Sync(plan.Nodes())
}

func (a *awgAdapter) Start(ctx context.Context) error { return a.Reload(ctx) }

func (a *awgAdapter) Stop(context.Context) error {
	a.run.StopAll()
	return nil
}

func (a *awgAdapter) Restart(ctx context.Context) error {
	a.run.StopAll()
	return a.Reload(ctx)
}

// Reload re-reconciles the last plan. Like Brook and unlike the file-config
// cores this is incremental: an interface whose config is unchanged and already
// up is left alone, so reloading does not drop established WireGuard sessions.
func (a *awgAdapter) Reload(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	plan := a.last
	a.mu.Unlock()
	return a.run.Sync(plan.Nodes())
}

// Reconcile re-applies the last plan. For this core Reload is already a
// per-inbound reconcile that leaves healthy inbounds untouched, so this is the
// same work under the name that says it is safe to run on a timer.
func (a *awgAdapter) Reconcile(ctx context.Context) error { return a.Reload(ctx) }

// HealthCheck reports the managed interfaces and kernel readiness. A host whose
// module or tools are missing reports StateUnavailable rather than
// StateCrashed: nothing died, the capability was never there, and the operator
// needs to install a package, not read a crash log.
func (a *awgAdapter) HealthCheck(context.Context) (Health, error) {
	ifaces := a.run.Status()
	kernel := a.run.KernelStatus()
	h := Health{
		Engine:  a.Name(),
		State:   StateStopped,
		Details: map[string]any{"interfaces": ifaces, "kernel": kernel},
	}
	if msg, _ := kernel["last_error"].(string); msg != "" {
		h.LastError = msg
	}
	ready, _ := kernel["kernel_ready"].(bool)
	if !ready {
		h.State = StateUnavailable
		return h, nil
	}
	for _, in := range ifaces {
		if up, _ := in["up"].(bool); up {
			h.State = StateRunning
			h.Running = true
			break
		}
	}
	return h, nil
}
