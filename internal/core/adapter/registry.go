package adapter

import (
	"fmt"
	"strings"
	"sync"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Registry resolves an inbound to the one adapter that will serve it.
//
// Resolution matches on BOTH the protocol and the resolved engine, and that
// pairing is the point. model.EngineFor answers "which core serves this
// protocol by default", but it cannot answer "which core serves it HERE" — a
// node may have only sing-box installed, or an operator may want VLESS on
// sing-box for its transport behaviour while another node keeps it on xray.
// Matching on the engine alone would hand an inbound to a core that then
// rejects it at startup; matching on the protocol alone would silently ignore
// the choice. Both must agree, and a disagreement is reported rather than
// guessed at.
type Registry struct {
	// EngineChoice optionally overrides the default protocol->engine mapping
	// for a single inbound. Returning "" (or leaving the hook nil) means "use
	// model.EngineFor", which is what every caller does today. It is the
	// extension point for per-node engine selection: a node that resolves VLESS
	// to sing-box changes nothing about how the VLESS inbound is described, only
	// which adapter receives it.
	//
	// Set it before the registry is shared between goroutines; it is read
	// without the lock, because a hook that changed mid-reload would route half
	// a reload to one core and half to another.
	EngineChoice func(n *model.Node) string

	mu     sync.RWMutex
	byName map[string]CoreAdapter
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]CoreAdapter{}}
}

// Register adds an adapter. Registration order is preserved and is the order
// Partition returns plans in, so a reload always drives the cores in the same
// sequence — an unstable order makes a flaky reload impossible to reproduce.
func (r *Registry) Register(a CoreAdapter) error {
	if a == nil {
		return fmt.Errorf("adapter: cannot register a nil adapter")
	}
	name := strings.TrimSpace(a.Name())
	if name == "" {
		return fmt.Errorf("adapter: adapter has no name")
	}
	if len(a.SupportedProtocols()) == 0 {
		return fmt.Errorf("adapter %s: registers no protocols, so nothing could ever route to it", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[name]; dup {
		return fmt.Errorf("adapter: %q is already registered", name)
	}
	if r.byName == nil {
		r.byName = map[string]CoreAdapter{}
	}
	r.byName[name] = a
	r.order = append(r.order, name)
	return nil
}

// Lookup returns the adapter registered under an engine name.
func (r *Registry) Lookup(name string) (CoreAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byName[name]
	return a, ok
}

// All returns every adapter in registration order.
func (r *Registry) All() []CoreAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CoreAdapter, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// Engines returns the registered engine names in registration order.
func (r *Registry) Engines() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

// Resolution is the outcome of matching an inbound to an adapter.
type Resolution struct {
	Protocol model.Protocol
	Engine   string
	Adapter  CoreAdapter
	// Overridden is true when the engine came from EngineChoice rather than
	// from model.EngineFor. The panel shows it so an operator can see that an
	// inbound is deliberately not on its default core.
	Overridden bool
}

// Resolve matches a protocol to an adapter. engineOverride selects a specific
// core; empty means the protocol's default engine.
func (r *Registry) Resolve(p model.Protocol, engineOverride string) (Resolution, error) {
	eng := strings.TrimSpace(engineOverride)
	overridden := eng != ""
	if !overridden {
		eng = model.EngineFor(p)
	}
	if eng == "" || eng == model.EngineUnknown {
		return Resolution{}, &NoAdapterError{Protocol: p, Engine: model.EngineUnknown}
	}
	a, ok := r.Lookup(eng)
	if !ok {
		return Resolution{}, &NoAdapterError{Protocol: p, Engine: eng}
	}
	// The engine exists but must also actually serve the protocol. Skipping
	// this is what makes an engine override dangerous: the inbound reaches a
	// core that has no implementation for it, the core rejects the whole
	// config, and every OTHER inbound on that core stops with it.
	if !containsProtocol(a.SupportedProtocols(), p) {
		return Resolution{}, &UnsupportedError{Engine: eng, Protocol: p, Reason: "protocol not served by this engine"}
	}
	return Resolution{Protocol: p, Engine: eng, Adapter: a, Overridden: overridden}, nil
}

// ResolveNode matches a whole inbound, consulting EngineChoice and checking the
// transport as well as the protocol.
func (r *Registry) ResolveNode(n *model.Node) (Resolution, error) {
	if n == nil {
		return Resolution{}, errNilNode
	}
	override := ""
	if r.EngineChoice != nil {
		override = strings.TrimSpace(r.EngineChoice(n))
	}
	res, err := r.Resolve(n.Protocol, override)
	if err != nil {
		return Resolution{}, err
	}
	if err := res.Adapter.Supports(n); err != nil {
		return Resolution{}, err
	}
	return res, nil
}

// AdapterPlan is one adapter and the share of a reload it must apply.
type AdapterPlan struct {
	Adapter CoreAdapter
	Engine  string
	Plan    Plan
	// Overridden is how many of this plan's inbounds were routed here by
	// EngineChoice rather than by their protocol's default engine. It is a count
	// and not a flag because a plan carries many inbounds and only some of them
	// may have been re-routed; the panel shows the number so an operator can
	// tell a deliberately mixed node from a default one.
	Overridden int
}

// Unroutable is an inbound no adapter could serve, and why. These are reported,
// never dropped silently: an inbound that vanishes from the generated config
// with no explanation is the failure mode operators cannot debug.
type Unroutable struct {
	Node   *model.Node
	Remark string
	Engine string
	Reason string
}

// Partition splits a reload into one plan per adapter.
//
// Every registered adapter gets a plan, INCLUDING an empty one. That is
// deliberate: an adapter whose last inbound was just deleted has to be told, or
// its core keeps serving inbounds the panel no longer knows about. Handing out
// only the non-empty plans is precisely how a deleted inbound stays alive.
func (r *Registry) Partition(specs []engine.InboundSpec, certPath, keyPath string) ([]AdapterPlan, []Unroutable) {
	byEngine := map[string][]engine.InboundSpec{}
	overrides := map[string]int{}
	var bad []Unroutable

	for _, sp := range specs {
		if sp.Node == nil {
			bad = append(bad, Unroutable{Reason: errNilNode.Error()})
			continue
		}
		res, err := r.ResolveNode(sp.Node)
		if err != nil {
			bad = append(bad, Unroutable{
				Node:   sp.Node,
				Remark: sp.Node.Remark,
				Engine: model.EngineFor(sp.Node.Protocol),
				Reason: err.Error(),
			})
			continue
		}
		byEngine[res.Engine] = append(byEngine[res.Engine], sp)
		if res.Overridden {
			overrides[res.Engine]++
		}
	}

	out := make([]AdapterPlan, 0, len(r.order))
	for _, a := range r.All() {
		out = append(out, AdapterPlan{
			Adapter:    a,
			Engine:     a.Name(),
			Plan:       Plan{Specs: byEngine[a.Name()], CertPath: certPath, KeyPath: keyPath},
			Overridden: overrides[a.Name()],
		})
	}
	return out, bad
}

// DefaultRegistry builds the registry ForgePanel ships with: xray, sing-box,
// Brook and AmneziaWG.
//
// brook and awg are passed in rather than constructed here because their
// reconcilers live in internal/core, which this package must not import. They
// are REQUIRED, not optional: a registry silently missing an adapter resolves
// its protocols to "no adapter registered", and the inbounds would disappear
// from the reload with an error that reads like a bug in the registry rather
// than a wiring mistake at startup.
//
// ForgeDNS is deliberately absent. It is a protocol in the model, but it is not
// an inbound-serving proxy core: it is an authoritative DNS service driven from
// a zone table by core.ForgeDNSController, with no node list, no engine binary
// and no config file. Wrapping it here would mean inventing a Plan it cannot
// use. TestForgeDNSIsTheOnlyUnroutableProtocol pins that as a decision rather
// than an oversight.
func DefaultRegistry(opts Options, brook BrookRunner, awg InterfaceRunner) (*Registry, error) {
	if brook == nil {
		return nil, fmt.Errorf("adapter: DefaultRegistry needs a Brook runner")
	}
	if awg == nil {
		return nil, fmt.Errorf("adapter: DefaultRegistry needs an AmneziaWG runner")
	}
	r := NewRegistry()
	for _, a := range []CoreAdapter{
		NewXray(opts),
		NewSingbox(opts),
		NewBrook(opts, brook),
		NewAmneziaWG(awg),
	} {
		if err := r.Register(a); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// ValidateBundle asks each core to validate its share of an already-built
// bundle.
//
// This is the gap between "the panel produced JSON" and "the core accepts it".
// A routing rule naming a geosite category that does not exist renders perfectly
// and is refused with "code not found in geosite.dat", which rejects the WHOLE
// config — every inbound on the box, for one typo. Only the core can say so.
//
// A missing binary is not an error. A panel whose core has not been downloaded
// yet must still be configurable, and the reload path validates before applying
// regardless.
func (r *Registry) ValidateBundle(b *engine.Bundle) error {
	if b == nil {
		return nil
	}
	for _, a := range r.All() {
		var cfg []byte
		switch a.Name() {
		case model.EngineXray:
			if b.XrayN == 0 {
				continue
			}
			cfg = b.Xray
		case model.EngineSingBox:
			if b.SingboxN == 0 {
				continue
			}
			cfg = b.Singbox
		default:
			// Cores whose config this bundle does not carry — Brook, AmneziaWG —
			// are validated on their own path.
			continue
		}
		if len(cfg) == 0 {
			continue
		}
		if p, ok := a.(Provisionable); ok && !p.Provisioned() {
			// The core has not been downloaded yet. Validating would trigger a
			// ~60MB fetch inside what the caller thinks is a cheap check, and
			// the reload path validates before applying anyway.
			continue
		}
		if err := a.ValidateConfig(cfg); err != nil {
			return fmt.Errorf("%s: %w", a.Name(), err)
		}
	}
	return nil
}
