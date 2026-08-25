// Package profile turns one protocol definition plus a per-node binding into a
// concrete inbound.
//
// The whole value of a profile is that the parts which must be identical across
// nodes CANNOT drift. So this function is deliberately narrow: it copies the
// template and changes exactly three things — the listen port, the public
// address, and the remark. Everything else is the template's, by construction
// rather than by discipline.
//
// A wider override mechanism was the obvious alternative and is the wrong shape:
// once a binding can override the transport or the credentials, ten bindings can
// disagree about them, and the operator is back to maintaining ten definitions
// with extra steps.
package profile

import (
	"fmt"
	"net"
	"strings"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Binding is what one node contributes to a materialised inbound.
type Binding struct {
	NodeID   uint
	NodeName string
	// Port zero means "keep the template's port", which is right when every node
	// can listen on the same one.
	Port int
	// PublicHost is the address clients are given. Empty keeps the template's.
	//
	// It is separate from the listen address on purpose: a node behind a CDN or
	// a NAT is reached at a name unrelated to what it binds locally.
	PublicHost string
}

// Materialise produces the concrete node for one binding.
//
// The template is never mutated — callers hold one template and materialise it
// many times, and a shared mutation would make every later binding inherit the
// previous one's port.
func Materialise(template *model.Node, profileName string, b Binding) (*model.Node, error) {
	if template == nil {
		return nil, fmt.Errorf("profile %q has no template", profileName)
	}
	n := template.Clone()

	if b.Port > 0 {
		n.Port = b.Port
	}
	if n.Port <= 0 || n.Port > 65535 {
		// A profile whose template has no usable port and a binding that does
		// not supply one would otherwise render an inbound the core refuses.
		return nil, fmt.Errorf("profile %q on %s: no valid port (template has %d, binding supplied %d)",
			profileName, b.NodeName, template.Port, b.Port)
	}
	// The template's Address is a LISTEN address and must be bindable. A hostname
	// there is refused here with a message naming the fix, rather than passed to
	// the core to fail as "unable to listen on domain address" on every one of
	// the ten rows at once.
	if !bindableAddress(n.Address) {
		return nil, fmt.Errorf(
			"profile %q: the template's listen address %q is a hostname; "+
				"use 0.0.0.0 (or a local IP) and set the public hostname on the binding instead",
			profileName, n.Address)
	}
	if b.PublicHost != "" {
		// Domain, NOT Address. Address is the LISTEN address — writing a hostname
		// there makes the core refuse the inbound outright ("unable to listen on
		// domain address"), which is exactly what the real-core test caught.
		// Domain is the advertised name, swapped in for client links at export
		// time by substituteAddr, and it also cascades to SNI and Host.
		n.Domain = b.PublicHost
	}

	// The remark identifies WHICH node this row serves. Without it every
	// materialised inbound is called the same thing and the panel's inbound list
	// becomes ten identical rows.
	n.Remark = remarkFor(profileName, b)

	// The tag is cleared so it is derived per-row rather than inherited from the
	// template. The core indexes by tag, routing rules target it, and traffic
	// counters are keyed on it — ten rows sharing one tag would silently merge
	// their accounting.
	n.Tag = ""

	n.Normalize()
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("profile %q on %s: %w", profileName, b.NodeName, err)
	}
	return n, nil
}

// remarkFor names a materialised inbound.
func remarkFor(profileName string, b Binding) string {
	node := b.NodeName
	if node == "" {
		node = fmt.Sprintf("node-%d", b.NodeID)
	}
	return strings.TrimSpace(profileName) + " @ " + node
}

// bindableAddress reports whether an address can actually be listened on.
//
// Empty is fine: the renderer treats it as bind-all, which is the common case
// for a template that leaves the choice to the node.
func bindableAddress(addr string) bool {
	a := strings.TrimSpace(addr)
	if a == "" {
		return true
	}
	if a == "localhost" {
		return true
	}
	// Strip a bracketed IPv6 form before parsing.
	a = strings.TrimPrefix(strings.TrimSuffix(a, "]"), "[")
	return net.ParseIP(a) != nil
}
