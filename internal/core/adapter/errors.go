package adapter

import (
	"errors"
	"fmt"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// errNilNode guards the whole package against a nil inbound. A nil *model.Node
// used to reach the renderers through engine.BuildMulti and panic there; the
// registry drops it as unroutable instead, because one corrupt row must not take
// the reload for every other inbound down with it.
var errNilNode = errors.New("adapter: nil inbound")

// UnsupportedError says an adapter cannot serve an inbound, and why. It is a
// typed error because the resolver has to tell two different failures apart: an
// inbound whose protocol belongs to another core (route it elsewhere) and one
// whose transport no core carries (a configuration mistake the operator must
// see).
type UnsupportedError struct {
	Engine   string
	Protocol model.Protocol
	Network  model.Network
	Reason   string
}

func (e *UnsupportedError) Error() string {
	if e.Network != "" {
		return fmt.Sprintf("adapter %s: %s over %s: %s", e.Engine, e.Protocol, e.Network, e.Reason)
	}
	return fmt.Sprintf("adapter %s: %s: %s", e.Engine, e.Protocol, e.Reason)
}

// NoAdapterError says no registered adapter serves a protocol under its resolved
// engine. It carries the engine so the operator is told which core is missing
// rather than only which inbound failed.
type NoAdapterError struct {
	Protocol model.Protocol
	Engine   string
}

func (e *NoAdapterError) Error() string {
	return fmt.Sprintf("adapter: no adapter registered for engine %q (protocol %q)", e.Engine, e.Protocol)
}
