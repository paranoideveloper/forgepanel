package api

// Which protocol/transport/security combinations actually work.
//
// The panel knew this and could not say it. /capabilities carried the rule as
// English prose — "REALITY only wraps tcp/xhttp/grpc; normal HTTP CDNs only
// front ws/xhttp/httpupgrade" — which no form can grey an option out with. So
// the builder offered every security for every transport, the operator picked
// REALITY over WebSocket, filled the whole form, pressed Save, and got a 400
// from a validator that had known the answer before the first field was typed.
//
// The matrix is MEASURED, not restated: every triple is built into a real node,
// completed by the same create-defaults the create endpoint runs, and put
// through model.Validate — the same function that will reject it on save. A
// hand-maintained table would be a second opinion, and the second opinion is
// the one that goes stale.

import (
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Combination is one protocol/transport/security triple and whether it works.
type Combination struct {
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"` // "" for protocols with no transport layer
	Security  string `json:"security"`  // "" for protocols with no security layer
	Supported bool   `json:"supported"`
	// Reason is the validator's own message, so what the form shows on a
	// disabled option is exactly what the save would have said.
	Reason string `json:"reason,omitempty"`
}

// combinationMatrix walks every combination the form can offer.
func combinationMatrix() []Combination {
	out := []Combination{}
	for _, ps := range protocolSchemas(offeredTransports(), []string{"none", "tls", "reality"}) {
		if !ps.ServesInbound {
			continue
		}
		transports := ps.Transports
		if len(transports) == 0 {
			transports = []string{""}
		}
		securities := ps.Securities
		if len(securities) == 0 {
			securities = []string{""}
		}
		for _, tr := range transports {
			for _, sec := range securities {
				out = append(out, checkCombination(ps.Proto, tr, sec))
			}
		}
	}
	return out
}

func checkCombination(proto, transport, security string) Combination {
	c := Combination{Protocol: proto, Transport: transport, Security: security, Supported: true}
	n := &model.Node{
		Protocol: model.Protocol(proto),
		Address:  "example.com",
		// A port is required and is not what is under test.
		Port: 443,
	}
	if transport != "" {
		n.Transport = model.Transport{Network: model.Network(transport)}
	}
	if security != "" {
		n.Security = model.Security{Type: model.SecurityType(security)}
	}
	// The same completion the create endpoint performs, so a failure here is
	// about the COMBINATION and never about a credential nobody has typed yet.
	applyCreateDefaults(n)
	if err := n.Validate(); err != nil {
		c.Supported, c.Reason = false, err.Error()
	}
	return c
}
