package api

// Refusing a port-hopping range that would swallow another inbound.
//
// porthop.Conflicts was written, correct, and CALLED BY NOTHING. It answers the
// one question that makes port hopping dangerous rather than merely
// ineffective: does this range contain a port some OTHER inbound is listening
// on?
//
// If it does, the firewall redirect installed for the hopping inbound captures
// that port too, and the other inbound's traffic is silently rerouted to the
// wrong listener. The operator is looking at the inbound they just edited; the
// one that breaks is a different one they are not looking at, and it fails with
// no error anywhere — the port is still open, still accepting, and answering as
// somebody else.
//
// That is why this REFUSES rather than warns, unlike the CAP_NET_ADMIN
// pre-flight. There, the inbound the operator is editing simply serves on its
// base port and nothing else is affected. Here, saving breaks a working inbound
// belonging to someone else's customers.

import (
	"fmt"
	"sort"

	"github.com/forgepanel/forgepanel/internal/core/porthop"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// portHopConflict returns a human-readable error when n's hop range would
// capture another enabled inbound's port, or "" when it is safe.
//
// excludeID is the inbound being edited, so updating one does not report it as
// conflicting with its own previous row.
func (s *Server) portHopConflict(n *model.Node, excludeID uint) string {
	if n == nil || n.Protocol != model.ProtoHysteria2 || n.Hysteria2 == nil {
		return ""
	}
	spec := n.Hysteria2.PortHopping
	if spec == "" {
		return ""
	}
	ranges, err := porthop.ParseSpec(spec)
	if err != nil {
		// A malformed range is a different failure and the model's own
		// validation reports it. Saying nothing here avoids two errors for one
		// mistake.
		return ""
	}
	if s.db == nil {
		return ""
	}
	inbounds, err := s.db.ListInbounds()
	if err != nil {
		// Cannot prove a conflict, so do not claim one. Refusing a save because
		// a read failed would block work over a transient error.
		return ""
	}

	used := make([]int, 0, len(inbounds))
	owner := map[int]string{}
	for _, in := range inbounds {
		if in.ID == excludeID || !in.Enabled || in.Port == 0 {
			continue
		}
		used = append(used, in.Port)
		owner[in.Port] = in.Remark
	}
	bad := porthop.Conflicts(ranges, n.Port, used)
	if len(bad) == 0 {
		return ""
	}
	sort.Ints(bad)

	// Name the inbounds, not just the ports. "conflicts with 30000" makes the
	// operator go and find which inbound that is; the panel already knows.
	parts := make([]string, 0, len(bad))
	for _, p := range bad {
		if r := owner[p]; r != "" {
			parts = append(parts, fmt.Sprintf("%d (%s)", p, r))
		} else {
			parts = append(parts, fmt.Sprintf("%d", p))
		}
	}
	return fmt.Sprintf(
		"the port-hopping range %s covers %d port(s) already in use: %v. "+
			"The firewall redirect would capture that traffic and send it to this inbound instead, "+
			"breaking the other listener with no error anywhere",
		spec, len(bad), parts)
}
