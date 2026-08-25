package api

// Telling the operator when an inbound is not actually serving.
//
// An inbound that no core can serve is left OUT of the generated configuration
// rather than failing the whole build. That is right — one bad inbound must not
// take every other one down with it — and it was already the behaviour. What was
// missing is that nobody was told. `reloadEngines` discarded the bundle, so the
// list of skipped inbounds was computed on every reload and thrown away, and the
// operator's only symptom was an inbound that existed, looked enabled, and never
// carried a byte.
//
// The inbound is NOT auto-disabled. Rewriting the operator's own `enabled` flag
// makes the panel disagree with what they set, and reads afterwards as though a
// person did it. An inbound that is enabled and not serving, with the reason
// attached, is the honest state — and it is functionally the same thing, because
// it is already absent from the running config either way.

import (
	"time"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/store"
)

// recordNotServing stores, or clears, the reason each inbound is absent from the
// running configuration.
func (s *Server) recordNotServing(b *engine.Bundle) {
	if s.db == nil {
		return
	}
	inbounds, err := s.db.ListInbounds()
	if err != nil {
		return
	}

	// Skipped entries carry the inbound's REMARK, which is what the engine layer
	// knows it by.
	reason := map[string]string{}
	if b != nil {
		for _, sk := range b.Skipped {
			reason[sk.Remark] = sk.Reason
		}
	}

	now := time.Now()
	for i := range inbounds {
		in := &inbounds[i]
		want := reason[in.Remark]

		// Only inbounds the operator actually enabled are candidates. A disabled
		// one is absent by request, and labelling it "not serving" would be
		// noise on a state nobody is confused about.
		if !in.Enabled {
			want = ""
		}

		if want == in.NotServingReason {
			// Unchanged. Writing the row anyway on every reload would churn the
			// database for nothing and reset the "since" timestamp, destroying
			// the one piece of information that says how long this has been
			// broken.
			continue
		}

		fields := map[string]any{"not_serving_reason": want}
		if want == "" {
			fields["not_serving_since"] = nil
		} else {
			fields["not_serving_since"] = now
		}
		if err := s.db.UpdateInboundFields(in.ID, fields); err != nil {
			continue
		}

		// Audited, because an inbound silently stopping is exactly the kind of
		// change someone needs to find afterwards. Logged only on a TRANSITION,
		// so the trail stays readable instead of repeating every reload.
		entry := &store.AuditLog{Actor: "system", Action: "inbound.serving", Target: in.Remark}
		if want != "" {
			entry.Action = "inbound.not_serving"
			entry.Diff = want
		}
		s.db.Audit(entry)
	}
}
