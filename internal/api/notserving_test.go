package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/engine"
	"github.com/forgepanel/forgepanel/internal/store"
)

// An inbound no core can serve is left out of the generated config rather than
// failing the whole build — right, and already the behaviour. What was missing
// is that NOBODY WAS TOLD: reloadEngines discarded the bundle, so the list of
// skipped inbounds was computed on every reload and thrown away. The operator
// created an inbound, the panel accepted it, it never carried a byte, and there
// was no explanation anywhere.

// These use dbServerT rather than adminAPI DELIBERATELY. recordNotServing needs
// only the database, and a full server runs its own background reloads that call
// this same function with a real bundle — which does not skip these fixture
// inbounds, so it clears the reason mid-test and the assertion fails on
// something the test is not about. An earlier version raced exactly that way
// under full-suite load.
func mkInbound(t *testing.T, s *Server, remark string, enabled bool) *store.Inbound {
	t.Helper()
	in := &store.Inbound{Remark: remark, Protocol: "vless", Port: 443, Enabled: enabled}
	if err := s.db.SaveInbound(in); err != nil {
		t.Fatal(err)
	}
	return in
}

func reload(t *testing.T, s *Server, id uint) *store.Inbound {
	t.Helper()
	list, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	t.Fatalf("inbound %d vanished", id)
	return nil
}

func TestSkippedInboundGetsAReason(t *testing.T) {
	s := dbServerT(t)
	in := mkInbound(t, s, "broken", true)

	s.recordNotServing(&engine.Bundle{Skipped: []engine.SkippedInbound{
		{Remark: "broken", Reason: "no supervised engine"},
	}})

	got := reload(t, s, in.ID)
	if got.NotServingReason != "no supervised engine" {
		t.Fatalf("reason = %q; an inbound that never carries a byte must say why", got.NotServingReason)
	}
	// The timestamp is how an operator tells "just broke" from "has been broken
	// for a week".
	if got.NotServingSince == nil {
		t.Error("no since-timestamp recorded")
	}
	// The operator's own enabled flag is NOT rewritten. Doing so makes the panel
	// disagree with what they set, and reads afterwards as though a person did
	// it — while changing nothing, since the inbound is absent from the running
	// config either way.
	if !got.Enabled {
		t.Error("the inbound was auto-disabled; that silently overwrites the operator's setting")
	}
}

func TestReasonIsClearedWhenTheInboundServesAgain(t *testing.T) {
	s := dbServerT(t)
	in := mkInbound(t, s, "fixed", true)

	s.recordNotServing(&engine.Bundle{Skipped: []engine.SkippedInbound{
		{Remark: "fixed", Reason: "egress: bad upstream"},
	}})
	if reload(t, s, in.ID).NotServingReason == "" {
		t.Fatal("setup: the reason should have been recorded")
	}

	s.recordNotServing(&engine.Bundle{})
	got := reload(t, s, in.ID)
	// A stale reason on a working inbound sends an operator to fix something
	// that is no longer wrong.
	if got.NotServingReason != "" {
		t.Fatalf("reason = %q after the inbound recovered", got.NotServingReason)
	}
	if got.NotServingSince != nil {
		t.Error("the since-timestamp outlived the problem")
	}
}

func TestTheSinceTimestampSurvivesRepeatedReloads(t *testing.T) {
	s := dbServerT(t)
	in := mkInbound(t, s, "persistent", true)
	bundle := &engine.Bundle{Skipped: []engine.SkippedInbound{
		{Remark: "persistent", Reason: "no supervised engine"},
	}}

	// Back to back, with no sleep. A sleep would let the server's own background
	// reload run in between, clear the reason (its real bundle does not skip
	// this inbound) and re-set it with a fresh timestamp — a test failing on
	// something it is not testing. time.Now() differs between these calls
	// anyway, so a rewrite would still be visible.
	s.recordNotServing(bundle)
	first := reload(t, s, in.ID).NotServingSince
	if first == nil {
		t.Fatal("setup")
	}
	s.recordNotServing(bundle)
	s.recordNotServing(bundle)

	got := reload(t, s, in.ID).NotServingSince
	if got == nil || !got.Equal(*first) {
		// Rewriting on every reload destroys the one piece of information that
		// says how long this has been broken — and churns the database for a
		// value that did not change.
		t.Fatalf("since = %v, want the original %v", got, first)
	}
}

func TestADisabledInboundIsNotLabelledBroken(t *testing.T) {
	s := dbServerT(t)
	in := mkInbound(t, s, "off", false)

	s.recordNotServing(&engine.Bundle{Skipped: []engine.SkippedInbound{
		{Remark: "off", Reason: "no supervised engine"},
	}})
	// It is absent by request. Labelling it "not serving" is noise on a state
	// nobody is confused about.
	if r := reload(t, s, in.ID).NotServingReason; r != "" {
		t.Fatalf("a disabled inbound was labelled %q", r)
	}
}

func TestTransitionsAreAuditedOnceNotEveryReload(t *testing.T) {
	s := dbServerT(t)
	mkInbound(t, s, "flapper", true)
	bundle := &engine.Bundle{Skipped: []engine.SkippedInbound{
		{Remark: "flapper", Reason: "no supervised engine"},
	}}

	count := func() int {
		entries, _, err := s.db.ListAuditLogs(store.AuditFilter{Action: "inbound.not_serving", Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}

	// A DELTA across a tight loop, not an absolute count. The server runs its
	// own background reloads, which call this same function with a real bundle;
	// an absolute count fails whenever one lands during the test, on something
	// the test is not about.
	before := count()
	for i := 0; i < 5; i++ {
		s.recordNotServing(bundle)
	}
	// Five reloads, ONE transition. Logging every reload would bury the trail
	// under thousands of identical lines.
	if got := count() - before; got != 1 {
		t.Fatalf("five identical reloads produced %d audit entries, want 1", got)
	}

	entries, _, err := s.db.ListAuditLogs(store.AuditFilter{Action: "inbound.not_serving", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Diff == "" {
		t.Error("the audit entry does not say why")
	}
}
