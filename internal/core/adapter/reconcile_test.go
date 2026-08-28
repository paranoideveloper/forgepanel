package adapter

import (
	"context"
	"testing"
)

// Which cores may be reconciled on a timer is a correctness question, not a
// preference: Brook and AmneziaWG bring back individual inbounds and leave the
// rest running, while xray's and sing-box's Reload is a process RESTART that
// drops every live connection. Running the second kind every few minutes would
// be an outage every few minutes.
//
// The capability is discovered by type assertion, so getting it wrong is silent
// in both directions — a supervised core that grew a Reconcile method would be
// restarted on a timer, and a per-inbound core that lost one would stop being
// repaired. This is the test that notices.
func TestOnlyPerInboundCoresAreReconcilable(t *testing.T) {
	opts := Options{DataDir: t.TempDir()}
	reg, err := DefaultRegistry(opts, &fakeBrook{}, &fakeAWG{})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"brook":     true,
		"amneziawg": true,
		"xray":      false,
		"sing-box":  false,
	}
	seen := map[string]bool{}
	for _, a := range reg.All() {
		_, is := a.(Reconciler)
		seen[a.Name()] = true
		expect, known := want[a.Name()]
		if !known {
			t.Errorf("core %q is registered and this test has no opinion about whether it may be "+
				"reconciled on a timer — decide, do not delete the case", a.Name())
			continue
		}
		if is != expect {
			if expect {
				t.Errorf("%s reconciles per inbound but does not implement Reconciler, so a downed "+
					"inbound is never brought back", a.Name())
			} else {
				t.Errorf("%s implements Reconciler, but its Reload is a process restart — reconciling "+
					"it on a timer would drop every connection every cycle", a.Name())
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("core %q is no longer registered; update this test deliberately", name)
		}
	}
}

// Reconcile on a core that has never been given a plan must be a no-op, not an
// error and not a teardown. Maintenance runs on a fresh panel too.
func TestReconcilingACoreWithNoPlanDoesNothing(t *testing.T) {
	opts := Options{DataDir: t.TempDir()}
	reg, err := DefaultRegistry(opts, &fakeBrook{}, &fakeAWG{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range reg.All() {
		r, ok := a.(Reconciler)
		if !ok {
			continue
		}
		if err := r.Reconcile(context.Background()); err != nil {
			t.Errorf("%s: reconciling with no plan returned %v", a.Name(), err)
		}
	}
}
