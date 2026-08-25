package api

import "testing"

// The sing-box protocols can only be metered by a binary built with
// with_v2ray_api, which the official releases are not. Without it a user can
// exhaust their plan on hysteria2/tuic/anytls and stay active forever, because
// the quota system is guarding traffic it cannot see — silently, and always in
// the customer's favour. That has to be visible somewhere an operator looks.
func TestMeteringSubsystemIsReported(t *testing.T) {
	s, _, _ := createComprehensiveTestServer(t)
	rep := s.healthReport()

	var found *Subsystem
	for i := range rep.Subsystems {
		if rep.Subsystems[i].Key == "metering" {
			found = &rep.Subsystems[i]
		}
	}
	if found == nil {
		t.Fatal("health reports no metering subsystem, so unmetered protocols stay invisible")
	}
	if found.Summary == "" {
		t.Error("the metering subsystem carries no human-readable summary")
	}
	// With no sing-box inbounds there is nothing uncounted, so this must not
	// cry wolf: a warning an operator cannot act on trains them to ignore
	// warnings.
	if found.State != HealthOK {
		t.Errorf("with no sing-box inbounds the state is %q, want ok (%s)", found.State, found.Summary)
	}
}
