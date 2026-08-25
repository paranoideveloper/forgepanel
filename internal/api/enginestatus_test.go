package api

import (
	"encoding/json"
	"testing"
)

// Controller.BrookStatus, AWGStatus and AWGKernelStatus were implemented and
// tested and had NO HTTP ROUTE, so an operator running Brook or AmneziaWG saw an
// engines list that did not mention them at all — and had no way to discover
// that the AmneziaWG kernel module was missing, which is a property of the host
// that no amount of correct configuration fixes.

func TestAuxEngineStatusIsReachable(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/admin/engines/aux", token)
	if code != 200 {
		t.Fatalf("%d: %s — the status functions have no route again", code, body)
	}
	var res struct {
		Brook           []map[string]any `json:"brook"`
		AmneziaWG       []map[string]any `json:"amneziawg"`
		AmneziaWGKernel map[string]any   `json:"amneziawg_kernel"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("response is not the documented shape: %v: %s", err, body)
	}
	// Nil slices serialise as null, which every consumer then special-cases.
	if res.Brook == nil || res.AmneziaWG == nil {
		t.Errorf("a list came back null rather than empty: %s", body)
	}
	// The kernel check must be present even when nothing is configured: "is the
	// module loaded" is exactly what an operator needs BEFORE their first
	// AmneziaWG inbound, not after.
	if res.AmneziaWGKernel == nil {
		t.Errorf("no kernel-readiness report: %s", body)
	}
}

func TestAuxEngineStatusNeedsAuth(t *testing.T) {
	s, _ := adminAPI(t)
	if code, _ := doGET(t, s, "/api/admin/engines/aux", ""); code != 401 {
		t.Fatalf("unauthenticated request returned %d, want 401", code)
	}
}
