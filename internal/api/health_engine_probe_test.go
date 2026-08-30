package api

// A core that is up but answering nothing used to fall through BOTH buckets of
// the engine health check: not "running", not "crashed", so running==0 and
// failed==0, and the panel told the operator "No engine is running yet — add an
// inbound to start one" for a box that was wedged and serving nobody. The gap
// was reported as its own opposite.

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core/supervisor"
)

func TestAnUnresponsiveEngineIsCritical(t *testing.T) {
	sub := engineHealthFrom([]supervisor.Status{{
		Engine: "xray", State: supervisor.StateUnresponsive,
		LastError: "not answering its API: connection refused",
	}})
	if sub.State != HealthCritical {
		t.Errorf("state = %q, want %q — a wedged engine is serving nobody", sub.State, HealthCritical)
	}
	if !strings.Contains(sub.Detail, "connection refused") {
		t.Errorf("detail = %q, want the probe error the operator needs", sub.Detail)
	}
}
