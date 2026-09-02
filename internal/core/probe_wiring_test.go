package core

// The probe is worthless unless buildRegistry actually hands one to every
// supervised core. That is the single production site where adapter.Options is
// constructed, and the repository has form here: an unwired liveness check is
// exactly what internal/forgedns/upstream.CheckHealth is — complete, correct,
// and called by nothing but its own test.

import (
	"context"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func TestBuildRegistryGivesEverySupervisedCoreALivenessProbe(t *testing.T) {
	c := NewController(t.TempDir(), 20085)
	reg, err := c.buildRegistry()
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	for _, name := range []string{model.EngineXray, model.EngineSingBox} {
		a, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("no %s adapter in the registry", name)
		}
		pr, ok := a.(interface{ HasLivenessProbe() bool })
		if !ok || !pr.HasLivenessProbe() {
			t.Errorf("the %s adapter was built with no liveness probe: a wedged core would be "+
				"supervised forever as 'running'", name)
		}
	}
}

// The xray probe must FAIL when nothing is listening, or it reports every core
// healthy and the supervisor never restarts anything.
func TestXrayProbeFailsWhenTheAPIIsNotThere(t *testing.T) {
	c := NewController(t.TempDir(), 1) // port 1: nothing listens, and the binary is absent too
	if err := c.probeXrayAPI(context.Background()); err == nil {
		t.Error("probeXrayAPI returned nil against a core that is not running")
	}
}

// The sing-box probe must SKIP, not fail, on a stock binary. The official
// archives are built without with_v2ray_api, so treating "no stats API" as
// "unresponsive" would put every stock install into a restart loop.
func TestSingboxProbeSkipsWhenTheBinaryHasNoStatsAPI(t *testing.T) {
	c := NewController(t.TempDir(), 20085)
	if c.SingboxStatsSupported().Supported {
		t.Skip("this host's sing-box reports stats support; the skip path cannot be exercised")
	}
	if err := c.probeSingboxAPI(context.Background()); err != nil {
		t.Errorf("probeSingboxAPI = %v, want nil: a core with no stats API is unmeterable, not wedged", err)
	}
}
