package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/deploy"
)

// The settings surface must shrink with the deployment. A control the platform
// owns is removed, because a disabled control says "you are not allowed" when
// the truth is "the platform does this for you".

func TestTheSettingsRegistryDropsWhatThePlatformOwns(t *testing.T) {
	s, token := adminAPI(t)

	// A plain server: everything the panel knows about is offered.
	code, body := doGET(t, s, "/api/admin/settings/registry", token)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if !strings.Contains(body, "net_tune_bbr") {
		t.Fatal("a plain server should offer kernel tuning")
	}
	if !strings.Contains(body, "public_address") {
		t.Fatal("a plain server should offer a public address")
	}

	// The same panel on Railway: the platform owns the host and the hostname.
	s.cfg = config.WithPaaSForTest(config.PaaS{
		Enabled: true, Platform: "railway", Domain: "x.up.railway.app",
	})
	code, body = doGET(t, s, "/api/admin/settings/registry", token)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if strings.Contains(body, "net_tune_bbr") {
		t.Error("kernel tuning is offered inside a container that cannot change sysctls")
	}
	if strings.Contains(body, "public_address") {
		t.Error("a public address is offered where the platform assigns the hostname")
	}
	// Settings that still apply must survive; over-filtering is the other failure.
	if !strings.Contains(body, "sub_routing_preset") {
		t.Error("subscription settings were filtered out; they apply everywhere")
	}
}

func TestDeploymentEndpointExplainsEveryHiddenSection(t *testing.T) {
	s, token := adminAPI(t)
	s.cfg = config.WithPaaSForTest(config.PaaS{Enabled: true, Platform: "railway"})

	code, body := doGET(t, s, "/api/admin/deployment", token)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var res struct {
		Surface        deploy.Surface    `json:"surface"`
		HiddenSections map[string]string `json:"hidden_sections"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Surface.Kind != "paas" || res.Surface.Platform != "railway" {
		t.Fatalf("surface = %+v", res.Surface)
	}
	for _, want := range []string{"certs", "domains", "system"} {
		why, ok := res.HiddenSections[want]
		if !ok {
			t.Errorf("section %q should be hidden on Railway", want)
			continue
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("section %q hidden with no explanation", want)
		}
	}
	if _, hidden := res.HiddenSections["nodes"]; hidden {
		t.Error("remote node management should survive; it is why a panel is useful there")
	}
}

func TestAPlainServerHidesNothing(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/admin/deployment", token)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var res struct {
		Surface        deploy.Surface    `json:"surface"`
		HiddenSections map[string]string `json:"hidden_sections"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Surface.Kind != "vps" {
		t.Errorf("kind = %q, want vps", res.Surface.Kind)
	}
	if len(res.HiddenSections) != 0 {
		t.Errorf("a server the operator owns should hide nothing, got %v", res.HiddenSections)
	}
}
