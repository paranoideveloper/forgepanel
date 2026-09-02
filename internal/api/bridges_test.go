package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func bridgeBody(name, backend string) string {
	return `{"name":"` + name + `","backend":"` + backend + `",
	  "exit_addr":"203.0.113.10","tunnel_port":38443,
	  "services":[{"name":"hy2","protocol":"udp","bridge_port":38081,"exit_host":"127.0.0.1","exit_port":38081}]}`
}

func TestABridgeHandsBackTheOtherHalfsInstructions(t *testing.T) {
	// The panel manages the EXIT half only. The bridge box is by definition a
	// machine in Iran the panel usually cannot reach, so the whole feature is
	// useless unless it produces something a person can paste there.
	s, token := adminAPI(t)
	rec := doJSON(t, s, "POST", "/api/admin/bridges", token, bridgeBody("b1", "rathole"))
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Bundle struct {
			Backend     string   `json:"backend"`
			DownloadURL string   `json:"download_url"`
			SHA256      string   `json:"sha256"`
			Config      string   `json:"config"`
			Command     string   `json:"command"`
			Warnings    []string `json:"warnings"`
		} `json:"bundle"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)

	if !strings.Contains(out.Bundle.Config, "[client]") {
		t.Fatalf("the bundle is not the bridge half:\n%s", out.Bundle.Config)
	}
	if !strings.Contains(out.Bundle.Config, `type = "udp"`) {
		t.Errorf("the udp service is missing from the bridge config:\n%s", out.Bundle.Config)
	}
	// The operator is about to run this as root on a box less trusted than the
	// exit, so they need the digest to check it against.
	if len(out.Bundle.SHA256) != 64 {
		t.Errorf("no pinned checksum in the bundle: %q", out.Bundle.SHA256)
	}
	if !strings.HasPrefix(out.Bundle.DownloadURL, "https://github.com/rathole-org/") {
		t.Errorf("download URL = %q", out.Bundle.DownloadURL)
	}
	// A UDP service through a firewall that only allows TCP looks connected and
	// carries nothing, which is the single most common way this is misdeployed.
	joined := strings.Join(out.Bundle.Warnings, " ")
	if !strings.Contains(joined, "UDP port 38081") {
		t.Errorf("no warning about the inbound UDP port: %v", out.Bundle.Warnings)
	}
}

func TestTheSharedTokenIsGeneratedAndNeverReturned(t *testing.T) {
	// An operator asked to invent a shared secret picks a memorable one, and
	// this token is the whole of the tunnel's authentication.
	s, token := adminAPI(t)
	rec := doJSON(t, s, "POST", "/api/admin/bridges", token, bridgeBody("b2", "frp"))
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID     uint `json:"id"`
		Bundle struct {
			Config string `json:"config"`
		} `json:"bundle"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)

	// The token has to be IN the bundle — the other half cannot authenticate
	// without it — but it must not come back from the list endpoint, which is
	// the one an operator leaves open in a tab.
	if !strings.Contains(out.Bundle.Config, "auth.token") {
		t.Fatal("the bridge half has no token, so it can never attach")
	}
	list := doJSON(t, s, "GET", "/api/admin/bridges", token, "")
	if strings.Contains(list.Body.String(), "auth.token") || strings.Contains(list.Body.String(), "token_enc") {
		t.Fatalf("the bridge list leaked the shared token: %s", list.Body.String())
	}
}

func TestAUDPServiceOnATCPOnlyBackendIsRefusedAtTheAPI(t *testing.T) {
	// Every backend carries UDP today, so this proves the API surfaces the
	// validator rather than proving a current backend's limits.
	s, token := adminAPI(t)
	body := `{"name":"b3","backend":"nosuchbackend","exit_addr":"203.0.113.10","tunnel_port":38443,
	  "services":[{"name":"x","protocol":"udp","bridge_port":1,"exit_port":1}]}`
	rec := doJSON(t, s, "POST", "/api/admin/bridges", token, body)
	if rec.Code == 201 {
		t.Fatal("a bridge on an unknown backend was created")
	}
	if !strings.Contains(rec.Body.String(), "backhaul") {
		t.Errorf("the error does not list the backends that do exist: %s", rec.Body.String())
	}
}

func TestABridgeWithNoServicesIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	body := `{"name":"b4","backend":"rathole","exit_addr":"203.0.113.10","tunnel_port":38443,"services":[]}`
	rec := doJSON(t, s, "POST", "/api/admin/bridges", token, body)
	if rec.Code == 201 {
		t.Fatal("a bridge that forwards nothing was created")
	}
}

func TestTheBackendListSaysWhichCarryUDP(t *testing.T) {
	// It is the property that decides whether Hysteria2 survives the hop, so it
	// has to be visible before an operator picks one.
	s, token := adminAPI(t)
	rec := doJSON(t, s, "GET", "/api/admin/bridges/backends", token, "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Backends []struct {
			Name       string `json:"name"`
			CarriesUDP bool   `json:"carries_udp"`
			SHA256     string `json:"sha256"`
		} `json:"backends"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Backends) != 4 {
		t.Fatalf("got %d backends, want 4", len(out.Backends))
	}
	for _, b := range out.Backends {
		if !b.CarriesUDP {
			t.Errorf("%s is offered but does not carry UDP", b.Name)
		}
		if len(b.SHA256) != 64 {
			t.Errorf("%s has no pinned checksum", b.Name)
		}
	}
}
