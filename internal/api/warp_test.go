package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	warppkg "github.com/forgepanel/forgepanel/internal/warp"
)

// A mock WARP API. The real one is Cloudflare's and registering against it in a
// test would mint a real device on every run.
func mockWarp(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/account") {
			// Flat, as Cloudflare answers a license update.
			_, _ = w.Write([]byte(`{"id":"dev-1","warp_plus":true,"premium_data":1,"quota":1,"role":"child"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"dev-1","token":"tok-1",
			"config":{"client_id":"AQID",
			  "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8::1"}},
			  "peers":[{"public_key":"PEERPUB"}]},
			"account":{"warp_plus":false,"premium_data":0}}`))
	}))
	old, oldPause := warppkg.RegBase, warppkg.RegPause
	warppkg.RegBase, warppkg.RegPause = srv.URL+"/v0a4005/reg", 0
	t.Cleanup(func() {
		warppkg.RegBase, warppkg.RegPause = old, oldPause
		srv.Close()
	})
	return srv
}

func warpStatus(t *testing.T, s *Server, token string) warpStatusView {
	t.Helper()
	code, body := doGET(t, s, "/api/admin/routing/warp", token)
	if code != 200 {
		t.Fatalf("warp status: %d %s", code, body)
	}
	var v warpStatusView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Provisioning has to leave BOTH halves in place: an account the panel
// remembers, and an outbound a routing rule can actually name. They come apart
// easily, and an account with no outbound looks configured while routing
// nothing.
func TestProvisioningWarpCreatesARoutableOutbound(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)

	code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`)
	if code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	st := warpStatus(t, s, token)
	if !st.Configured || !st.OutboundExists {
		t.Fatalf("status after provisioning = %+v, want both an account and an outbound", st)
	}

	ob := s.warpOutbound()
	if ob == nil {
		t.Fatal("no warp outbound row")
	}
	if ob.Protocol != "wireguard" {
		t.Errorf("protocol = %q", ob.Protocol)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(ob.Settings), &settings); err != nil {
		t.Fatalf("settings are not valid JSON: %v", err)
	}
	// The three reserved bytes are what make Cloudflare accept the session. An
	// outbound without them handshakes and then carries nothing, which is the
	// failure this whole feature exists to avoid shipping.
	r, ok := settings["reserved"].([]any)
	if !ok || len(r) != 3 {
		t.Fatalf("settings.reserved = %v, want three decoded bytes", settings["reserved"])
	}
	if settings["secretKey"] == "" || settings["secretKey"] == nil {
		t.Error("settings carry no secretKey, so the outbound cannot authenticate")
	}
}

// The secrets must not come back out. The account holds a WireGuard private key
// and a bearer token that can rebind the device.
func TestWarpStatusNeverReturnsTheAccountSecrets(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	acct, ok := s.storedWarpAccount()
	if !ok || acct.Token == "" || acct.PrivateKey == "" {
		t.Fatal("expected a stored account with a token and a private key")
	}

	_, body := doGET(t, s, "/api/admin/routing/warp", token)
	for _, secret := range []string{acct.Token, acct.PrivateKey, acct.DeviceID} {
		if secret != "" && strings.Contains(body, secret) {
			t.Errorf("the status response contains a secret (%q): %s", secret, body)
		}
	}
	// And the settings registry must not list it either, which is the reason it
	// is stored under a raw key rather than a registered def.
	_, reg := doGET(t, s, "/api/admin/settings/registry", token)
	if strings.Contains(reg, acct.PrivateKey) || strings.Contains(reg, warpAccountKey) {
		t.Errorf("the settings registry exposes the WARP account: %s", reg)
	}
}

func TestWarpLicenseActivationIsReported(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{"license":"KEY"}`)
	if code != 200 {
		t.Fatalf("provision with license: %d %s", code, body)
	}
	if st := warpStatus(t, s, token); !st.Premium {
		t.Errorf("status = %+v, want Premium after a successful activation", st)
	}
}

// Re-provisioning to attach a license must not mint a new device: the license
// binds to the device, and a silent re-registration strands it.
func TestReprovisioningKeepsTheSameDeviceUnlessAsked(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	first, _ := s.storedWarpAccount()

	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{"license":"KEY"}`); code != 200 {
		t.Fatalf("second provision: %d %s", code, body)
	}
	second, _ := s.storedWarpAccount()
	if second.PrivateKey != first.PrivateKey {
		t.Error("provisioning again minted a new device, which strands any license bound to the old one")
	}

	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{"reregister":true}`); code != 200 {
		t.Fatalf("reregister: %d %s", code, body)
	}
	if third, _ := s.storedWarpAccount(); third.PrivateKey == first.PrivateKey {
		t.Error("reregister:true did not mint a new device")
	}
}

func TestRotatingWarpChangesTheEndpointAndTheOutbound(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	before := s.warpOutbound()
	beforeSettings := string(before.Settings)

	code, body := doPOST(t, s, "/api/admin/routing/warp/rotate", token, `{}`)
	if code != 200 {
		t.Fatalf("rotate: %d %s", code, body)
	}
	after := s.warpOutbound()
	if after == nil {
		t.Fatal("rotation removed the outbound")
	}
	if string(after.Settings) == beforeSettings {
		t.Error("rotation left the rendered endpoint unchanged, so the outbound still dials the old address")
	}
	if after.ID != before.ID {
		t.Errorf("rotation replaced the row (%d -> %d); a rule naming it by id would be orphaned", before.ID, after.ID)
	}
}

// Rotation must preserve the operator's own choices on the row. SortOrder in
// particular decides which outbound is the core's default for unmatched
// traffic, so resetting it moves traffic nobody asked to move.
func TestRotationPreservesSortOrderAndEnabled(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	ob := s.warpOutbound()
	ob.SortOrder = 7
	ob.Enabled = false
	ob.Note = "operator's own note"
	if err := s.db.SaveOutbound(ob); err != nil {
		t.Fatal(err)
	}

	if code, body := doPOST(t, s, "/api/admin/routing/warp/rotate", token, `{}`); code != 200 {
		t.Fatalf("rotate: %d %s", code, body)
	}
	after := s.warpOutbound()
	if after.SortOrder != 7 {
		t.Errorf("SortOrder = %d, want 7 kept — it decides the core's default outbound", after.SortOrder)
	}
	if after.Enabled {
		t.Error("rotation re-enabled an outbound the operator had disabled")
	}
	if after.Note != "operator's own note" {
		t.Errorf("Note = %q, want the operator's own kept", after.Note)
	}
}

func TestRotatingWithNoAccountIs404(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := doPOST(t, s, "/api/admin/routing/warp/rotate", token, `{}`); code != http.StatusNotFound {
		t.Errorf("rotate with no account = %d, want 404", code)
	}
}

func TestDeletingWarpRemovesBothHalves(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/routing/warp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if s.warpOutbound() != nil {
		t.Error("the outbound survived the delete")
	}
	if _, ok := s.storedWarpAccount(); ok {
		t.Error("the account survived the delete, so status still reports it configured")
	}
}

// The scheduled half. It runs off the maintenance sweep, so what matters is
// that it does nothing until its own interval has passed — a rotator that fires
// every sweep would change the exit address every few seconds.
func TestScheduledRotationWaitsForItsInterval(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{"rotate_hours":6}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	before := string(s.warpOutbound().Settings)

	s.rotateWarpIfDue()
	if string(s.warpOutbound().Settings) != before {
		t.Fatal("rotated immediately after provisioning, six hours early")
	}

	// Wind the clock back past the interval.
	acct, _ := s.storedWarpAccount()
	acct.RotatedAt = time.Now().Add(-7 * time.Hour)
	s.persistWarp(acct)

	s.rotateWarpIfDue()
	if string(s.warpOutbound().Settings) == before {
		t.Error("the interval had passed and nothing rotated")
	}
}

func TestScheduledRotationIsOffByDefault(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	acct, _ := s.storedWarpAccount()
	acct.RotatedAt = time.Now().Add(-100 * time.Hour)
	s.persistWarp(acct)
	before := string(s.warpOutbound().Settings)

	s.rotateWarpIfDue()
	if string(s.warpOutbound().Settings) != before {
		t.Error("rotation happened with no cadence configured; it must be opt-in")
	}
}

// Enabling a schedule is a request for a cadence, not for a change right now.
func TestEnablingRotationOnAnOlderAccountDoesNotRotateImmediately(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	// An account provisioned before rotation existed has no RotatedAt at all.
	acct, _ := s.storedWarpAccount()
	acct.RotatedAt = time.Time{}
	s.persistWarp(acct)
	if err := s.knobs().Set(warpRotateKey, "6"); err != nil {
		t.Fatal(err)
	}
	before := string(s.warpOutbound().Settings)

	s.rotateWarpIfDue()
	if string(s.warpOutbound().Settings) != before {
		t.Error("switching rotation on immediately changed the endpoint")
	}
	if a, _ := s.storedWarpAccount(); a.RotatedAt.IsZero() {
		t.Error("the clock was not started, so the schedule can never come due")
	}
}

func TestWarpRotateIntervalRejectsNonsense(t *testing.T) {
	for _, raw := range []string{"", "0", "-3", "six", "1.5", " "} {
		if got := warpRotateInterval(raw); got != 0 {
			t.Errorf("warpRotateInterval(%q) = %v, want rotation disabled", raw, got)
		}
	}
	if got := warpRotateInterval(" 6 "); got != 6*time.Hour {
		t.Errorf("warpRotateInterval(\" 6 \") = %v", got)
	}
}

// A guard on the scope note at the top of warp.go: operator outbounds are
// rendered into the Xray config only. If sing-box ever starts consuming them,
// the WARP settings blob stored here is the wrong shape for it (secretKey vs
// private_key) and this test should fail rather than the tunnel silently not
// carrying.
func TestTheProvisionedOutboundIsTheXrayShape(t *testing.T) {
	s, token := adminAPI(t)
	mockWarp(t)
	if code, body := doPOST(t, s, "/api/admin/routing/warp", token, `{}`); code != 200 {
		t.Fatalf("provision: %d %s", code, body)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(s.warpOutbound().Settings), &settings); err != nil {
		t.Fatal(err)
	}
	if _, ok := settings["secretKey"]; !ok {
		t.Error("no secretKey: the stored blob is not Xray's WireGuard shape")
	}
	if _, ok := settings["private_key"]; ok {
		t.Error("private_key present: this is sing-box's shape, which the Xray config will not accept")
	}
}
