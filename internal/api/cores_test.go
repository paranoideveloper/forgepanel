package api

// Operator-selectable core versions (FP-ADAPT-014).
//
// The failure these guard against is the one this codebase keeps producing: a
// handler that writes a row, a GET that reads it back, and a supervisor that
// goes on exec'ing the version compiled into the binary. Every assertion below
// is about the SUPERVISOR's resolved path, not about what the API echoes.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/store"
)

// coreTestServer builds a panel around a real store in dir. It deliberately
// creates NO inbound: s.Close waits on the background group, and a reload with
// an inbound would send ensureBinariesFor at a real 60 MB download.
func coreTestServer(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	oldListeners := hostListeners
	hostListeners = func() []firewall.Listener { return nil }
	t.Cleanup(func() { hostListeners = oldListeners })

	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.DataDir = dir

	s, err := NewWithStore(cfg)
	if err != nil {
		t.Fatalf("NewWithStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Reused across a restart in TestStoredPinsAreAppliedOnTheNextBoot, so the
	// owner may already be in the database this boot opened.
	admin, err := s.db.AdminByUsername("owner")
	if err != nil {
		admin = &store.Admin{Username: "owner", PasswordHash: "x", Role: store.RoleOwner}
		if err := s.db.CreateAdmin(admin); err != nil {
			t.Fatalf("CreateAdmin: %v", err)
		}
	}
	token, _, err := s.signer.Issue(admin.ID, admin.Username, string(admin.Role))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return s, token
}

func corePost(t *testing.T, s *Server, token, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func hostXrayAsset(t *testing.T, ver string) string {
	t.Helper()
	asset, err := binmgr.HostAssetName(binmgr.EngineXray, ver)
	if err != nil {
		t.Skipf("no Xray asset for this host: %v", err)
	}
	return asset
}

func TestPinningACoreReachesTheRunningSupervisor(t *testing.T) {
	s, token := coreTestServer(t, t.TempDir())
	asset := hostXrayAsset(t, "v25.1.1")

	before := s.engine.Bins().Path(binmgr.EngineXray)
	body := `{"version":"v25.1.1","sha256":{"` + asset + `":"` + strings.Repeat("a", 64) + `"}}`
	if rec := corePost(t, s, token, "/api/admin/cores/xray/pin", body); rec.Code != 200 {
		t.Fatalf("pin: %d %s", rec.Code, rec.Body.String())
	}

	after := s.engine.Bins().Path(binmgr.EngineXray)
	if !strings.Contains(after, "xray-v25.1.1") {
		t.Fatalf("the pin never reached the supervisor: Path %q -> %q", before, after)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/cores", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"pinned":"v25.1.1"`) {
		t.Fatalf("GET /cores does not report the pin: %s", rec.Body.String())
	}
}

// A pin with no digest for this host's asset must be refused BEFORE anything is
// stored: the checksum mandate is the only thing standing between an operator
// typo and an unverified proxy core.
func TestPinningWithoutADigestIsRefusedAndStoresNothing(t *testing.T) {
	s, token := coreTestServer(t, t.TempDir())
	hostXrayAsset(t, "v25.1.1") // skip on a platform with no Xray build

	before := s.engine.Bins().Path(binmgr.EngineXray)
	rec := corePost(t, s, token, "/api/admin/cores/xray/pin", `{"version":"v25.1.1","sha256":{}}`)
	if rec.Code != 400 {
		t.Fatalf("pin with no digest: %d %s", rec.Code, rec.Body.String())
	}
	if after := s.engine.Bins().Path(binmgr.EngineXray); after != before {
		t.Fatalf("a refused pin still moved the supervisor: %q -> %q", before, after)
	}
	if v := s.knobs().String("core_version_xray"); v != "" {
		t.Fatalf("a refused pin was persisted anyway: core_version_xray = %q", v)
	}
}

func TestRollbackReturnsTheSupervisorToThePreviousVersion(t *testing.T) {
	s, token := coreTestServer(t, t.TempDir())
	asset := hostXrayAsset(t, "v25.1.1")
	shipped := s.engine.Bins().Path(binmgr.EngineXray)

	body := `{"version":"v25.1.1","sha256":{"` + asset + `":"` + strings.Repeat("a", 64) + `"}}`
	if rec := corePost(t, s, token, "/api/admin/cores/xray/pin", body); rec.Code != 200 {
		t.Fatalf("pin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := corePost(t, s, token, "/api/admin/cores/xray/rollback", ""); rec.Code != 200 {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	if got := s.engine.Bins().Path(binmgr.EngineXray); got != shipped {
		t.Fatalf("rollback did not return the supervisor to %q; it is on %q", shipped, got)
	}
}

// WIRING: the pin has to survive a restart. Without applyStoredCorePins in
// NewWithStore the rows are written, the API reports them, and the next boot
// silently execs the compiled version again.
func TestStoredPinsAreAppliedOnTheNextBoot(t *testing.T) {
	dir := t.TempDir()
	s, token := coreTestServer(t, dir)
	asset := hostXrayAsset(t, "v25.1.1")

	body := `{"version":"v25.1.1","sha256":{"` + asset + `":"` + strings.Repeat("a", 64) + `"}}`
	if rec := corePost(t, s, token, "/api/admin/cores/xray/pin", body); rec.Code != 200 {
		t.Fatalf("pin: %d %s", rec.Code, rec.Body.String())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, _ := coreTestServer(t, dir)
	if got := s2.engine.Bins().Path(binmgr.EngineXray); !strings.Contains(got, "xray-v25.1.1") {
		t.Fatalf("a stored pin was not applied on boot: Path = %q", got)
	}
}
