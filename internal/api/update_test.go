package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgepanel/forgepanel/internal/update"
	"github.com/gin-gonic/gin"
)

// githubReleaseStub serves the two GitHub endpoints the update check can reach,
// so the channel the handler picked is observable from the tag it comes back
// with. /releases/latest can never carry a prerelease — that is what makes this
// distinguishable at all.
func githubReleaseStub(t *testing.T) *httptest.Server {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/repos/paranoideveloper/forgepanel/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","assets":[]}`))
		case "/repos/paranoideveloper/forgepanel/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0-rc1","prerelease":true,"assets":[]},` +
				`{"tag_name":"v1.0.0","assets":[]}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(gh.Close)
	old := update.GitHubAPIBase
	update.GitHubAPIBase = gh.URL
	t.Cleanup(func() { update.GitHubAPIBase = old })
	return gh
}

// The check is driven through the REAL server — real route table, real authz
// chain — because the failure this row exists to prevent is a handler that
// works and is mounted nowhere. A test that assembled its own gin.Engine would
// pass with the routes deleted.
func TestPanelUpdateCheckHonoursTheChannel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)
	githubReleaseStub(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/update?channel=prerelease", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("update check: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Current         string `json:"current"`
		Latest          string `json:"latest"`
		UpdateAvailable bool   `json:"update_available"`
		Channel         string `json:"channel"`
		ApplyHint       string `json:"apply_hint"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	if got.Latest != "v2.0.0-rc1" {
		t.Errorf("latest = %q, want the prerelease tag — the stable endpoint was queried instead", got.Latest)
	}
	if !got.UpdateAvailable {
		t.Errorf("update_available = false for %q over %q", got.Latest, got.Current)
	}
	if got.Channel != "prerelease" {
		t.Errorf("channel = %q, want the one the request asked for", got.Channel)
	}
	// Applying is still forgectl's job (ProtectSystem=full). The operator has to
	// be told that in the response, or the UI invents a button that cannot work.
	if got.ApplyHint == "" {
		t.Errorf("apply_hint is empty: nothing tells the operator how to apply the update")
	}
}

// The channel is a stored setting, not just a query parameter: with no explicit
// channel the check must follow what the operator chose, and the only writer of
// that setting is this route.
func TestPanelUpdateChannelIsStoredAndThenHonoured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)
	githubReleaseStub(t)

	if code, body := realPost(t, s, "/api/admin/update/channel",
		token, map[string]any{"channel": "prerelease"}); code != http.StatusOK {
		t.Fatalf("set channel: %d %s", code, body)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/update", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update check: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Latest  string `json:"latest"`
		Channel string `json:"channel"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	if got.Channel != "prerelease" || got.Latest != "v2.0.0-rc1" {
		t.Errorf("channel=%q latest=%q: the stored update_channel was not used", got.Channel, got.Latest)
	}
}

// The enum validator lives in the settings registry; the route must surface its
// refusal rather than storing a channel no release lookup knows how to use.
func TestPanelUpdateChannelRefusesAnUnknownChannel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, _, token := createComprehensiveTestServer(t)

	code, body := realPost(t, s, "/api/admin/update/channel", token, map[string]any{"channel": "nightly"})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown channel: %d %s, want 400", code, body)
	}
	var env struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal([]byte(body), &env)
	if env.Kind != "validation" {
		t.Errorf("refusal kind = %q, want validation (an ad-hoc error body has no kind)", env.Kind)
	}
}
