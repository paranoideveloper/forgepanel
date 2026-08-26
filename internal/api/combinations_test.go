package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The matrix must agree with the validator on every triple, because the whole
// point is that a greyed-out option and a rejected save are the same decision.
// It is derived by running Validate, so this checks the derivation did not get
// replaced by a table somebody typed out.
func TestTheCombinationMatrixAgreesWithTheValidator(t *testing.T) {
	m := combinationMatrix()
	if len(m) < 20 {
		t.Fatalf("only %d combinations — the walk is broken, not the matrix", len(m))
	}
	for _, c := range m {
		n := &model.Node{Protocol: model.Protocol(c.Protocol), Address: "example.com", Port: 443}
		if c.Transport != "" {
			n.Transport = model.Transport{Network: model.Network(c.Transport)}
		}
		if c.Security != "" {
			n.Security = model.Security{Type: model.SecurityType(c.Security)}
		}
		applyCreateDefaults(n)
		err := n.Validate()
		if (err == nil) != c.Supported {
			t.Errorf("%s/%s/%s: matrix says supported=%v, the validator says %v",
				c.Protocol, c.Transport, c.Security, c.Supported, err)
		}
		if !c.Supported && c.Reason == "" {
			t.Errorf("%s/%s/%s is unsupported with no reason; the form would grey out an option and not say why",
				c.Protocol, c.Transport, c.Security)
		}
	}
}

// The specific combination that made this worth building. REALITY over
// WebSocket renders perfectly, reads plausibly, and the core refuses it.
func TestRealityOverWebsocketIsReportedUnsupported(t *testing.T) {
	var found bool
	for _, c := range combinationMatrix() {
		if c.Protocol == "vless" && c.Transport == "ws" && c.Security == "reality" {
			found = true
			if c.Supported {
				t.Error("REALITY over ws is reported as supported; the core rejects it")
			}
			if !strings.Contains(c.Reason, "REALITY") {
				t.Errorf("reason = %q, want the validator's own message", c.Reason)
			}
		}
	}
	if !found {
		t.Error("vless/ws/reality is not in the matrix at all, so the form has nothing to grey out")
	}
}

// And a combination that DOES work must not be reported as blocked. A matrix
// that says no to everything greys out the whole dropdown and is worse than no
// matrix at all.
func TestWorkingCombinationsAreNotBlocked(t *testing.T) {
	want := map[string]bool{"vless/tcp/reality": false, "vless/ws/tls": false, "vless/xhttp/reality": false}
	for _, c := range combinationMatrix() {
		k := c.Protocol + "/" + c.Transport + "/" + c.Security
		if _, ok := want[k]; ok {
			want[k] = true
			if !c.Supported {
				t.Errorf("%s is reported unsupported: %s", k, c.Reason)
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("%s is missing from the matrix", k)
		}
	}
}

// It has to reach the UI, not just exist.
func TestCapabilitiesServesTheCombinationMatrix(t *testing.T) {
	s, token := adminAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/capabilities", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Combinations []Combination `json:"combinations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Combinations) == 0 {
		t.Fatal("the capability report carries no combinations, so the builder has nothing to grey out")
	}
}
