package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The egress test button was a working internal port scanner: it HEADs whatever
// the operator types and reports reachable / unreachable / 5xx as three
// distinguishable answers. Owning the panel does not imply owning the machine's
// private network, so a target that is not public unicast has to be refused
// before the dial — and refused as a VALIDATION error, not as the 502 the
// handler uses for "your proxy is broken", or the operator is told to go and
// fix a proxy that is working fine.
func TestTestingEgressAgainstAnInternalAddressIsRefusedAsAValidationError(t *testing.T) {
	s, token := adminAPI(t)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	defer srv.Close()

	code, body := realPost(t, s, "/api/admin/settings/egress/test", token, map[string]any{
		"target": srv.URL,
	})
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("the egress test reached the internal listener %d time(s): it is a port scanner", got)
	}
	if code != http.StatusBadRequest {
		t.Fatalf("an internal target answered %d, want 400: %s", code, body)
	}
	// The classification, not just the number: apierr.IsTyped is what lets the
	// guard's own status survive the handler's 502 fallback.
	if !strings.Contains(body, `"kind":"validation"`) {
		t.Fatalf("the refusal is not classified as a validation error: %s", body)
	}
	if !strings.Contains(body, "remediation") {
		t.Fatalf("the refusal does not say what to do instead: %s", body)
	}
}
