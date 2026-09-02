package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// porthop.Conflicts was written, correct, and called by nothing. It answers the
// one question that makes port hopping DANGEROUS rather than merely ineffective:
// does this range contain a port another inbound is listening on? If it does,
// the firewall redirect captures that traffic and sends it to the wrong
// listener — and the inbound that breaks is not the one the operator is editing.

func addInbound(t *testing.T, s *Server, remark string, port int) *store.Inbound {
	t.Helper()
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: port,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: remark}
	n.Normalize()
	in, err := s.db.CreateInbound(n)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// doPUT posts a raw JSON body with PUT, which the shared map-based helper
// cannot express for these nested documents.
func doPUT(t *testing.T, s *Server, path, token, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func hy2(port int, hop string) string {
	return fmt.Sprintf(
		`{"protocol":"hysteria2","address":"0.0.0.0","port":%d,"remark":"hopper","password":"pw",`+
			`"hysteria2":{"port_hopping":%q}}`, port, hop)
}

func TestARangeThatSwallowsAnotherInboundIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	addInbound(t, s, "victim", 30000)

	code, body := doPOST(t, s, "/api/admin/inbounds", token, hy2(8443, "20000-50000"))
	if code == 200 || code == 201 {
		t.Fatalf("a hop range covering another inbound's port was accepted (%d): "+
			"that inbound's traffic would be silently rerouted", code)
	}
	if code != 409 {
		t.Errorf("status = %d, want 409 Conflict", code)
	}
	// Naming the port is not enough — the panel knows which inbound it is, and
	// making the operator go and find out is work it can do for them.
	if !strings.Contains(body, "30000") || !strings.Contains(body, "victim") {
		t.Errorf("the refusal does not name the affected inbound: %s", body)
	}
}

func TestANonOverlappingRangeIsAccepted(t *testing.T) {
	s, token := adminAPI(t)
	addInbound(t, s, "elsewhere", 443)

	code, body := doPOST(t, s, "/api/admin/inbounds", token, hy2(8443, "20000-25000"))
	if code != 200 && code != 201 {
		t.Fatalf("a range that overlaps nothing was refused: %d %s", code, body)
	}
}

func TestTheListenerPortItselfIsNotAConflict(t *testing.T) {
	s, token := adminAPI(t)
	// The listener sits INSIDE its own range: that is where the redirect sends
	// traffic, so it is the normal arrangement, not a collision.
	code, body := doPOST(t, s, "/api/admin/inbounds", token, hy2(30000, "20000-50000"))
	if code != 200 && code != 201 {
		t.Fatalf("an inbound listening inside its own hop range was refused: %d %s", code, body)
	}
}

func TestADisabledInboundDoesNotBlockARange(t *testing.T) {
	s, token := adminAPI(t)
	in := addInbound(t, s, "switched-off", 30000)
	if err := s.db.UpdateInboundFields(in.ID, map[string]any{"enabled": false}); err != nil {
		t.Fatal(err)
	}
	// A disabled inbound is not listening, so nothing of its can be captured.
	// Blocking on it would make an operator delete a row to reuse a range.
	code, body := doPOST(t, s, "/api/admin/inbounds", token, hy2(8443, "20000-50000"))
	if code != 200 && code != 201 {
		t.Fatalf("a disabled inbound blocked a hop range: %d %s", code, body)
	}
}

func TestEditingAHoppingInboundDoesNotConflictWithItself(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/inbounds", token, hy2(30000, "20000-40000"))
	if code != 200 && code != 201 {
		t.Fatalf("setup: %d %s", code, body)
	}
	var id uint
	list, _ := s.db.ListInbounds()
	for _, in := range list {
		if in.Port == 30000 {
			id = in.ID
		}
	}
	if id == 0 {
		t.Fatal("could not find the created inbound")
	}

	// Widening its own range must not report a conflict with its own row.
	code, body = doPUT(t, s, fmt.Sprintf("/api/admin/inbounds/%d?confirm=1", id), token,
		hy2(30000, "20000-50000"))
	if code == 409 {
		t.Fatalf("editing a hopping inbound conflicted with itself: %s", body)
	}
}
