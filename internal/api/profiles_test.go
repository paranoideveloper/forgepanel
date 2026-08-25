package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// Serving one definition from ten nodes meant ten hand-made inbounds, and every
// rotation had to be repeated ten times. These cover the part that makes a
// profile trustworthy: one edit reaching every node, and nothing silently
// disagreeing afterwards.

const vlessTemplate = `{"protocol":"vless","address":"0.0.0.0","port":443,` +
	`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","remark":"tpl","security":{"type":"none"}}`

func mkProfile(t *testing.T, s *Server, token, name string) uint {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"template":%s}`, name, vlessTemplate)
	code, resp := doPOST(t, s, "/api/admin/profiles", token, body)
	if code != 200 {
		t.Fatalf("creating profile: %d %s", code, resp)
	}
	var out struct {
		Profile store.Profile `json:"profile"`
	}
	if err := json.Unmarshal([]byte(resp), &out); err != nil {
		t.Fatal(err)
	}
	return out.Profile.ID
}

func bind(t *testing.T, s *Server, token string, profileID, nodeID uint, port int, host string) {
	t.Helper()
	body := fmt.Sprintf(`{"profile_id":%d,"node_id":%d,"port":%d,"public_host":%q}`,
		profileID, nodeID, port, host)
	if code, resp := doPOST(t, s, "/api/admin/profiles/bindings", token, body); code != 200 {
		t.Fatalf("binding node %d: %d %s", nodeID, code, resp)
	}
}

func TestOneProfileMaterialisesOneInboundPerNode(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "eu-vless")
	bind(t, s, token, pid, 1, 8443, "de.example")
	bind(t, s, token, pid, 2, 9443, "nl.example")

	ins, err := s.db.ListInbounds()
	if err != nil {
		t.Fatal(err)
	}
	if len(ins) != 2 {
		t.Fatalf("inbounds = %d, want one per binding", len(ins))
	}
	// Each row says which node it serves, or the list is N identical rows and
	// nobody can tell which one is misbehaving.
	remarks := map[string]bool{}
	for _, in := range ins {
		remarks[in.Remark] = true
	}
	if len(remarks) != 2 {
		t.Fatalf("the materialised rows are not distinguishable: %v", remarks)
	}
}

func TestEditingTheProfileReachesEveryNode(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "fleet")
	bind(t, s, token, pid, 1, 8443, "a.example")
	bind(t, s, token, pid, 2, 9443, "b.example")

	// The whole point: one edit, every node. Rotate the credential.
	const newUUID = "11111111-2222-4333-8444-555555555555"
	updated := strings.Replace(vlessTemplate, "b831381d-6324-4d53-ad4f-8cda48b30811", newUUID, 1)
	code, resp := doPUT(t, s, fmt.Sprintf("/api/admin/profiles/%d", pid), token,
		fmt.Sprintf(`{"name":"fleet","template":%s}`, updated))
	if code != 200 {
		t.Fatalf("updating the profile: %d %s", code, resp)
	}

	ins, _ := s.db.ListInbounds()
	if len(ins) != 2 {
		t.Fatalf("the update changed the number of rows: %d", len(ins))
	}
	for _, in := range ins {
		n, err := in.Node()
		if err != nil {
			t.Fatal(err)
		}
		if n.UUID != newUUID {
			t.Fatalf("%s still carries the old credential; the tenth node is where the "+
				"mistake lives and this is exactly it", in.Remark)
		}
	}
}

func TestPerNodeFieldsStayPerNode(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "p")
	bind(t, s, token, pid, 1, 8443, "de.example")
	bind(t, s, token, pid, 2, 9443, "nl.example")

	ins, _ := s.db.ListInbounds()
	ports, hosts := map[int]bool{}, map[string]bool{}
	for _, in := range ins {
		n, _ := in.Node()
		ports[n.Port] = true
		hosts[n.Domain] = true
		// The public host must NOT become the listen address: the core refuses
		// to bind a hostname.
		if n.Address != "0.0.0.0" {
			t.Fatalf("%s listens on %q, not the template's bind address", in.Remark, n.Address)
		}
	}
	if len(ports) != 2 || len(hosts) != 2 {
		t.Fatalf("per-node fields collapsed: ports=%v hosts=%v", ports, hosts)
	}
}

func TestAManagedInboundRefusesDirectEdits(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "managed")
	bind(t, s, token, pid, 1, 8443, "a.example")

	ins, _ := s.db.ListInbounds()
	if len(ins) != 1 {
		t.Fatalf("setup: %d inbounds", len(ins))
	}
	code, body := doPUT(t, s, fmt.Sprintf("/api/admin/inbounds/%d?confirm=1", ins[0].ID), token,
		vlessTemplate)
	// Silently reverting somebody's work on the next sync is the worse failure:
	// they watch it succeed and find out later.
	if code != 409 {
		t.Fatalf("a profile-managed inbound accepted a direct edit (%d): %s", code, body)
	}
	if !strings.Contains(body, "profile") {
		t.Errorf("the refusal does not say where the change belongs: %s", body)
	}
}

func TestDeletingAProfileTakesItsInboundsWithIt(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "doomed")
	bind(t, s, token, pid, 1, 8443, "a.example")
	bind(t, s, token, pid, 2, 9443, "b.example")

	if code, body := doDELETE(t, s, fmt.Sprintf("/api/admin/profiles/%d", pid), token); code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	ins, _ := s.db.ListInbounds()
	// Rows left behind keep serving under a definition nothing in the panel can
	// edit as a group any more — orphans that look like ordinary inbounds.
	if len(ins) != 0 {
		t.Fatalf("%d inbound(s) outlived their profile", len(ins))
	}
}

func TestOneBadBindingFailsTheWholeSync(t *testing.T) {
	s, token := adminAPI(t)
	pid := mkProfile(t, s, token, "strict")
	bind(t, s, token, pid, 1, 8443, "a.example")

	// A port outside the valid range cannot be materialised.
	code, body := doPOST(t, s, "/api/admin/profiles/bindings", token,
		fmt.Sprintf(`{"profile_id":%d,"node_id":2,"port":70000}`, pid))
	// A partially-applied profile is a fleet where some nodes carry the new
	// definition and some carry the old — the exact inconsistency profiles exist
	// to prevent.
	if code == 200 {
		t.Fatalf("an unmaterialisable binding was accepted: %s", body)
	}
}

func TestATemplateThatCannotListenIsRefusedAtTheProfile(t *testing.T) {
	s, token := adminAPI(t)
	bad := strings.Replace(vlessTemplate, `"address":"0.0.0.0"`, `"address":"vpn.example.com"`, 1)
	code, body := doPOST(t, s, "/api/admin/profiles", token,
		fmt.Sprintf(`{"name":"bad","template":%s}`, bad))
	// Caught once, at the profile, rather than N times as an engine error on
	// every binding.
	if code == 200 {
		t.Fatalf("a template that cannot listen was accepted: %s", body)
	}
}
