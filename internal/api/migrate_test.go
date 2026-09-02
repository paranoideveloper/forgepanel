package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// The importer read a foreign panel's database and PRINTED JSON. Nothing was
// written, so "migrate from 3x-ui" meant reading the output and re-typing it.
//
// These build a REAL SQLite database in the foreign panel's own table shape,
// rather than mocking the reader. A migration that works against a hand-made
// struct and not against a real file is worth nothing on the day it is needed.

type fixtureInbound struct {
	remark, protocol, settings, stream string
	port                               int
}

func foreignPanelDB(t *testing.T, rows ...fixtureInbound) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x-ui.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE inbounds (
		id INTEGER PRIMARY KEY, remark TEXT, port INTEGER,
		protocol TEXT, settings TEXT, stream_settings TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	for i, r := range rows {
		if err := db.Exec(`INSERT INTO inbounds (id, remark, port, protocol, settings, stream_settings)
			VALUES (?,?,?,?,?,?)`, i+1, r.remark, r.port, r.protocol, r.settings, r.stream).Error; err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, _ := db.DB()
	_ = sqlDB.Close()
	return path
}

func vlessRow(remark string, port int, clients string) fixtureInbound {
	return fixtureInbound{
		remark: remark, port: port, protocol: "vless",
		settings: fmt.Sprintf(`{"clients":[%s],"decryption":"none"}`, clients),
		stream:   `{"network":"tcp","security":"none"}`,
	}
}

func client(email, id string) string {
	return fmt.Sprintf(`{"id":%q,"email":%q}`, id, email)
}

func preview(t *testing.T, s *Server, token, path string) map[string]any {
	t.Helper()
	code, body := doPOST(t, s, "/api/admin/migrate/preview", token, fmt.Sprintf(`{"path":%q}`, path))
	if code != 200 {
		t.Fatalf("preview: %d %s", code, body)
	}
	var out struct {
		Plan map[string]any `json:"plan"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Plan
}

func TestPreviewWritesNothing(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t,
		vlessRow("legacy-a", 10443, client("alice@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))

	plan := preview(t, s, token, path)
	if plan["create_inbounds"].(float64) != 1 {
		t.Fatalf("plan = %+v, want one inbound to create", plan)
	}
	// The whole point of a dry run.
	ins, _ := s.db.ListInbounds()
	users, _ := s.db.ListUsers(0)
	if len(ins) != 0 || len(users) != 0 {
		t.Fatalf("the preview wrote %d inbound(s) and %d user(s)", len(ins), len(users))
	}
}

func TestApplyActuallyWrites(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t,
		vlessRow("legacy-a", 10443,
			client("alice@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")+","+
				client("bob@panel", "11111111-2222-4333-8444-555555555555")))

	code, body := doPOST(t, s, "/api/admin/migrate/apply", token, fmt.Sprintf(`{"path":%q}`, path))
	if code != 200 {
		t.Fatalf("apply: %d %s", code, body)
	}
	ins, _ := s.db.ListInbounds()
	if len(ins) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(ins))
	}
	users, _ := s.db.ListUsers(0)
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	// The domain half of the foreign "email" is dropped: alice@panel.local is one
	// person called alice, and carrying the old hostname into every username is
	// noise that never goes away.
	names := map[string]bool{}
	for _, u := range users {
		names[u.Username] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Fatalf("usernames = %v, want alice and bob", names)
	}

	// An imported user must be ASSIGNED, or the account exists, looks correct,
	// and has no inbound — which reads as a panel bug rather than a partial
	// import.
	for _, u := range users {
		a, err := s.db.UserAssignments(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Direct) == 0 {
			t.Fatalf("%s was imported with no inbound assignment", u.Username)
		}
	}
}

func TestImportedUsersGetFreshSubscriptionTokens(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t,
		vlessRow("legacy", 10443, client("carol@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))
	if code, body := doPOST(t, s, "/api/admin/migrate/apply", token,
		fmt.Sprintf(`{"path":%q}`, path)); code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	users, _ := s.db.ListUsers(0)
	// Carrying the foreign panel's token over would mean two panels handing out
	// the same subscription URL, with the old one still able to serve it.
	if len(users) != 1 || users[0].SubToken == "" {
		t.Fatalf("imported user has no subscription token: %+v", users)
	}
}

func TestRunningTheImportTwiceDoesNotDuplicate(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t,
		vlessRow("legacy", 10443, client("dave@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))
	body := fmt.Sprintf(`{"path":%q}`, path)

	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token, body); code != 200 {
		t.Fatalf("first apply: %d %s", code, b)
	}
	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token, body); code != 200 {
		t.Fatalf("second apply: %d %s", code, b)
	}
	ins, _ := s.db.ListInbounds()
	users, _ := s.db.ListUsers(0)
	// An operator who is unsure whether the first run worked will run it again.
	if len(ins) != 1 || len(users) != 1 {
		t.Fatalf("a repeated import duplicated: %d inbound(s), %d user(s)", len(ins), len(users))
	}
}

func TestAPortAlreadyInUseIsAConflictNotASilentOverwrite(t *testing.T) {
	s, token := adminAPI(t)
	// The panel already serves something on this port.
	existing := &store.Inbound{Remark: "mine", Protocol: "vless", Port: 10443, Enabled: true}
	if err := s.db.SaveInbound(existing); err != nil {
		t.Fatal(err)
	}
	path := foreignPanelDB(t,
		vlessRow("legacy", 10443, client("erin@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))

	plan := preview(t, s, token, path)
	if plan["conflict_inbounds"].(float64) != 1 {
		t.Fatalf("plan = %+v, want the port collision reported as a conflict", plan)
	}
	raw, _ := json.Marshal(plan)
	// The conflict names the obstacle. "Port 10443 is taken" makes the operator
	// go and find out by what.
	if !strings.Contains(string(raw), "mine") {
		t.Errorf("the conflict does not name what holds the port: %s", raw)
	}

	// And applying it must not import the conflicting inbound.
	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token,
		fmt.Sprintf(`{"path":%q}`, path)); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	ins, _ := s.db.ListInbounds()
	if len(ins) != 1 {
		t.Fatalf("inbounds = %d; the conflicting one was imported anyway", len(ins))
	}
}

func TestTwoForeignInboundsOnOnePortConflict(t *testing.T) {
	s, token := adminAPI(t)
	// A foreign panel can hold two inbounds on one port (one disabled, or on
	// different addresses). Importing both produces a config the core refuses to
	// start — after the write has already happened.
	path := foreignPanelDB(t,
		vlessRow("a", 10443, client("f@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")),
		vlessRow("b", 10443, client("g@panel", "11111111-2222-4333-8444-555555555555")))

	plan := preview(t, s, token, path)
	if plan["create_inbounds"].(float64) != 1 || plan["conflict_inbounds"].(float64) != 1 {
		t.Fatalf("plan = %+v, want one created and one conflicted", plan)
	}
}

func TestAMissingFileIsSaidPlainly(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doPOST(t, s, "/api/admin/migrate/preview", token, `{"path":"/nonexistent/x-ui.db"}`)
	if code == 200 {
		t.Fatal("a missing database was accepted")
	}
	// "Not there" and "not a panel database" have completely different fixes.
	if !strings.Contains(body, "no readable file") {
		t.Errorf("unhelpful error: %s", body)
	}
}

func TestPreviewDoesNotEchoImportedCredentials(t *testing.T) {
	s, token := adminAPI(t)
	const secret = "b831381d-6324-4d53-ad4f-8cda48b30811"
	path := foreignPanelDB(t, vlessRow("legacy", 10443, client("h@panel", secret)))

	_, body := doPOST(t, s, "/api/admin/migrate/preview", token, fmt.Sprintf(`{"path":%q}`, path))
	// A dry-run response that echoed every user's UUID would put the whole
	// imported credential set into a log or a browser history.
	if strings.Contains(body, secret) {
		t.Fatal("the preview echoed an imported credential")
	}
}

func TestMigrateIsOwnerOnly(t *testing.T) {
	s, _ := adminAPI(t)
	a := &store.Admin{Username: "adm", PasswordHash: "x", Role: store.RoleAdmin}
	if err := s.db.CreateAdmin(a); err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.signer.Issue(a.ID, a.Username, string(store.RoleAdmin))
	if err != nil {
		t.Fatal(err)
	}
	// It reads an arbitrary path on the host and writes across the whole panel.
	if code, _ := doPOST(t, s, "/api/admin/migrate/preview", tok, `{"path":"/tmp/x"}`); code != 403 {
		t.Fatalf("a non-owner reached the importer (%d)", code)
	}
	_ = os.Remove("/tmp/x")
}

func TestARenamedInboundIsNotImportedTwice(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t,
		vlessRow("original-name", 10443, client("ivy@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))
	body := fmt.Sprintf(`{"path":%q}`, path)

	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token, body); code != 200 {
		t.Fatalf("first apply: %d %s", code, b)
	}
	ins, _ := s.db.ListInbounds()
	if len(ins) != 1 {
		t.Fatalf("setup: %d inbounds", len(ins))
	}
	// The operator renames it AND moves it to a different port — both ordinary
	// things to do after a migration.
	//
	// Both matter for this test. Changing only the name leaves the original port
	// occupied, so a re-import is blocked by the port conflict instead and the
	// test passes without provenance doing anything: an earlier version of this
	// test did exactly that and PASSED with provenance matching disabled.
	if err := s.db.UpdateInboundFields(ins[0].ID, map[string]any{
		"remark": "renamed-by-operator", "port": 20443,
	}); err != nil {
		t.Fatal(err)
	}

	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token, body); code != 200 {
		t.Fatalf("second apply: %d %s", code, b)
	}
	ins, _ = s.db.ListInbounds()
	// Matching on the remark would create a duplicate here, and the operator
	// ends up with two of everything they touched.
	if len(ins) != 1 {
		t.Fatalf("a renamed inbound was imported again: %d inbounds", len(ins))
	}
}

func TestTwoSourcePanelsWithTheSameRowIdsBothImport(t *testing.T) {
	s, token := adminAPI(t)
	a := foreignPanelDB(t, vlessRow("from-a", 10443, client("j@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))
	b := foreignPanelDB(t, vlessRow("from-b", 10444, client("k@panel", "11111111-2222-4333-8444-555555555555")))

	// Both databases number their first inbound 1. Keying provenance on the row
	// id alone would make the second import a no-op.
	if code, r := doPOST(t, s, "/api/admin/migrate/apply", token,
		fmt.Sprintf(`{"path":%q,"panel":"panel-a"}`, a)); code != 200 {
		t.Fatalf("%d: %s", code, r)
	}
	if code, r := doPOST(t, s, "/api/admin/migrate/apply", token,
		fmt.Sprintf(`{"path":%q,"panel":"panel-b"}`, b)); code != 200 {
		t.Fatalf("%d: %s", code, r)
	}
	ins, _ := s.db.ListInbounds()
	if len(ins) != 2 {
		t.Fatalf("inbounds = %d, want one from each source panel", len(ins))
	}
}

func TestProvenanceIsRecordedOnTheRow(t *testing.T) {
	s, token := adminAPI(t)
	path := foreignPanelDB(t, vlessRow("p", 10443, client("l@panel", "b831381d-6324-4d53-ad4f-8cda48b30811")))
	if code, b := doPOST(t, s, "/api/admin/migrate/apply", token,
		fmt.Sprintf(`{"path":%q,"panel":"old-panel"}`, path)); code != 200 {
		t.Fatalf("%d: %s", code, b)
	}
	ins, _ := s.db.ListInbounds()
	// Without this the row cannot be recognised later, and "where did this
	// inbound come from" has no answer at all.
	if len(ins) != 1 || !strings.HasPrefix(ins[0].ImportSource, "old-panel:") {
		t.Fatalf("import source = %q, want old-panel:<id>", ins[0].ImportSource)
	}
}
