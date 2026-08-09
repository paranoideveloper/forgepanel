package api

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// TestTgPanelDataManagement exercises the Telegram admin mutations against a real
// store: create → inspect → disable → reset/limit → extend → delete, plus the
// not-found and duplicate paths.
func TestTgPanelDataManagement(t *testing.T) {
	s := dbServerT(t)
	d := tgPanelData{s}

	// Create.
	tok, err := d.CreateUser("charlie")
	if err != nil || tok == "" {
		t.Fatalf("create: tok=%q err=%v", tok, err)
	}
	if _, err := d.CreateUser("charlie"); err == nil {
		t.Fatal("duplicate username should be rejected")
	}

	// Inspect via the read path.
	name, status, _, _, ok := d.UserByName("charlie")
	if !ok || name != "charlie" || status != "active" {
		t.Fatalf("read: %q %q ok=%v", name, status, ok)
	}

	// Disable → status flips in the DB.
	if err := d.SetUserStatus("charlie", "disabled"); err != nil {
		t.Fatal(err)
	}
	u := mustUser(t, s, "charlie")
	if u.Status != store.StatusDisabled {
		t.Fatalf("status not persisted: %s", u.Status)
	}

	// Limit + reset + extend.
	if err := d.SetUserLimitGB("charlie", 20); err != nil {
		t.Fatal(err)
	}
	if u := mustUser(t, s, "charlie"); u.DataLimit != 20*gbBytes {
		t.Fatalf("limit not applied: %d", u.DataLimit)
	}
	if err := d.ResetUserTraffic("charlie"); err != nil {
		t.Fatal(err)
	}
	exp, err := d.ExtendUserDays("charlie", 30)
	if err != nil || exp == "" {
		t.Fatalf("extend: %q %v", exp, err)
	}
	if u := mustUser(t, s, "charlie"); u.ExpireAt == nil {
		t.Fatal("expiry not set")
	}

	// Not found paths.
	if err := d.SetUserStatus("ghost", "active"); err == nil {
		t.Fatal("ghost status should error")
	}
	if err := d.DeleteUser("ghost"); err == nil {
		t.Fatal("ghost delete should error")
	}

	// Delete.
	if err := d.DeleteUser("charlie"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, ok := d.UserByName("charlie"); ok {
		t.Fatal("user still present after delete")
	}
}

func mustUser(t *testing.T, s *Server, name string) *store.User {
	t.Helper()
	us, _ := s.db.ListUsers(0)
	for i := range us {
		if us[i].Username == name {
			return &us[i]
		}
	}
	t.Fatalf("user %q not found", name)
	return nil
}
