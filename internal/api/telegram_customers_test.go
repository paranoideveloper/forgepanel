package api

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/store"
)

func TestTelegramLinkBindsOneChatToOneAccount(t *testing.T) {
	s := dbServerT(t)
	cfg, err := config.LoadFromDataDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Panel().Domain, cfg.Panel().Port, cfg.Panel().AdminPath = "panel.example.com", 443, "/adm"
	s.cfg = cfg
	d := tgPanelData{s}

	mk := func(name, tok string) *store.User {
		u := &store.User{Username: name, SubToken: tok, Status: store.StatusActive,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b3081" + name[:1]}
		if err := s.db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	alice, bob := mk("alice", "tokA"), mk("bob", "tokB")

	if name, err := d.LinkChat("tokA", 500); err != nil || name != "alice" {
		t.Fatalf("link: %q %v", name, err)
	}
	if _, err := d.LinkChat("tokA", 600); err == nil {
		t.Fatal("a second Telegram account claimed an already linked invite")
	}
	if _, err := d.LinkChat("nope", 600); err == nil {
		t.Fatal("an unknown token linked")
	}
	c, ok := d.CustomerByChat(500)
	if !ok || c.Username != "alice" || c.SubURL != "https://panel.example.com/sub/tokA" {
		t.Fatalf("customer: %+v %v", c, ok)
	}

	// The same chat opening another account's invite moves over to it.
	if _, err := d.LinkChat("tokB", 500); err != nil {
		t.Fatal(err)
	}
	a, _ := s.db.UserByID(alice.ID)
	b, _ := s.db.UserByID(bob.ID)
	if a.TelegramID != 0 || b.TelegramID != 500 {
		t.Fatalf("after move: alice=%d bob=%d", a.TelegramID, b.TelegramID)
	}
	if got := d.LinkedChats(); len(got) != 1 || got[0] != 500 {
		t.Fatalf("linked chats: %v", got)
	}

	// A revoked subscription cannot be linked.
	now := time.Now()
	if err := s.db.UpdateUserFields(alice.ID, map[string]any{"sub_revoked": &now}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LinkChat("tokA", 700); err == nil {
		t.Fatal("a revoked subscription was linked")
	}
}
