package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/telegram"
)

// The token was read once from FORGEPANEL_TELEGRAM_TOKEN at process start and
// nowhere else, so setting up alerts meant editing a compose file and restarting
// the panel — for a feature whose entire purpose is telling an operator about
// things that happen while they are not looking.
func TestTheBotCanBeConfiguredFromThePanel(t *testing.T) {
	s, token := adminAPI(t)

	code, body := doGET(t, s, "/api/admin/settings/telegram", token)
	if code != 200 {
		t.Fatalf("GET returned %d: %s", code, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["configured"] != false {
		t.Errorf("a fresh panel reports configured=%v", got["configured"])
	}

	var sent []int64
	s.tgSend = func(_ string, chatID int64, _ string) error {
		sent = append(sent, chatID)
		return nil
	}
	code, body = realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "123456:AA-fake-token", "chat_ids": "111, -100222", "test": true,
	})
	if code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	// Every chat, not just the first: an operator who added a second admin needs
	// to know the bot cannot write to it, and the usual cause is invisible from
	// the first one succeeding.
	if len(sent) != 2 || sent[0] != 111 || sent[1] != -100222 {
		t.Errorf("test message went to %v, want both chats including the negative group id", sent)
	}

	// The resolved config must be what the notifier will actually use.
	cfg := s.resolveTelegram()
	if cfg.Token != "123456:AA-fake-token" || len(cfg.ChatIDs) != 2 {
		t.Fatalf("resolved config = %+v", cfg)
	}
	if !cfg.Configured {
		t.Error("configured is false with a token and two chats")
	}
}

// The token is a bearer credential for the bot: it reads every message the bot
// receives and posts as it. It must never come back out.
func TestTheBotTokenIsNeverReturned(t *testing.T) {
	s, token := adminAPI(t)
	if code, body := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "secret-token-value", "chat_ids": "42",
	}); code != 200 {
		t.Fatalf("POST returned %d: %s", code, body)
	}
	_, body := doGET(t, s, "/api/admin/settings/telegram", token)
	if strings.Contains(body, "secret-token-value") {
		t.Fatalf("the settings response contains the token: %s", body)
	}
	if !strings.Contains(body, `"has_token":true`) {
		t.Errorf("the response does not say a token is set: %s", body)
	}
}

// Saving the chat ids must not require re-typing a secret the panel refused to
// show back. Omitting the token keeps the stored one.
func TestSavingChatIDsKeepsTheStoredToken(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "keep-me", "chat_ids": "1",
	}); code != 200 {
		t.Fatal("first save failed")
	}
	if code, body := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"chat_ids": "1, 2",
	}); code != 200 {
		t.Fatalf("second save returned %d: %s", code, body)
	}
	if cfg := s.resolveTelegram(); cfg.Token != "keep-me" || len(cfg.ChatIDs) != 2 {
		t.Fatalf("resolved = %+v; saving chat ids cleared the token", cfg)
	}
}

// A failing test must block the save. The point of testing before saving is not
// replacing a working configuration with a broken one.
func TestAFailedTestDoesNotOverwriteAWorkingConfiguration(t *testing.T) {
	s, token := adminAPI(t)
	if code, _ := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "good", "chat_ids": "7",
	}); code != 200 {
		t.Fatal("initial save failed")
	}
	s.tgSend = func(string, int64, string) error {
		return &telegram.SendError{ChatID: 8, Code: 401, Description: "Unauthorized"}
	}
	code, body := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "bad", "chat_ids": "8", "test": true,
	})
	if code != 422 {
		t.Fatalf("a failing test returned %d: %s", code, body)
	}
	// And the remediation has to name the fix. "Unauthorized" is Telegram's
	// word for "your token is wrong", which almost nobody reads that way.
	if !strings.Contains(body, "BotFather") {
		t.Errorf("the failure does not say what to do: %s", body)
	}
	if cfg := s.resolveTelegram(); cfg.Token != "good" {
		t.Errorf("the failed save replaced the working token with %q", cfg.Token)
	}
}

// Testing without saving, so a token can be checked before it replaces one that
// works.
func TestTheTestEndpointSavesNothing(t *testing.T) {
	s, token := adminAPI(t)
	s.tgSend = func(string, int64, string) error { return nil }
	if code, body := realPost(t, s, "/api/admin/settings/telegram/test", token, map[string]any{
		"token": "throwaway", "chat_ids": "99",
	}); code != 200 {
		t.Fatalf("test returned %d: %s", code, body)
	}
	if cfg := s.resolveTelegram(); cfg.Token != "" {
		t.Errorf("the test endpoint persisted the token %q", cfg.Token)
	}
}

// A chat id is negative for a group. The most common way this is set up wrong is
// a group id silently dropped by a parser that expected a positive number.
func TestChatIDParsingKeepsGroupIDsAndRejectsNonsense(t *testing.T) {
	got := parseChatIDs("111\n-1002223334445, 0, notanumber; 111  222")
	want := []int64{111, -1002223334445, 222}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v (duplicates and zeros dropped, order kept)", got, want)
		}
	}
}

// A list that is entirely unusable must be refused rather than saved as empty:
// an operator who typed a username instead of an id would otherwise see the save
// succeed and no alert ever arrive.
func TestAChatIDListWithNothingUsableIsRefused(t *testing.T) {
	s, token := adminAPI(t)
	code, body := realPost(t, s, "/api/admin/settings/telegram", token, map[string]any{
		"token": "x", "chat_ids": "@myusername",
	})
	if code != 422 {
		t.Fatalf("returned %d: %s", code, body)
	}
	if !strings.Contains(body, "userinfobot") {
		t.Errorf("the error does not say how to find a chat id: %s", body)
	}
}
