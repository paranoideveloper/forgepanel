package telegram

import (
	"errors"
	"strings"
	"testing"
)

// custData is fakeData plus customer links, keyed by chat.
type custData struct {
	fakeData
	tokens map[string]string // sub token -> username
	linked map[int64]string  // chat -> username
}

func newCustData() *custData {
	return &custData{tokens: map[string]string{"tokAlice": "alice"}, linked: map[int64]string{}}
}

func (d *custData) LinkChat(token string, chatID int64) (string, error) {
	name, ok := d.tokens[token]
	if !ok {
		return "", errors.New("this invite link does not belong to any account")
	}
	for c, n := range d.linked {
		if n == name && c != chatID {
			return "", errors.New("already linked")
		}
	}
	d.linked[chatID] = name
	return name, nil
}
func (d *custData) CustomerByChat(chatID int64) (Customer, bool) {
	n, ok := d.linked[chatID]
	if !ok {
		return Customer{}, false
	}
	return Customer{Username: n, Status: "active", UsedGB: 1.25, LimitGB: 10, Expiry: "2026-12-01",
		SubURL: "https://p.example.com/sub/tokAlice"}, true
}
func (d *custData) LinkedChats() []int64 {
	var out []int64
	for c := range d.linked {
		out = append(out, c)
	}
	return out
}
func (d *custData) SubTokenForUser(name string) (string, error) {
	for t, n := range d.tokens {
		if n == name {
			return t, nil
		}
	}
	return "", errors.New("user not found")
}

func TestACustomerLinksWithTheInviteAndSeesOnlyTheirOwnAccount(t *testing.T) {
	d, snd := newCustData(), &fakeSender{}
	b := New("", []int64{1}, d)
	b.sender = snd

	b.Handle(500, "/me")
	if !strings.Contains(snd.last, "not linked") {
		t.Fatalf("an unlinked chat got: %q", snd.last)
	}
	b.Handle(500, "/start tokAlice")
	if !strings.Contains(snd.last, "Linked to *alice*") {
		t.Fatalf("link reply: %q", snd.last)
	}
	b.Handle(500, "/me")
	if !strings.Contains(snd.last, "1.25 / 10.0 GB") || !strings.Contains(snd.last, "2026-12-01") {
		t.Fatalf("/me: %q", snd.last)
	}
	b.Handle(500, "/sub")
	if !strings.Contains(snd.last, "https://p.example.com/sub/tokAlice") {
		t.Fatalf("/sub: %q", snd.last)
	}

	// A second Telegram account holding the forwarded link is refused.
	b.Handle(600, "/start tokAlice")
	if !strings.Contains(snd.last, "Could not link") {
		t.Fatalf("second claim: %q", snd.last)
	}
	// Customers cannot run admin commands.
	b.Handle(500, "/user alice")
	if !strings.Contains(snd.last, "admin only") {
		t.Fatalf("customer ran an admin command: %q", snd.last)
	}
}

func TestAMalformedStartPayloadIsRefusedBeforeAnyLookup(t *testing.T) {
	d, snd := newCustData(), &fakeSender{}
	b := New("", nil, d)
	b.sender = snd
	b.Handle(500, "/start tok'; DROP")
	if !strings.Contains(snd.last, "not valid") || len(d.linked) != 0 {
		t.Fatalf("got %q, linked=%v", snd.last, d.linked)
	}
}

func TestBroadcastReachesEveryLinkedChatAndOnlyAdminsMaySendIt(t *testing.T) {
	broadcastPace = 0
	d := newCustData()
	d.linked[500], d.linked[501] = "alice", "bob"
	got := map[int64]string{}
	b := New("", []int64{1}, d)
	b.sender = senderFunc(func(chat int64, text string) error { got[chat] = text; return nil })

	b.Handle(500, "/broadcast hello")
	if _, ok := got[501]; ok {
		t.Fatal("a customer was able to broadcast")
	}
	b.Handle(1, "/broadcast maintenance at 02:00 UTC")
	if got[500] != "maintenance at 02:00 UTC" || got[501] != "maintenance at 02:00 UTC" {
		t.Fatalf("broadcast: %v", got)
	}
	if !strings.Contains(got[1], "sent to 2") {
		t.Fatalf("admin summary: %q", got[1])
	}
}

type senderFunc func(int64, string) error

func (f senderFunc) Send(c int64, t string) error { return f(c, t) }

func TestHelpShowsEachKindOfChatOnlyItsOwnCommands(t *testing.T) {
	if h := helpText(false, false); strings.Contains(h, "/me") || strings.Contains(h, "/broadcast") {
		t.Fatalf("stranger help: %q", h)
	}
	if h := helpText(false, true); !strings.Contains(h, "/me") || strings.Contains(h, "/broadcast") {
		t.Fatalf("customer help: %q", h)
	}
	if h := helpText(true, false); !strings.Contains(h, "/invite") || !strings.Contains(h, "/broadcast") {
		t.Fatalf("admin help: %q", h)
	}
}
