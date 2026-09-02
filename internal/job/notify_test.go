package job

import (
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The panel knew a quota had tripped or an account had expired and told nobody:
// the bot answered commands and initiated nothing. These prove the transitions
// actually reach a notifier, and — more importantly — that a broken bot cannot
// stop the enforcement it is reporting on.

type capturedAlert struct{ event, subject, message string }

func TestATrippedQuotaIsAnnounced(t *testing.T) {
	db := ipTestStore(t)
	u := &store.User{Username: "heavy", SubToken: "hv", Status: store.StatusActive, DataLimit: 1000}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	var got []capturedAlert
	s := New(Config{
		DB: db,
		PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
			return map[string]store.TrafficSplit{UserEmail(u.ID): {Down: 5000}}, nil
		},
		Notify: func(e, subj, msg string) { got = append(got, capturedAlert{e, subj, msg}) },
	})
	s.pollAndAccount()

	if len(got) != 1 {
		t.Fatalf("alerts = %+v, want exactly one for the trip", got)
	}
	if got[0].event != "traffic-limit" || got[0].subject != "heavy" {
		t.Fatalf("alert = %+v, want a traffic-limit alert naming the user", got[0])
	}
	// The subject is separate from the message because the notifier dedups on
	// it; folding it into the text would make every alert unique and defeat that.
	if !strings.Contains(got[0].message, "heavy") {
		t.Errorf("the message does not name the user: %q", got[0].message)
	}
}

func TestAnExpiryIsAnnounced(t *testing.T) {
	db := ipTestStore(t)
	past := time.Now().Add(-time.Hour)
	u := &store.User{Username: "lapsed", SubToken: "lp", Status: store.StatusActive, ExpireAt: &past}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	var got []capturedAlert
	s := New(Config{DB: db,
		Notify: func(e, subj, msg string) { got = append(got, capturedAlert{e, subj, msg}) }})
	s.sweepAt(time.Now())

	if len(got) != 1 || got[0].event != "expiry" || got[0].subject != "lapsed" {
		t.Fatalf("alerts = %+v, want one expiry alert for lapsed", got)
	}
}

func TestABrokenNotifierDoesNotStopEnforcement(t *testing.T) {
	db := ipTestStore(t)
	past := time.Now().Add(-time.Hour)
	u := &store.User{Username: "still-expires", SubToken: "se", Status: store.StatusActive, ExpireAt: &past}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db, Notify: func(string, string, string) { panic("telegram is down") }})
	s.sweepAt(time.Now())

	got, err := db.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Notification is a side effect of the sweep, never a condition of it. A bot
	// that is down, rate-limited or misconfigured must not leave an expired
	// account being served.
	if got.Status != store.StatusExpired {
		t.Fatalf("status = %q; a panicking notifier stopped the user being expired", got.Status)
	}
}

func TestNoNotifierConfiguredIsFine(t *testing.T) {
	db := ipTestStore(t)
	past := time.Now().Add(-time.Hour)
	u := &store.User{Username: "quiet", SubToken: "q", Status: store.StatusActive, ExpireAt: &past}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	// A panel with no Telegram configured must not need a check at every call
	// site, and must still enforce.
	s := New(Config{DB: db})
	s.sweepAt(time.Now())
	got, _ := db.UserByID(u.ID)
	if got.Status != store.StatusExpired {
		t.Fatal("enforcement broke without a notifier")
	}
}
