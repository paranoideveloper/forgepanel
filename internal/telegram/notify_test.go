package telegram

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// A notifier that repeats an ongoing alert gets muted within an hour, and a
// muted channel is worse than no channel: the operator now believes they are
// covered. These tests are almost entirely about NOT sending.

type recordingSender struct {
	mu   sync.Mutex
	sent []string
}

func (f *recordingSender) Send(chat int64, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, text)
	return nil
}

func (f *recordingSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *recordingSender) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return ""
	}
	return f.sent[len(f.sent)-1]
}

func fixture(t *testing.T) (*Notifier, *recordingSender, *time.Time) {
	t.Helper()
	f := &recordingSender{}
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	n := NewNotifier(f, []int64{111, 222})
	n.now = func() time.Time { return now }
	return n, f, &now
}

func TestAnOngoingAlertIsNotRepeated(t *testing.T) {
	n, f, now := fixture(t)

	if !n.Notify(EventNodeDown, "edge-1", "Node edge-1 is unreachable") {
		t.Fatal("the first alert was not sent")
	}
	if f.count() != 2 {
		t.Fatalf("sent to %d chats, want both admins", f.count())
	}

	// The node is still down on the next sweep, and the next, and the next.
	for i := 0; i < 50; i++ {
		*now = now.Add(time.Minute)
		if n.Notify(EventNodeDown, "edge-1", "Node edge-1 is unreachable") {
			t.Fatalf("the same alert was re-sent after %d minutes", i+1)
		}
	}
	if f.count() != 2 {
		t.Fatalf("messages = %d, want 2 — an ongoing outage must not bury the channel", f.count())
	}
}

func TestAnOngoingAlertResurfacesEventually(t *testing.T) {
	n, f, now := fixture(t)
	n.Notify(EventNodeDown, "edge-1", "Node edge-1 is unreachable")

	*now = now.Add(RepeatAfter - time.Minute)
	if n.Notify(EventNodeDown, "edge-1", "still down") {
		t.Fatal("re-sent before the repeat interval")
	}
	*now = now.Add(2 * time.Minute)
	if !n.Notify(EventNodeDown, "edge-1", "still down") {
		t.Fatal("a problem nobody acted on never resurfaced")
	}
	// It says how long. "Still down" is much less useful than "still down, 6h".
	if !strings.Contains(f.last(), "ongoing for") {
		t.Errorf("the repeat does not say how long: %q", f.last())
	}
}

func TestDifferentSubjectsAndEventsDoNotSuppressEachOther(t *testing.T) {
	n, f, _ := fixture(t)

	n.Notify(EventNodeDown, "edge-1", "a")
	n.Notify(EventNodeDown, "edge-2", "b")
	n.Notify(EventTrafficLimit, "edge-1", "c")

	// A node can be down AND a user over quota; collapsing those would hide one.
	if f.count() != 6 {
		t.Fatalf("messages = %d, want 3 alerts × 2 admins", f.count())
	}
}

func TestRecoveryIsAnnouncedOnlyIfSomethingWasWrong(t *testing.T) {
	n, f, now := fixture(t)

	// Nothing was ever raised: a healthy check must not announce a recovery from
	// a problem that never happened, on every node, forever.
	if n.Resolve(EventNodeDown, "edge-1", "Node edge-1 is back") {
		t.Fatal("announced a recovery with no preceding alert")
	}
	if f.count() != 0 {
		t.Fatalf("messages = %d, want none", f.count())
	}

	n.Notify(EventNodeDown, "edge-1", "Node edge-1 is unreachable")
	*now = now.Add(90 * time.Minute)
	if !n.Resolve(EventNodeDown, "edge-1", "Node edge-1 is back") {
		t.Fatal("a real recovery was not announced")
	}
	// How long it was down is the part that decides whether anyone investigates.
	if !strings.Contains(f.last(), "1h") {
		t.Errorf("the recovery does not say how long it lasted: %q", f.last())
	}
}

func TestAlertingAgainAfterRecoveryIsNotSuppressed(t *testing.T) {
	n, f, now := fixture(t)
	n.Notify(EventNodeDown, "flapper", "down")
	n.Resolve(EventNodeDown, "flapper", "back")
	before := f.count()

	*now = now.Add(time.Minute)
	if !n.Notify(EventNodeDown, "flapper", "down again") {
		t.Fatal("a NEW outage after a recovery was suppressed as a duplicate")
	}
	if f.count() <= before {
		t.Fatal("nothing was sent for the second outage")
	}
}

func TestNoSenderIsASilentNoOp(t *testing.T) {
	// A panel with no Telegram configured must not need every caller to check.
	n := NewNotifier(nil, []int64{1})
	if n.Notify(EventNodeDown, "x", "y") {
		t.Fatal("claimed to send with no sender")
	}
	n2 := NewNotifier(&recordingSender{}, nil)
	if n2.Notify(EventNodeDown, "x", "y") {
		t.Fatal("claimed to send with no configured admins")
	}
	var nilNotifier *Notifier
	if nilNotifier.Notify(EventNodeDown, "x", "y") || nilNotifier.Active(EventNodeDown, "x") {
		t.Fatal("a nil notifier must be safe to call")
	}
}

func TestTrackedAlertsAreBounded(t *testing.T) {
	n, _, now := fixture(t)
	// The key includes a subject, so a panel that churns users would otherwise
	// grow this map without limit over months of uptime.
	for i := 0; i < maxTrackedAlerts*2; i++ {
		*now = now.Add(time.Second)
		n.Notify(EventTrafficLimit, string(rune('a'+i%26))+string(rune(i)), "over")
	}
	n.mu.Lock()
	size := len(n.active)
	n.mu.Unlock()
	if size > maxTrackedAlerts {
		t.Fatalf("tracked alerts = %d, want at most %d", size, maxTrackedAlerts)
	}
}

func TestConcurrentNotifyIsSafe(t *testing.T) {
	// Alerts come from the scheduler, the health checker and the API at once.
	n, _, _ := fixture(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				n.Notify(EventNodeDown, string(rune('a'+g)), "down")
				n.Resolve(EventNodeDown, string(rune('a'+g)), "up")
				_ = n.Active(EventNodeDown, string(rune('a'+g)))
			}
		}(g)
	}
	wg.Wait()
}
