package telegram

// Pushing events to the operator, instead of waiting to be asked.
//
// The bot answered commands and initiated nothing. A node could be down for a
// day, a certificate could expire, a customer could hit their limit at 3am — and
// the panel knew all of it and told nobody. Someone had to think to ask.
//
// THE HARD PART IS NOT SENDING, IT IS NOT SENDING TOO MUCH. A node that stays
// down is still down on the next sweep, and the next, and the next. A notifier
// that says so every minute gets muted within an hour, and a muted channel is
// worse than no channel: the operator now believes they are covered.
//
// So every alert is deduplicated by (event, subject) and re-sent only after a
// long interval, and every alert that can clear sends a RECOVERY notice when it
// does. "Node down" with no matching "node back" leaves someone driving to a
// datacentre for a problem that fixed itself twenty minutes later.

import (
	"fmt"
	"sync"
	"time"
)

// Event categorises a notification. It is part of the dedup key, so the same
// subject can be down AND over quota without either suppressing the other.
type Event string

const (
	EventTrafficLimit Event = "traffic-limit"
	EventExpiry       Event = "expiry"
	EventNodeDown     Event = "node-down"
	EventCertExpiry   Event = "cert-expiry"
	EventSecurity     Event = "security"
	// EventPoolExhausted is a DNS rotation pool with no healthy domain left.
	// Whatever it fronts is unreachable, and rotating is the only way out.
	EventPoolExhausted Event = "pool-exhausted"
)

// RepeatAfter is how long a still-active alert waits before saying so again.
//
// Six hours: long enough that an ongoing outage does not bury the channel,
// short enough that a problem nobody acted on resurfaces within a working day.
const RepeatAfter = 6 * time.Hour

// maxTrackedAlerts bounds the dedup map.
//
// The key includes a subject — a username, a node name — so a panel that churns
// users would otherwise grow this without limit in a process that runs for
// months. The oldest entry is dropped, which at worst re-sends one alert.
const maxTrackedAlerts = 4096

type alertState struct {
	firstSent time.Time
	lastSent  time.Time
}

// Notifier pushes deduplicated alerts to the panel's Telegram admins.
type Notifier struct {
	sender Sender
	chats  []int64

	mu     sync.Mutex
	active map[string]*alertState
	now    func() time.Time
}

// NewNotifier builds a notifier. A nil sender or an empty chat list makes every
// call a no-op, so callers never have to check whether Telegram is configured.
func NewNotifier(sender Sender, chats []int64) *Notifier {
	return &Notifier{
		sender: sender,
		chats:  append([]int64(nil), chats...),
		active: map[string]*alertState{},
		now:    time.Now,
	}
}

func key(e Event, subject string) string { return string(e) + "\x00" + subject }

// Notify raises an alert, or stays silent if the same one is already active and
// was sent recently.
//
// It reports whether anything was actually sent, which is what makes the dedup
// testable rather than a promise.
func (n *Notifier) Notify(e Event, subject, message string) bool {
	if n == nil || n.sender == nil || len(n.chats) == 0 {
		return false
	}
	now := n.now()
	k := key(e, subject)

	n.mu.Lock()
	st, existing := n.active[k]
	switch {
	case !existing:
		if len(n.active) >= maxTrackedAlerts {
			n.evictOldestLocked()
		}
		n.active[k] = &alertState{firstSent: now, lastSent: now}
	case now.Sub(st.lastSent) >= RepeatAfter:
		st.lastSent = now
		// An ongoing problem says how long it has been going on. "Still down"
		// is much less useful than "still down, 14h".
		message = fmt.Sprintf("%s\n_ongoing for %s_", message, roundDuration(now.Sub(st.firstSent)))
	default:
		n.mu.Unlock()
		return false
	}
	n.mu.Unlock()

	n.broadcast(message)
	return true
}

// Resolve clears an alert and announces the recovery, but ONLY if the alert was
// actually raised.
//
// Without that condition, every healthy check on every node would announce a
// recovery from a problem that never happened.
func (n *Notifier) Resolve(e Event, subject, message string) bool {
	if n == nil || n.sender == nil || len(n.chats) == 0 {
		return false
	}
	k := key(e, subject)

	n.mu.Lock()
	st, existing := n.active[k]
	if !existing {
		n.mu.Unlock()
		return false
	}
	delete(n.active, k)
	down := n.now().Sub(st.firstSent)
	n.mu.Unlock()

	n.broadcast(fmt.Sprintf("%s\n_was affected for %s_", message, roundDuration(down)))
	return true
}

// Active reports whether an alert is currently raised, for callers that need to
// avoid duplicating work rather than duplicating messages.
func (n *Notifier) Active(e Event, subject string) bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.active[key(e, subject)]
	return ok
}

func (n *Notifier) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, st := range n.active {
		if oldestKey == "" || st.lastSent.Before(oldest) {
			oldestKey, oldest = k, st.lastSent
		}
	}
	if oldestKey != "" {
		delete(n.active, oldestKey)
	}
}

// broadcast sends to every configured admin.
//
// A failure to reach one admin must not stop the others being told: the whole
// point is that somebody finds out.
func (n *Notifier) broadcast(message string) {
	for _, chat := range n.chats {
		_ = n.sender.Send(chat, message)
	}
}

func roundDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
