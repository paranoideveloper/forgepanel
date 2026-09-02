package online

import (
	"sort"
	"sync"
	"time"
)

// DefaultTTL is how long after its last connection a source address still counts
// as present.
//
// A connection is an instant, not a duration: the access log records that one
// was accepted, never that it closed. Presence therefore has to be inferred from
// recency, and the window has to be longer than the gaps in ordinary browsing or
// every user would flicker between online and offline. Two minutes is long
// enough to bridge a quiet tab and short enough that a closed laptop drops off
// while the operator is still looking at the screen.
const DefaultTTL = 2 * time.Minute

// maxAddressesPerUser bounds one user's tracked source addresses.
//
// Without a cap, a user behind carrier-grade NAT that rotates its egress address
// per connection — or anyone deliberately doing so — grows this map without
// limit, in a process that is expected to stay up for months. The oldest entry
// is evicted, so the cap costs visibility into stale addresses and never into
// current ones.
const maxAddressesPerUser = 64

// Session is one source address seen for one user.
type Session struct {
	IP      string    `json:"ip"`
	Inbound string    `json:"inbound"`
	Node    string    `json:"node"`
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
	Count   int64     `json:"connections"`
}

// Presence is one user's current sessions.
type Presence struct {
	User     string    `json:"user"`
	Sessions []Session `json:"sessions"`
	LastSeen time.Time `json:"last_seen"`
}

// Tracker holds current presence in memory.
//
// In memory deliberately: this is connection metadata — who talked to what, from
// where — and a panel that persists it turns a compromise or a seizure into a
// history of everyone's activity. It is derived data with a two-minute useful
// life; keeping it anywhere durable buys nothing and costs a great deal.
type Tracker struct {
	mu    sync.Mutex
	users map[string]map[string]*Session
	ttl   time.Duration
	// now is injectable so the tests exercise expiry without sleeping.
	now func() time.Time
}

// NewTracker returns a tracker with the given TTL, or DefaultTTL for ttl <= 0.
func NewTracker(ttl time.Duration) *Tracker {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Tracker{
		users: map[string]map[string]*Session{},
		ttl:   ttl,
		now:   time.Now,
	}
}

// Observe records one accepted connection.
//
// Entries with no user are dropped. An unauthenticated inbound (a local SOCKS
// listener, the api dokodemo-door) produces access lines with no email, and
// filing those under a blank user would create a phantom "user" whose sessions
// are actually the panel's own machinery.
func (t *Tracker) Observe(e Entry, node string) {
	if e.User == "" || e.IP == "" {
		return
	}
	at := e.At
	if at.IsZero() {
		at = t.now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	byIP := t.users[e.User]
	if byIP == nil {
		byIP = map[string]*Session{}
		t.users[e.User] = byIP
	}
	if s := byIP[e.IP]; s != nil {
		s.Last = at
		s.Count++
		// The inbound can legitimately change — the same address reconnecting on
		// a different listener — and the current one is the useful answer.
		if e.Inbound != "" {
			s.Inbound = e.Inbound
		}
		if node != "" {
			s.Node = node
		}
		return
	}
	if len(byIP) >= maxAddressesPerUser {
		evictOldest(byIP)
	}
	byIP[e.IP] = &Session{
		IP:      e.IP,
		Inbound: e.Inbound,
		Node:    node,
		First:   at,
		Last:    at,
		Count:   1,
	}
}

func evictOldest(byIP map[string]*Session) {
	var oldestKey string
	var oldest time.Time
	for k, s := range byIP {
		if oldestKey == "" || s.Last.Before(oldest) {
			oldestKey, oldest = k, s.Last
		}
	}
	if oldestKey != "" {
		delete(byIP, oldestKey)
	}
}

// Snapshot returns everyone currently present, most recently seen first.
//
// It prunes expired sessions as it goes. Doing the expiry here rather than on a
// timer means a tracker nobody is reading holds no stale data forever, and there
// is no background goroutine to leak.
func (t *Tracker) Snapshot() []Presence {
	cutoff := t.now().Add(-t.ttl)

	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]Presence, 0, len(t.users))
	for user, byIP := range t.users {
		p := Presence{User: user}
		for ip, s := range byIP {
			if s.Last.Before(cutoff) {
				delete(byIP, ip)
				continue
			}
			p.Sessions = append(p.Sessions, *s)
			if s.Last.After(p.LastSeen) {
				p.LastSeen = s.Last
			}
		}
		if len(byIP) == 0 {
			// Drop the user's map too. Leaving empty maps behind is a slow leak
			// in a process that runs for months.
			delete(t.users, user)
			continue
		}
		sort.Slice(p.Sessions, func(i, j int) bool {
			return p.Sessions[i].Last.After(p.Sessions[j].Last)
		})
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].User < out[j].User
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// AddressCount returns how many distinct source addresses a user is currently
// using. This is what a concurrent-connection limit is enforced against.
func (t *Tracker) AddressCount(user string) int {
	cutoff := t.now().Add(-t.ttl)

	t.mu.Lock()
	defer t.mu.Unlock()

	byIP := t.users[user]
	n := 0
	for ip, s := range byIP {
		if s.Last.Before(cutoff) {
			delete(byIP, ip)
			continue
		}
		n++
	}
	if len(byIP) == 0 {
		delete(t.users, user)
	}
	return n
}

// Forget drops everything known about a user, for when they are deleted or
// their credentials are rotated — their old sessions are no longer theirs.
func (t *Tracker) Forget(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.users, user)
}

// ObserveLine parses a supervisor log line and records it if it is a
// connection. It is the hook handed to the process supervisor, and it must
// tolerate ANY line: the same pipe carries startup banners, warnings and DNS
// chatter, and a panic in a log pump would take the engine's output with it.
func (t *Tracker) ObserveLine(node string) func(string) {
	return func(line string) {
		if e, ok := ParseAccessLine(line); ok {
			t.Observe(e, node)
		}
	}
}
