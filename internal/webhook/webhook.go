// Package webhook delivers the panel's lifecycle events to systems the operator
// runs themselves.
//
// Telegram is the only sink the panel had, and it is the wrong shape for half
// the people who need this. An alert that has to be READ by a person cannot
// open a ticket, suspend a reseller's account downstream, or page whoever is on
// call this week — and in the places this panel is actually deployed, Telegram
// is itself blocked often enough that "the alerts stopped" and "nothing
// happened" look identical from the outside.
//
// TWO THINGS MAKE THIS MORE THAN AN HTTP POST.
//
// The first is that the receiver has to be able to believe the body. A webhook
// URL is a public endpoint; anything that finds it can post to it, and a
// receiver that suspends accounts on an unauthenticated POST has been handed a
// remote control. So every delivery carries an HMAC over the timestamp and the
// exact bytes (see sign.go), which is the same shape Stripe and GitHub use and
// therefore the shape a receiver already knows how to check.
//
// The second is that the receiver WILL be down at some point, and the events
// worth sending are exactly the ones that happen while nobody is watching. A
// fire-and-forget POST from the maintenance goroutine drops the alert on the
// first connection refused, blocks the sweep behind a receiver that accepts the
// connection and never answers, and — worst — retries forever against an
// endpoint that has been decommissioned. Hence the bounded queue with a fixed
// retry ladder in queue.go.
package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Event is one thing that happened, as an endpoint receives it.
//
// The JSON names are the contract: an operator writes a receiver against these
// and it is not versioned by anything else, so renaming a field here breaks
// every deployed receiver silently — the POST still succeeds.
type Event struct {
	// ID is unique per event, repeated across that event's retries, so a
	// receiver can make its own handling idempotent. Retries are not a
	// hypothetical here: a receiver that answers 200 after the client timeout
	// gets the same event again.
	ID      string         `json:"id"`
	Type    string         `json:"event"`
	Subject string         `json:"subject"`
	Message string         `json:"message,omitempty"`
	At      time.Time      `json:"at"`
	Data    map[string]any `json:"data,omitempty"`
}

// Endpoint is one configured receiver.
type Endpoint struct {
	ID     uint
	URL    string
	Secret string
	// Events is the subscribed type list. EMPTY MEANS EVERYTHING, deliberately:
	// the alternative is an endpoint that is configured, enabled, green in the
	// UI and receives nothing because nobody ticked a box.
	Events []string
	// ProxyURL overrides the panel-wide egress proxy for this endpoint alone. A
	// receiver on an internal network and the Telegram API are not reachable the
	// same way, and forcing one proxy on both is how one of them stops working.
	ProxyURL string
}

// resolvedSuffix marks the event that says an alert has cleared.
const resolvedSuffix = ".resolved"

// wants reports whether this endpoint asked for an event of this type.
//
// A subscription to "node-down" also takes "node-down.resolved". Making the
// recovery a separate subscription is how a receiver ends up holding an open
// incident for a node that came back twenty minutes later — the failure the
// recovery event exists to prevent.
func (e Endpoint) wants(t string) bool {
	if len(e.Events) == 0 {
		return true
	}
	base := strings.TrimSuffix(t, resolvedSuffix)
	for _, want := range e.Events {
		want = strings.TrimSpace(want)
		if strings.EqualFold(want, t) || strings.EqualFold(want, base) {
			return true
		}
	}
	return false
}

// Result is the outcome of ONE delivery attempt.
//
// It is recorded against the endpoint rather than only logged: "your webhook
// last answered 401 four hours ago" is the difference between an operator
// fixing a token and an operator believing the panel never sends anything.
type Result struct {
	Attempt int
	Status  int
	Err     string
	At      time.Time
}

// OK reports a delivery the receiver accepted.
func (r Result) OK() bool { return r.Err == "" && r.Status >= 200 && r.Status < 300 }

// repeatAfter is how long a still-active alert waits before being sent again.
//
// Six hours, matching telegram.RepeatAfter on purpose: an operator with both
// sinks configured must not see the two disagree about how often a node that is
// still down is worth mentioning. Without this gate the maintenance sweep would
// POST "node-down" once a minute for as long as the node stays down — 1440
// deliveries a day, each with its own retry ladder behind it, which is how a
// receiver ends up rate-limiting or blocking the panel outright.
const repeatAfter = 6 * time.Hour

// maxTrackedAlerts bounds the dedup map, for the same reason the notifier bounds
// its own: the key carries a subject, and a panel that churns users would grow
// this without limit in a process that runs for months.
const maxTrackedAlerts = 4096

// Dispatcher fans one event out to every endpoint that asked for it.
//
// Every method is nil-receiver safe, the same convention telegram.Notifier
// follows, so no call site has to ask whether webhooks are configured before
// reporting something that happened.
type Dispatcher struct {
	// load is consulted per event rather than cached, so an endpoint saved in
	// the panel receives the next event instead of the next restart.
	load   func() []Endpoint
	record func(uint, Result)
	retry  []time.Duration
	now    func() time.Time

	mu       sync.Mutex
	queue    []*delivery
	inflight int
	raised   map[string]time.Time
	closed   bool

	wake chan struct{}
	idle chan struct{}
	quit chan struct{}
	wg   sync.WaitGroup

	closeOnce sync.Once
}

// NewDispatcher starts a dispatcher. load supplies the current endpoint set;
// record, which may be nil, persists each attempt's outcome.
func NewDispatcher(load func() []Endpoint, record func(uint, Result)) *Dispatcher {
	return newDispatcher(load, record, retrySchedule, time.Now)
}

// newDispatcher takes the retry ladder and the clock as arguments so a test can
// shorten the one and control the other. They are passed in rather than assigned
// to the fields afterwards because the worker goroutine is already running by the
// time NewDispatcher returns, and writing them from the caller would be a race.
func newDispatcher(load func() []Endpoint, record func(uint, Result), retry []time.Duration, now func() time.Time) *Dispatcher {
	d := &Dispatcher{
		load:   load,
		record: record,
		retry:  append([]time.Duration(nil), retry...),
		now:    now,
		raised: map[string]time.Time{},
		wake:   make(chan struct{}, 1),
		idle:   make(chan struct{}, 1),
		quit:   make(chan struct{}),
	}
	d.wg.Add(1)
	go d.run()
	return d
}

func alertKey(ev Event) string { return ev.Type + "\x00" + ev.Subject }

// Dispatch queues an event for every endpoint that asked for it.
//
// For a FACT — an account was created, an account was deleted. Each one is a
// separate thing that happened and every one has to arrive, so nothing is
// suppressed here. Use Alert for a condition that persists.
func (d *Dispatcher) Dispatch(ev Event) {
	if d == nil {
		return
	}
	d.enqueue(ev)
}

// Alert queues an event unless the same (type, subject) alert is already raised
// and was sent recently, and reports whether it queued anything.
//
// For a CONDITION — a node is down, a certificate is expiring, a pool has no
// healthy domain left. The condition is still true on the next maintenance
// sweep and the one after that, so without this gate a single down node would
// POST once a minute for as long as it stayed down, each delivery dragging its
// own retry ladder behind it. That is how a receiver ends up rate-limiting the
// panel, at which point the alerts that matter are the ones being dropped.
func (d *Dispatcher) Alert(ev Event) bool {
	if d == nil {
		return false
	}
	now := d.now()
	k := alertKey(ev)

	d.mu.Lock()
	last, active := d.raised[k]
	switch {
	case !active:
		if len(d.raised) >= maxTrackedAlerts {
			d.evictOldestLocked()
		}
	case now.Sub(last) < repeatAfter:
		d.mu.Unlock()
		return false
	}
	d.raised[k] = now
	d.mu.Unlock()

	d.enqueue(ev)
	return true
}

// Resolve announces that an alert raised by Alert has cleared, delivering ev's
// type with ".resolved" appended — and ONLY if it was ever raised.
//
// Without that condition every healthy maintenance sweep would post a recovery
// for a problem that never happened, which is worse than saying nothing: a
// receiver that opens and closes a ticket per sweep is a receiver somebody turns
// off.
func (d *Dispatcher) Resolve(ev Event) bool {
	if d == nil {
		return false
	}
	k := alertKey(ev)
	d.mu.Lock()
	_, active := d.raised[k]
	delete(d.raised, k)
	d.mu.Unlock()
	if !active {
		return false
	}
	ev.Type += resolvedSuffix
	d.enqueue(ev)
	return true
}

func (d *Dispatcher) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, at := range d.raised {
		if oldestKey == "" || at.Before(oldest) {
			oldestKey, oldest = k, at
		}
	}
	if oldestKey != "" {
		delete(d.raised, oldestKey)
	}
}

// Drain blocks until every queued delivery has been attempted to completion.
//
// It exists so a test can assert on what was delivered without sleeping, and so
// a shutdown can choose to wait; nothing on the request path calls it.
func (d *Dispatcher) Drain(ctx context.Context) error {
	if d == nil {
		return nil
	}
	for {
		d.mu.Lock()
		pending := len(d.queue) + d.inflight
		d.mu.Unlock()
		if pending == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.idle:
		}
	}
}

// Close stops the worker. Queued deliveries are abandoned: they are alerts about
// a panel that is shutting down anyway, and blocking a shutdown for up to
// thirteen minutes of retry ladder is the worse failure.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		close(d.quit)
		d.wg.Wait()
	})
}

// newID mints a delivery id. A failed read from crypto/rand is not worth failing
// a delivery over — the id is for the receiver's own idempotency, not a secret —
// so it falls back to the timestamp.
func newID(now time.Time) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "ev-" + hex.EncodeToString([]byte(now.UTC().Format(time.RFC3339Nano)))
	}
	return "ev-" + hex.EncodeToString(b[:])
}
