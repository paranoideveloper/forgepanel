package webhook

// The delivery queue.
//
// The events worth sending are precisely the ones that happen while nobody is
// watching, so "POST it and move on" loses exactly the alerts this feature
// exists for: the receiver is restarting, the network blipped, the TLS
// handshake took eleven seconds. Equally, a queue that retries for ever against
// an endpoint somebody decommissioned months ago is a slow outbound flood the
// operator cannot see, so the ladder is finite and the queue is bounded.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/version"
)

// retrySchedule is the wait BEFORE each retry. The first attempt is immediate,
// so a receiver that stays broken is tried six times across about thirteen
// minutes and then given up on.
//
// The ladder starts at a second because most failures are a receiver restarting
// and are over before the second attempt, and ends at ten minutes because
// beyond that the alert has stopped being news — an operator who has not been
// told a node is down within a quarter of an hour is going to find out another
// way.
var retrySchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// attemptTimeout bounds ONE attempt, matching the Telegram bot's client. A
// receiver that accepts the connection and never answers is the failure this
// catches; without it a single such endpoint stalls every later delivery in the
// queue behind it.
const attemptTimeout = 10 * time.Second

// maxQueued bounds the backlog.
//
// A thousand pending deliveries already means the receiver has been down for a
// long time, and the alternative to a bound is a panel that answers a dead
// endpoint by growing until it is killed. The OLDEST is dropped rather than the
// newest: with a receiver that has been unreachable for an hour, the newest
// events are the ones still worth acting on.
const maxQueued = 1024

type delivery struct {
	ep      Endpoint
	ev      Event
	body    []byte
	attempt int // attempts already made
	due     time.Time
}

// enqueue fans one event out to every endpoint that asked for it.
func (d *Dispatcher) enqueue(ev Event) {
	if d.load == nil {
		return
	}
	now := d.now()
	if ev.ID == "" {
		ev.ID = newID(now)
	}
	if ev.At.IsZero() {
		ev.At = now.UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		// Only reachable through Event.Data, which a caller controls. Dropping
		// the event silently would make the caller's bad value look like a
		// delivery problem at the far end.
		fmt.Fprintf(os.Stderr, "forgepanel: webhook %s is not encodable: %v\n", ev.Type, err)
		return
	}
	for _, ep := range d.load() {
		if !ep.wants(ev.Type) {
			continue
		}
		d.push(&delivery{ep: ep, ev: ev, body: body, due: now})
	}
}

// push adds a delivery and wakes the worker.
func (d *Dispatcher) push(dl *delivery) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if len(d.queue) >= maxQueued {
		dropped := d.queue[0]
		d.queue = d.queue[1:]
		fmt.Fprintf(os.Stderr, "forgepanel: webhook queue is full; dropped %s for %s\n",
			dropped.ev.Type, dropped.ep.URL)
	}
	d.queue = append(d.queue, dl)
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// take claims the delivery that is due soonest.
//
// It returns either a delivery to send now, or how long to wait for the next
// one to come due. The queue is scanned rather than kept sorted: it is bounded
// at a thousand entries and this runs once per delivery, so the ordering cost
// is not worth the bug surface of a heap.
func (d *Dispatcher) take() (*delivery, time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.queue) == 0 {
		return nil, 0
	}
	best := 0
	for i, dl := range d.queue {
		if dl.due.Before(d.queue[best].due) {
			best = i
		}
	}
	if wait := d.queue[best].due.Sub(d.now()); wait > 0 {
		return nil, wait
	}
	dl := d.queue[best]
	d.queue = append(d.queue[:best], d.queue[best+1:]...)
	d.inflight++
	return dl, 0
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	for {
		dl, wait := d.take()
		switch {
		case dl != nil:
			d.deliver(dl)
			d.mu.Lock()
			d.inflight--
			d.mu.Unlock()
			select {
			case d.idle <- struct{}{}:
			default:
			}
		case wait > 0:
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-d.wake:
			case <-d.quit:
				t.Stop()
				return
			}
			t.Stop()
		default:
			select {
			case <-d.wake:
			case <-d.quit:
				return
			}
		}
	}
}

// deliver makes one attempt and decides whether there will be another.
func (d *Dispatcher) deliver(dl *delivery) {
	dl.attempt++
	res := send(context.Background(), dl.ep, dl.ev.Type, dl.ev.ID, dl.body)
	res.Attempt = dl.attempt
	if d.record != nil {
		// Recorded on EVERY attempt, success or not. An endpoint whose last
		// answer was 401 four hours ago is the single most useful thing the
		// settings page can say; without it the operator sees a configured
		// endpoint and concludes the panel never sends anything.
		d.record(dl.ep.ID, res)
	}
	if res.OK() || !retryable(res) {
		return
	}
	if dl.attempt > len(d.retry) {
		fmt.Fprintf(os.Stderr, "forgepanel: webhook %s to %s gave up after %d attempts: %s\n",
			dl.ev.Type, dl.ep.URL, dl.attempt, res.Err)
		return
	}
	dl.due = d.now().Add(d.retry[dl.attempt-1])
	d.push(dl)
}

// retryable separates "try again" from "you are wrong".
//
// A 5xx is the receiver being broken, a 429 is the receiver asking us to slow
// down, and a transport error is the network — all three are temporary by
// definition. Every other 4xx is the receiver saying this request will never be
// accepted, and repeating it five more times only adds load to a machine that
// has already answered.
func retryable(r Result) bool {
	return r.Status == 0 || r.Status >= 500 || r.Status == http.StatusTooManyRequests
}

// Deliver performs ONE attempt with no queue and no retry, and reports what
// happened.
//
// It is what the settings page's test button calls: an operator pressing test
// wants the answer in the response, including the failure and its status code,
// rather than a green tick that only means the event was queued.
func (d *Dispatcher) Deliver(ctx context.Context, ep Endpoint, ev Event) Result {
	now := time.Now()
	if d == nil {
		return Result{Attempt: 1, Err: "webhook delivery is not running on this panel", At: now.UTC()}
	}
	if ev.ID == "" {
		ev.ID = newID(now)
	}
	if ev.At.IsZero() {
		ev.At = now.UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return Result{Attempt: 1, Err: err.Error(), At: now.UTC()}
	}
	res := send(ctx, ep, ev.Type, ev.ID, body)
	res.Attempt = 1
	return res
}

// send is the whole of one HTTP attempt.
func send(ctx context.Context, ep Endpoint, eventType, id string, body []byte) Result {
	now := time.Now()
	res := Result{At: now.UTC()}
	client, err := newClient(ep.ProxyURL, attemptTimeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	// Re-checked per attempt rather than trusted from save time: the dial-time
	// hook inside the client cannot cover this path on its own, because a proxy
	// override makes the transport dial the proxy instead. Status stays 0 so
	// retryable() keeps this retryable — an operator who fixes the URL should
	// not have to restart the panel to make deliveries resume.
	if _, err := netegress.GuardTarget(ctx, netegress.PolicyNoMetadata, ep.URL); err != nil {
		res.Err = err.Error()
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ForgePanel/"+version.Version)
	req.Header.Set(HeaderEvent, eventType)
	req.Header.Set(HeaderDelivery, id)
	if ep.Secret != "" {
		// The timestamp is taken per ATTEMPT, not per event: a receiver that
		// rejects an old signature to stop replays would otherwise reject the
		// ten-minute retry, which is the attempt most likely to be the one that
		// lands.
		req.Header.Set(HeaderSignature, Sign(ep.Secret, now.Unix(), body))
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	// Drain a bounded amount. Leaving the body unread stops the connection being
	// reused; reading it unbounded lets a broken or hostile receiver spend the
	// panel's memory on a reply nobody looks at.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	res.Status = resp.StatusCode
	if !res.OK() {
		res.Err = "receiver answered " + resp.Status
	}
	return res
}
