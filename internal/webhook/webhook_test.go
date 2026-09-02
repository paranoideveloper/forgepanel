package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func hmacHex(secret, message string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}

// A signature that does not cover both halves is not a signature: covering only
// the body makes every captured delivery replayable for ever, and covering only
// the timestamp lets anyone re-use a stolen signature on a body of their choice.
func TestSignatureIsComputedOverTimestampAndBody(t *testing.T) {
	body := []byte(`{"event":"node-down","subject":"edge-1"}`)
	const secret = "s3cr3t"
	base := Sign(secret, 1700000000, body)

	// Recomputed independently — a helper checked against itself proves only
	// that it is deterministic.
	want := "t=1700000000,v1=" + hmacHex(secret, "1700000000."+string(body))
	if base != want {
		t.Fatalf("Sign = %s, want %s", base, want)
	}

	if got := Sign(secret, 1700000001, body); got == base {
		t.Error("a one-second change in the timestamp produced the same signature")
	}
	changed := append([]byte(nil), body...)
	changed[10] ^= 1
	if got := Sign(secret, 1700000000, changed); got == base {
		t.Error("a one-byte change in the body produced the same signature")
	}
	if got := Sign("other", 1700000000, body); got == base {
		t.Error("a different secret produced the same signature")
	}

	// The separator. Without the ".", a timestamp of 12 with a body starting
	// "3" signs the same bytes as a timestamp of 123 with the body one byte
	// shorter — so one valid delivery would authenticate another.
	if Sign(secret, 12, []byte("3abc")) == Sign(secret, 123, []byte("abc")) {
		t.Error("the timestamp and the body run together; a delivery can be re-framed")
	}
}

// testDispatcher shortens the retry ladder. The real one runs 1s → 10m, which
// is right in production and thirteen minutes of waiting in a test.
func testDispatcher(t *testing.T, eps []Endpoint, record func(uint, Result)) *Dispatcher {
	t.Helper()
	return clockedDispatcher(t, eps, record, time.Now)
}

func clockedDispatcher(t *testing.T, eps []Endpoint, record func(uint, Result), now func() time.Time) *Dispatcher {
	t.Helper()
	ladder := make([]time.Duration, len(retrySchedule))
	for i := range ladder {
		ladder[i] = time.Millisecond
	}
	d := newDispatcher(func() []Endpoint { return eps }, record, ladder, now)
	t.Cleanup(d.Close)
	return d
}

func drainT(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Drain(ctx); err != nil {
		t.Fatalf("draining: %v", err)
	}
}

// The events worth sending are the ones that happen while nobody is watching,
// so a receiver that is restarting must not lose them — and a receiver that has
// answered "this request is wrong" must not be asked five more times.
func TestA5xxIsRetriedAndA4xxIsNot(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   int
	}{
		{"a broken receiver is tried the whole ladder", http.StatusInternalServerError, len(retrySchedule) + 1},
		{"rate limiting is a temporary no", http.StatusTooManyRequests, len(retrySchedule) + 1},
		{"a rejected request is tried once", http.StatusBadRequest, 1},
		{"a missing endpoint is tried once", http.StatusNotFound, 1},
		{"an accepted delivery is tried once", http.StatusOK, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var attempts int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				attempts++
				mu.Unlock()
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			var lastResult Result
			d := testDispatcher(t, []Endpoint{{ID: 7, URL: srv.URL, Secret: "k"}},
				func(id uint, res Result) {
					mu.Lock()
					lastResult = res
					mu.Unlock()
				})
			d.Dispatch(Event{Type: "node-down", Subject: "edge-1"})
			drainT(t, d)

			mu.Lock()
			defer mu.Unlock()
			if attempts != tc.want {
				t.Errorf("attempts = %d, want %d", attempts, tc.want)
			}
			if lastResult.Attempt != tc.want {
				t.Errorf("recorded attempt = %d, want %d", lastResult.Attempt, tc.want)
			}
			if lastResult.Status != tc.status {
				t.Errorf("recorded status = %d, want %d", lastResult.Status, tc.status)
			}
		})
	}
}

// A transport failure is the network, not the receiver's answer. It has to be
// retried, and it has to leave a readable reason on the row.
func TestAnUnreachableReceiverIsRetriedAndRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close() // nothing is listening there now

	var mu sync.Mutex
	var results []Result
	d := testDispatcher(t, []Endpoint{{ID: 1, URL: dead}}, func(_ uint, res Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	})
	d.Dispatch(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)

	mu.Lock()
	defer mu.Unlock()
	if len(results) != len(retrySchedule)+1 {
		t.Fatalf("attempts = %d, want %d", len(results), len(retrySchedule)+1)
	}
	last := results[len(results)-1]
	if last.Status != 0 || last.Err == "" {
		t.Fatalf("a transport failure recorded %+v; the row would say nothing useful", last)
	}
}

// The gate that stops a still-down node posting once a minute for a week.
func TestARepeatedAlertIsSentOnceAndItsRecoveryOnlyIfItWasRaised(t *testing.T) {
	var mu sync.Mutex
	var events []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		events = append(events, r.Header.Get(HeaderEvent))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := testDispatcher(t, []Endpoint{{ID: 1, URL: srv.URL}}, nil)

	// A recovery for something never reported is silence, not a recovery.
	if d.Resolve(Event{Type: "node-down", Subject: "edge-1"}) {
		t.Error("a node that was never reported down announced a recovery")
	}
	for i := 0; i < 5; i++ {
		d.Alert(Event{Type: "node-down", Subject: "edge-1"})
	}
	// A different subject is a different problem and is not suppressed.
	d.Alert(Event{Type: "node-down", Subject: "edge-2"})
	if !d.Resolve(Event{Type: "node-down", Subject: "edge-1"}) {
		t.Error("a raised alert did not resolve")
	}
	// And a fact is never suppressed: two accounts created is two events.
	d.Dispatch(Event{Type: "user.created", Subject: "alice"})
	d.Dispatch(Event{Type: "user.created", Subject: "alice"})
	drainT(t, d)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"node-down", "node-down", "node-down.resolved", "user.created", "user.created"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

// An endpoint with no list takes everything, and a subscription to an alert
// carries its recovery — otherwise a receiver holds an incident open for a node
// that came back twenty minutes later.
func TestSubscriptionMatching(t *testing.T) {
	cases := []struct {
		events []string
		typ    string
		want   bool
	}{
		{nil, "node-down", true},
		{[]string{"node-down"}, "node-down", true},
		{[]string{"node-down"}, "node-down.resolved", true},
		{[]string{"node-down"}, "cert-expiry", false},
		{[]string{"cert-expiry", "node-down"}, "cert-expiry", true},
		{[]string{" node-down "}, "node-down", true},
		{[]string{"NODE-DOWN"}, "node-down", true},
	}
	for _, tc := range cases {
		if got := (Endpoint{Events: tc.events}).wants(tc.typ); got != tc.want {
			t.Errorf("Endpoint{%v}.wants(%q) = %v, want %v", tc.events, tc.typ, got, tc.want)
		}
	}
}

// A per-endpoint proxy that cannot be built has to fail on save. Left to fail
// at delivery time it is indistinguishable from a receiver that is down.
func TestValidateProxyRefusesWhatCannotBeDialled(t *testing.T) {
	if err := ValidateProxy(""); err != nil {
		t.Errorf("no proxy is not an error: %v", err)
	}
	for _, ok := range []string{"http://127.0.0.1:3128", "https://p:8443", "socks5://127.0.0.1:1080", "socks5h://u:p@127.0.0.1:1080"} {
		if err := ValidateProxy(ok); err != nil {
			t.Errorf("ValidateProxy(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"ftp://127.0.0.1:21", "socks5://", "://nope"} {
		if err := ValidateProxy(bad); err == nil {
			t.Errorf("ValidateProxy(%q) was accepted", bad)
		}
	}
}

// Every delivery of one event carries the same id, so a receiver can drop the
// duplicate a timed-out-but-succeeded attempt produces.
func TestRetriesRepeatTheDeliveryIdAndReSignEachAttempt(t *testing.T) {
	var mu sync.Mutex
	var ids, sigs []string
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ids = append(ids, r.Header.Get(HeaderDelivery))
		sigs = append(sigs, r.Header.Get(HeaderSignature))
		first := fail
		fail = false
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := testDispatcher(t, []Endpoint{{ID: 1, URL: srv.URL, Secret: "k"}}, nil)
	d.Dispatch(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)

	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 {
		t.Fatalf("attempts = %d, want 2", len(ids))
	}
	if ids[0] == "" || ids[0] != ids[1] {
		t.Errorf("delivery ids = %v; a receiver cannot deduplicate the retry", ids)
	}
	for _, s := range sigs {
		if s == "" {
			t.Fatal("a retry went out unsigned")
		}
	}
}

// The queue is bounded, or a receiver that has been down for a week grows the
// panel until it is killed. The OLDEST goes: after an hour of failures the
// newest events are the ones still worth acting on.
func TestTheQueueDropsTheOldestWhenItIsFull(t *testing.T) {
	d := testDispatcher(t, nil, nil)
	// Every entry is due in an hour, so the worker sleeps instead of draining
	// the queue out from under the assertion. Pushed directly because the state
	// under test is a full queue, which Dispatch alone would never produce
	// against a receiver that answers.
	soon := time.Now().Add(time.Hour)
	for i := 0; i < maxQueued; i++ {
		d.push(&delivery{ev: Event{Type: "node-down", Subject: strconv.Itoa(i)}, due: soon})
	}
	d.push(&delivery{ev: Event{Type: "node-down", Subject: "newest"}, due: soon})

	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) > maxQueued {
		t.Fatalf("queue length = %d, want at most %d", len(d.queue), maxQueued)
	}
	if d.queue[len(d.queue)-1].ev.Subject != "newest" {
		t.Error("the newest delivery was dropped instead of the oldest")
	}
	if d.queue[0].ev.Subject != "1" {
		t.Errorf("the front of the queue is %q, want the second-oldest after the oldest was dropped", d.queue[0].ev.Subject)
	}
}

// The gate is a WINDOW, not a mute. A node that is still down six hours later is
// still worth a delivery: a receiver that opened an incident and lost it to a
// restart has nothing else that would ever tell it again.
func TestAnAlertThatIsStillActiveIsReSentAfterTheRepeatWindow(t *testing.T) {
	var mu sync.Mutex
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var clockMu sync.Mutex
	now := time.Now()
	d := clockedDispatcher(t, []Endpoint{{ID: 1, URL: srv.URL}}, nil, func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	})
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	d.Alert(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)
	advance(repeatAfter - time.Minute)
	d.Alert(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)
	mu.Lock()
	if count != 1 {
		mu.Unlock()
		t.Fatalf("deliveries just inside the window = %d, want 1", count)
	}
	mu.Unlock()

	advance(2 * time.Minute)
	d.Alert(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatalf("deliveries after the window reopened = %d, want 2", count)
	}
}

// A receiver behind HTTP basic auth is configured as user:pass@host — there is
// no header field on a webhook endpoint, and the panel's own UI offers none. The
// SSRF guard rejected embedded credentials at DELIVERY time, which runs against
// every row already in the table, so an upgrade turned working endpoints into
// permanent failures: retryable, six attempts, then given up, with a remediation
// naming a feature the product does not have.
//
// Userinfo is not an SSRF control. What stops an internal fetch is the resolved
// IP, which is checked either way.
func TestAReceiverWithEmbeddedCredentialsStillGetsItsDelivery(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		got = user + ":" + pass
	}))
	defer srv.Close()

	// The shape an operator stores: credentials in the URL, which is the only
	// place this product lets them put one.
	withCreds := strings.Replace(srv.URL, "http://", "http://hookuser:hookpass@", 1)

	var mu sync.Mutex
	var results []Result
	d := testDispatcher(t, []Endpoint{{ID: 1, URL: withCreds}}, func(_ uint, res Result) {
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
	})
	d.Dispatch(Event{Type: "node-down", Subject: "edge-1"})
	drainT(t, d)

	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 {
		t.Fatalf("attempts = %d, want 1 — a working endpoint entered the retry ladder: %+v", len(results), results)
	}
	if !results[0].OK() {
		t.Fatalf("delivery refused: %+v", results[0])
	}
	if got != "hookuser:hookpass" {
		t.Fatalf("receiver saw basic-auth %q, want hookuser:hookpass", got)
	}
}
