package api

// The wiring, not the plumbing.
//
// The predictable way this feature dies is that internal/webhook ships
// complete and unit-tested, the settings page saves endpoints, "send test
// delivery" answers 200 because it calls the dispatcher directly — and not one
// real node-down, quota trip, expiry or cert warning ever leaves the box,
// because the seam between a lifecycle event and a sink was never widened. So
// these tests drive real lifecycle paths and watch a real HTTP server.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/webhook"
)

type capturedDelivery struct {
	method  string
	headers http.Header
	body    []byte
}

// webhookSink is an endpoint that records what it was sent.
func webhookSink(t *testing.T, status int) (*httptest.Server, func() []capturedDelivery) {
	t.Helper()
	var mu sync.Mutex
	var got []capturedDelivery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, capturedDelivery{method: r.Method, headers: r.Header.Clone(), body: body})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []capturedDelivery {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedDelivery(nil), got...)
	}
}

func drain(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.webhooks.Drain(ctx); err != nil {
		t.Fatalf("draining the webhook queue: %v", err)
	}
}

// TestANodeGoingSilentPostsASignedWebhook is the whole row in one test: a real
// lifecycle event, reached through the real maintenance sweep, arriving at a
// real HTTP endpoint with a signature the receiver can check.
//
// s.notifier is deliberately nil. That pins the guard in checkNodesReachable,
// which used to return early whenever Telegram was unconfigured — silently
// disabling node monitoring for precisely the operator who configured webhooks
// INSTEAD of Telegram.
func TestANodeGoingSilentPostsASignedWebhook(t *testing.T) {
	s, _ := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateNode(&store.Node{Name: "edge-1", Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateWebhook(&store.WebhookEndpoint{
		URL: srv.URL, Secret: "s3cr3t", Events: "node-down", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	s.notifier = nil
	s.runMaintenance()
	drain(t, s)

	got := deliveries()
	if len(got) != 1 {
		t.Fatalf("webhook deliveries = %d, want 1", len(got))
	}
	d := got[0]
	if d.method != http.MethodPost {
		t.Errorf("delivery method = %s, want POST", d.method)
	}
	if h := d.headers.Get(webhook.HeaderEvent); h != "node-down" {
		t.Errorf("%s = %q, want node-down", webhook.HeaderEvent, h)
	}
	if d.headers.Get(webhook.HeaderDelivery) == "" {
		t.Errorf("%s is empty; a receiver cannot deduplicate a retry", webhook.HeaderDelivery)
	}

	var body struct {
		ID      string `json:"id"`
		Event   string `json:"event"`
		Subject string `json:"subject"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(d.body, &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, d.body)
	}
	if body.Event != "node-down" || body.Subject != "edge-1" {
		t.Errorf("body = %+v, want event=node-down subject=edge-1", body)
	}
	if body.ID == "" || body.Message == "" {
		t.Errorf("body is missing an id or a message: %+v", body)
	}

	// The signature, recomputed here rather than by calling webhook.Sign: a
	// helper checked against itself proves only that it is deterministic.
	ts, mac := parseSignature(t, d.headers.Get(webhook.HeaderSignature))
	want := hmacHex("s3cr3t", strconv.FormatInt(ts, 10)+"."+string(d.body))
	if !hmac.Equal([]byte(mac), []byte(want)) {
		t.Errorf("signature v1 = %s, want %s", mac, want)
	}
	if age := time.Since(time.Unix(ts, 0)); age > time.Minute || age < -time.Minute {
		t.Errorf("signed timestamp is %s away from now; a receiver checking replay age would reject it", age)
	}
}

// A recovered node has to say so, or a receiver holds an incident open for a
// problem that fixed itself. The recovery is only sent for an alert that was
// actually raised.
func TestARecoveredNodePostsAResolutionAndAHealthyOneSaysNothing(t *testing.T) {
	s, _ := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateWebhook(&store.WebhookEndpoint{
		URL: srv.URL, Secret: "s3cr3t", Events: "node-down", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	s.notifier = nil

	// A node that has been healthy all along must produce nothing at all.
	seen := time.Now()
	healthy := &store.Node{Name: "edge-ok", EnrollToken: "tok-ok", Enrolled: true, LastSeen: &seen}
	if err := s.db.CreateNode(healthy); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	drain(t, s)
	if got := deliveries(); len(got) != 0 {
		t.Fatalf("a healthy fleet produced %d deliveries: %+v", len(got), got)
	}

	// Now one goes silent, then comes back.
	down := &store.Node{Name: "edge-1", EnrollToken: "tok-1", Enrolled: true}
	if err := s.db.CreateNode(down); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	drain(t, s)

	now := time.Now()
	down.LastSeen = &now
	if err := s.db.SaveNode(down); err != nil {
		t.Fatal(err)
	}
	s.runMaintenance()
	drain(t, s)

	var types []string
	for _, d := range deliveries() {
		types = append(types, d.headers.Get(webhook.HeaderEvent))
	}
	if strings.Join(types, ",") != "node-down,node-down.resolved" {
		t.Fatalf("event sequence = %v, want [node-down node-down.resolved]", types)
	}
}

// The condition is still true on the next sweep and the one after. Without the
// repeat gate a single down node posts once a minute for as long as it is down.
func TestAStillDownNodeIsNotReAnnouncedOnEverySweep(t *testing.T) {
	s, _ := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateNode(&store.Node{Name: "edge-1", Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateWebhook(&store.WebhookEndpoint{
		URL: srv.URL, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	s.notifier = nil

	for i := 0; i < 3; i++ {
		s.runMaintenance()
		drain(t, s)
	}
	if got := deliveries(); len(got) != 1 {
		t.Fatalf("three sweeps over one down node produced %d deliveries, want 1", len(got))
	}
}

// Creating an account is a fact, not a condition, and it reaches the webhook
// sink through the audit helper — which is what makes every path that creates a
// user produce the event, not just the one handler.
func TestCreatingAUserThroughTheAPIPostsAWebhook(t *testing.T) {
	s, token := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateWebhook(&store.WebhookEndpoint{
		URL: srv.URL, Events: "user.created", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	code, body := realPost(t, s, "/api/admin/users", token, map[string]any{"username": "alice"})
	if code != 201 {
		t.Fatalf("creating a user returned %d: %s", code, body)
	}
	drain(t, s)

	got := deliveries()
	if len(got) != 1 {
		t.Fatalf("user.created deliveries = %d, want 1", len(got))
	}
	if h := got[0].headers.Get(webhook.HeaderEvent); h != "user.created" {
		t.Fatalf("%s = %q, want user.created", webhook.HeaderEvent, h)
	}
	if !strings.Contains(string(got[0].body), `"subject":"alice"`) {
		t.Fatalf("body does not name the account: %s", got[0].body)
	}
}

// An endpoint that asked for one event must not receive every other one.
func TestAnEndpointOnlyReceivesTheEventsItSubscribedTo(t *testing.T) {
	s, token := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateWebhook(&store.WebhookEndpoint{
		URL: srv.URL, Events: "cert-expiry", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateNode(&store.Node{Name: "edge-1", Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	s.notifier = nil

	s.runMaintenance()
	if code, body := realPost(t, s, "/api/admin/users", token, map[string]any{"username": "bob"}); code != 201 {
		t.Fatalf("creating a user returned %d: %s", code, body)
	}
	drain(t, s)

	if got := deliveries(); len(got) != 0 {
		t.Fatalf("a cert-expiry subscriber received %d unrelated deliveries: %+v", len(got), got)
	}
}

// A disabled endpoint is off, not merely hidden from the list.
func TestADisabledEndpointReceivesNothing(t *testing.T) {
	s, _ := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	if err := s.db.CreateNode(&store.Node{Name: "edge-1", Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateWebhook(&store.WebhookEndpoint{URL: srv.URL, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	s.notifier = nil

	s.runMaintenance()
	drain(t, s)
	if got := deliveries(); len(got) != 0 {
		t.Fatalf("a disabled endpoint received %d deliveries", len(got))
	}
}

// The outcome of every attempt lands on the row. Without it a broken receiver
// looks identical to a panel that never sends anything.
func TestAFailedDeliveryIsRecordedAgainstTheEndpoint(t *testing.T) {
	s, _ := adminAPI(t)
	srv, _ := webhookSink(t, http.StatusUnauthorized)

	if err := s.db.CreateNode(&store.Node{Name: "edge-1", Enrolled: true}); err != nil {
		t.Fatal(err)
	}
	row := &store.WebhookEndpoint{URL: srv.URL, Enabled: true}
	if err := s.db.CreateWebhook(row); err != nil {
		t.Fatal(err)
	}
	s.notifier = nil

	s.runMaintenance()
	drain(t, s)

	after, err := s.db.WebhookByID(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastStatus != http.StatusUnauthorized {
		t.Errorf("last_status = %d, want 401", after.LastStatus)
	}
	if after.LastError == "" || after.LastAttempt == nil {
		t.Errorf("a failed delivery left no trace: %+v", after)
	}
}

func parseSignature(t *testing.T, header string) (int64, string) {
	t.Helper()
	if header == "" {
		t.Fatal("no signature header; a receiver cannot tell this delivery from a forged one")
	}
	var ts int64
	var mac string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				t.Fatalf("signature timestamp %q: %v", v, err)
			}
			ts = n
		case "v1":
			mac = v
		}
	}
	if ts == 0 || mac == "" {
		t.Fatalf("signature %q is not t=<unix>,v1=<hex>", header)
	}
	return ts, mac
}

func hmacHex(secret, message string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(message))
	return hex.EncodeToString(m.Sum(nil))
}

// The endpoints an operator drives from the settings page, through the real
// router: an editor that saves rows nothing delivers to is the same feature
// gap in a different place.
func TestTheWebhookSettingsEndpointsRoundTrip(t *testing.T) {
	s, token := adminAPI(t)
	srv, deliveries := webhookSink(t, 200)

	code, body := realPost(t, s, "/api/admin/settings/webhooks", token, map[string]any{
		"url": srv.URL, "events": "node-down", "enabled": true,
	})
	if code != 201 {
		t.Fatalf("creating a webhook returned %d: %s", code, body)
	}
	var created struct {
		ID     uint   `json:"id"`
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	// The secret is minted when none was given, and shown exactly once: an
	// unsigned webhook hands anyone who learns the URL a remote control.
	if created.Secret == "" {
		t.Fatal("no signing secret was minted; deliveries would be unauthenticated")
	}

	code, body = doGET(t, s, "/api/admin/settings/webhooks", token)
	if code != 200 {
		t.Fatalf("listing returned %d: %s", code, body)
	}
	if strings.Contains(body, created.Secret) {
		t.Errorf("the list endpoint echoes the signing secret: %s", body)
	}
	if !strings.Contains(body, `"has_secret":true`) {
		t.Errorf("the list does not say whether a secret is set: %s", body)
	}

	// The test button delivers now and reports the receiver's own answer.
	path := fmt.Sprintf("/api/admin/settings/webhooks/%d/test", created.ID)
	if code, body = realPost(t, s, path, token, map[string]any{}); code != 200 {
		t.Fatalf("test delivery returned %d: %s", code, body)
	}
	if got := deliveries(); len(got) != 1 {
		t.Fatalf("test deliveries = %d, want 1", len(got))
	}

	// A typo in the event list has to fail on save. An endpoint subscribed to
	// "node_down" is enabled, green and permanently silent.
	code, body = realPost(t, s, "/api/admin/settings/webhooks", token, map[string]any{
		"url": srv.URL, "events": "node_down",
	})
	if code != 422 {
		t.Fatalf("an unknown event type was accepted with %d: %s", code, body)
	}
	if code, body = realPost(t, s, "/api/admin/settings/webhooks", token, map[string]any{
		"url": "ftp://example.com/hook",
	}); code != 400 {
		t.Fatalf("a non-HTTP URL was accepted with %d: %s", code, body)
	}

	// Disabling it stops delivery without deleting the row.
	path = fmt.Sprintf("/api/admin/settings/webhooks/%d", created.ID)
	if code, body = adminReq(t, s, http.MethodPut, path, token, map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("updating returned %d: %s", code, body)
	}
	after, err := s.db.WebhookByID(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled || after.Secret != created.Secret {
		t.Fatalf("the update did not disable it, or lost the secret: %+v", after)
	}

	if code, body = doDELETE(t, s, path, token); code != 200 {
		t.Fatalf("deleting returned %d: %s", code, body)
	}
	rows, err := s.db.ListWebhooks()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("%d endpoints survived the delete", len(rows))
	}
}

// The subscription list and the events the panel actually raises are two copies
// of the same fact, and a second copy is a thing that drifts.
//
// Both directions are a silent failure. An event raised but not listed cannot be
// subscribed to by name, so an operator who narrows their subscription stops
// receiving it and nothing says so. An event listed but never raised is a tick
// box that produces an endpoint which is enabled, green and permanently silent.
// The scheduler's own alerts are the ones that drift first: they reach the seam
// through the Notify closure as bare strings, and nothing in internal/api
// mentions them by name.
func TestTheSubscribableEventsAreExactlyTheOnesThePanelRaises(t *testing.T) {
	constants := map[string]string{}
	src, err := os.ReadFile(filepath.FromSlash("../telegram/notify.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(Event\w+)\s+Event\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		constants[m[1]] = m[2]
	}
	if len(constants) == 0 {
		t.Fatal("no telegram.Event constants found; this guard is not reading what it thinks it is")
	}

	raised := map[string]string{
		eventUserCreated: "admin.go (the audit helper)",
		eventUserDeleted: "admin.go (the audit helper)",
	}
	scan := func(glob string, re *regexp.Regexp, resolve func(string) (string, bool)) {
		files, _ := filepath.Glob(filepath.FromSlash(glob))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				v, ok := resolve(m[1])
				if !ok {
					t.Fatalf("%s raises %q, which is not a declared telegram.Event", f, m[1])
				}
				raised[v] = filepath.Base(f)
			}
		}
	}
	scan("*.go", regexp.MustCompile(`s\.emit(?:Resolve)?\(telegram\.(Event\w+)`),
		func(name string) (string, bool) { v, ok := constants[name]; return v, ok })
	scan("../job/*.go", regexp.MustCompile(`s\.alert\("([^"]+)"`),
		func(lit string) (string, bool) { return lit, true })

	if len(raised) < 5 {
		t.Fatalf("only found %d raised events; the scan is not matching the call sites", len(raised))
	}

	known := map[string]bool{}
	for _, e := range webhookEventTypes {
		known[e] = true
	}
	var unlistable, unraised []string
	for e, where := range raised {
		if !known[e] {
			unlistable = append(unlistable, e+" (raised in "+where+")")
		}
	}
	for _, e := range webhookEventTypes {
		if _, ok := raised[e]; !ok {
			unraised = append(unraised, e)
		}
	}
	sort.Strings(unlistable)
	sort.Strings(unraised)
	if len(unlistable) > 0 {
		t.Errorf("these events are raised but cannot be subscribed to by name, so narrowing a "+
			"subscription silently drops them — add them to webhookEventTypes:\n  %s",
			strings.Join(unlistable, "\n  "))
	}
	if len(unraised) > 0 {
		t.Errorf("these events can be subscribed to and nothing raises them, so the endpoint is "+
			"enabled, green and permanently silent:\n  %s", strings.Join(unraised, "\n  "))
	}
}

// Owning the panel does not imply owning the hosting account. 169.254.169.254
// hands instance credentials to anything on the box, and a stored webhook is
// retried by a background goroutine with no operator watching — so the refusal
// has to happen at save time, not only at delivery time.
func TestAWebhookPointedAtTheMetadataServiceIsRefusedOnSave(t *testing.T) {
	s, token := adminAPI(t)

	code, body := realPost(t, s, "/api/admin/settings/webhooks", token, map[string]any{
		"url": "http://169.254.169.254/hook", "events": "node-down", "enabled": true,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a webhook aimed at the cloud metadata service was accepted with %d: %s", code, body)
	}

	// The other half of the policy: an internal receiver is the DOCUMENTED case
	// for a webhook (internal/webhook/transport.go), so loopback must still save.
	code, body = realPost(t, s, "/api/admin/settings/webhooks", token, map[string]any{
		"url": "http://127.0.0.1:2053/hook", "events": "node-down", "enabled": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("a webhook aimed at an internal receiver was refused with %d: %s", code, body)
	}
}
