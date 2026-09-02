package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A node that will not serve says why on its own stderr, on a machine the
// operator has to SSH into. Everything the panel could tell them was "this node
// is unhappy" — so every remote-node problem ended in a terminal on another
// continent. The lines ride the heartbeat because the agent is strictly pull:
// the panel can never open a connection to a node behind NAT.

// capturingPanel records every heartbeat body the agent posts.
type capturingPanel struct {
	mu     sync.Mutex
	bodies []map[string]any
	fail   bool
	srv    *httptest.Server
}

func newCapturingPanel(t *testing.T) *capturingPanel {
	t.Helper()
	p := &capturingPanel{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/heartbeat" {
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": 1})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p.mu.Lock()
		p.bodies = append(p.bodies, body)
		fail := p.fail
		p.mu.Unlock()
		if fail {
			// A lost response: the panel accepted the post and the agent never
			// learns it. Exactly the case cumulative reporting exists for.
			http.Error(w, "boom", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"xray_config": ""})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *capturingPanel) last() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.bodies) == 0 {
		return nil
	}
	return p.bodies[len(p.bodies)-1]
}

func (p *capturingPanel) logsOf(i int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, _ := p.bodies[i]["logs"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// talkativeCore writes fixed lines to stderr and then stays up, so the agent has
// a real process whose output it must capture rather than a stub.
func talkativeCore(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, "fake-core")
	// Only the RUN invocation behaves like a core. Validation ("-test"/"check")
	// and every capability probe the agent makes must return immediately, or the
	// heartbeat blocks on a stub pretending to be a proxy.
	script := "#!/bin/sh\nif [ \"$1\" != \"run\" ] || [ \"$2\" != \"-config\" ]; then exit 0; fi\n"
	for _, l := range lines {
		script += "echo '" + l + "' >&2\n"
	}
	script += "sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// waitForLogs polls until the agent has captured n lines, because the core writes
// them from its own process and the drain is a goroutine.
func waitForLogs(t *testing.T, a *NodeAgent, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		lines, _ := a.collectLogs()
		if len(lines) >= n {
			return lines
		}
		time.Sleep(20 * time.Millisecond)
	}
	lines, _ := a.collectLogs()
	t.Fatalf("the agent captured %d line(s) after 5s, want %d: %v", len(lines), n, lines)
	return nil
}

func TestACoresOutputRidesTheHeartbeat(t *testing.T) {
	dir := t.TempDir()
	p := newCapturingPanel(t)
	bin := talkativeCore(t, dir, "xray: failed to start inbound in-443", "xray: address already in use")

	a := &NodeAgent{panel: p.srv.URL, token: "t", dataDir: dir, engines: testEngines(bin)}
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"x"}]}`})
	defer a.engines["xray"].stop()
	waitForLogs(t, a, 2)

	if _, err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}
	got := p.logsOf(0)
	if len(got) < 2 {
		t.Fatalf("the heartbeat carried %v; the core's output never left the node", got)
	}
	if !strings.Contains(strings.Join(got, "\n"), "address already in use") {
		t.Fatalf("the core's own words are not in the heartbeat: %v", got)
	}
	if _, ok := p.last()["log_epoch"].(string); !ok {
		t.Error("the heartbeat carries no log_epoch, so the panel cannot tell a restart from a re-send")
	}
}

// The cursor advances only on a SUCCESSFUL post, for the same reason the traffic
// counters are cumulative: a dropped response must not cost the operator the
// lines that explain why the node is down.
func TestLinesAreResentUntilThePanelAcceptsThem(t *testing.T) {
	dir := t.TempDir()
	p := newCapturingPanel(t)
	p.fail = true
	bin := talkativeCore(t, dir, "core: one", "core: two")

	a := &NodeAgent{panel: p.srv.URL, token: "t", dataDir: dir, engines: testEngines(bin)}
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"x"}]}`})
	defer a.engines["xray"].stop()
	waitForLogs(t, a, 2)

	if _, err := a.heartbeat(); err == nil {
		t.Fatal("the failing panel returned no error")
	}
	p.mu.Lock()
	p.fail = false
	p.mu.Unlock()
	if _, err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}

	if got := p.logsOf(1); len(got) < 2 {
		t.Fatalf("after a lost response the agent re-sent %v; the lines were dropped", got)
	}
}

// And once accepted they are not sent again, or the panel spends every heartbeat
// filtering out the same lines forever.
func TestAcceptedLinesAreNotSentTwice(t *testing.T) {
	dir := t.TempDir()
	p := newCapturingPanel(t)
	bin := talkativeCore(t, dir, "core: one")

	a := &NodeAgent{panel: p.srv.URL, token: "t", dataDir: dir, engines: testEngines(bin)}
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"x"}]}`})
	defer a.engines["xray"].stop()
	waitForLogs(t, a, 1)

	for i := 0; i < 2; i++ {
		if _, err := a.heartbeat(); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.logsOf(1); len(got) != 0 {
		t.Fatalf("the second heartbeat re-sent %v after the first was accepted", got)
	}
	if seq, _ := p.last()["log_seq"].(float64); int(seq) != 1 {
		t.Errorf("log_seq = %v after one accepted line, want 1", p.last()["log_seq"])
	}
}

// A core that refuses its config is the single most common remote-node failure,
// and the panel used to be told only that the node was alive. It is the node's
// own verdict on itself, so it travels as last_error and turns the node's badge
// red while its heartbeats keep arriving on time.
func TestACoreRejectingItsConfigIsReportedAsLastError(t *testing.T) {
	dir := t.TempDir()
	p := newCapturingPanel(t)
	// A core that fails validation: every config it is offered is refused.
	bin := filepath.Join(dir, "picky-core")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 'invalid inbound settings' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	a := &NodeAgent{panel: p.srv.URL, token: "t", dataDir: dir, engines: testEngines(bin)}
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"x"}]}`})

	if _, err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}
	got, _ := p.last()["last_error"].(string)
	if got == "" {
		t.Fatal("the node reported no last_error; the panel calls a node whose core refuses every config \"connected\"")
	}
	if !strings.Contains(got, "invalid inbound settings") {
		t.Errorf("last_error = %q, want the core's own refusal", got)
	}
}

// And it clears, or one bad config marks a node broken until the agent restarts.
func TestALastErrorClearsOnceTheCoreAcceptsAConfig(t *testing.T) {
	dir := t.TempDir()
	p := newCapturingPanel(t)
	bad := filepath.Join(dir, "picky-core")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho 'nope' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := talkativeCore(t, dir, "core: up")

	a := &NodeAgent{panel: p.srv.URL, token: "t", dataDir: dir, engines: testEngines(bad)}
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"x"}]}`})
	if _, err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.last()["last_error"].(string); got == "" {
		t.Fatal("setup: the refusal was not reported")
	}

	a.engines["xray"].bin = good
	a.applyConfigs(map[string]string{"xray": `{"inbounds":[{"tag":"y"}]}`})
	defer a.engines["xray"].stop()
	if _, err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.last()["last_error"].(string); got != "" {
		t.Fatalf("last_error = %q after the core accepted a config; the node stays red forever", got)
	}
}
