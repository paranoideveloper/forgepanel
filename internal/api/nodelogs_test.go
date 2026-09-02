package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
	"golang.org/x/net/websocket"
)

// Live core logs from a remote node.
//
// Everything an operator needs to diagnose a node — why xray refused the config,
// which inbound failed to bind — was written to that node's journal and stayed
// there. The panel knew a node was unhappy and could not say why, so every
// remote-node problem ended in an SSH session. The lines ride the heartbeat
// because the agent is strictly pull: the panel can never open a connection to a
// node that is behind NAT, which every node behind a home or cloud firewall is.

// dialNodeLogs opens the log stream the way the browser does: a WebSocket with
// the token in the query, because `new WebSocket()` cannot set a header.
func dialNodeLogs(t *testing.T, srv *httptest.Server, id uint, token string) *websocket.Conn {
	t.Helper()
	url := fmt.Sprintf("%s/api/admin/nodes/%d/logs?access_token=%s",
		"ws"+strings.TrimPrefix(srv.URL, "http"), id, token)
	ws, err := websocket.Dial(url, "", srv.URL)
	if err != nil {
		t.Fatalf("dialling the node log stream: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	return ws
}

// readLine returns the next line of node output, skipping the empty keepalive
// frames and the "nothing yet" notice, neither of which is something a node said.
func readLine(t *testing.T, ws *websocket.Conn) string {
	t.Helper()
	for i := 0; i < 10; i++ {
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		var line string
		if err := websocket.Message.Receive(ws, &line); err != nil {
			t.Fatalf("reading from the node log stream: %v", err)
		}
		if line == "" || strings.HasPrefix(line, "—") {
			continue
		}
		return line
	}
	t.Fatal("the stream carried nothing but keepalives")
	return ""
}

// The lines a node has already reported must be there the moment the panel is
// opened. A stream that only carries what happens next is useless for the case
// it exists for: something already went wrong and the operator is looking now.
func TestTheNodeLogPanelOpensOnWhatTheNodeAlreadySaid(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "logs1", Address: "203.0.113.40", EnrollToken: "tok-l1", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"token":     "tok-l1",
		"logs":      []string{"xray: failed to start inbound in-443", "xray: address already in use"},
		"log_seq":   0,
		"log_epoch": "p1",
	})
	if code, b := doPOST(t, s, "/api/node/heartbeat", "", string(body)); code != 200 {
		t.Fatalf("heartbeat: %d %s", code, b)
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ws := dialNodeLogs(t, srv, n.ID, token)

	if got := readLine(t, ws); !strings.Contains(got, "failed to start inbound") {
		t.Fatalf("first line = %q, want the failure the node already reported", got)
	}
	if got := readLine(t, ws); !strings.Contains(got, "address already in use") {
		t.Fatalf("second line = %q", got)
	}
}

// The live half: a line a node reports while an admin is watching reaches that
// admin without a reload.
func TestALineANodeReportsReachesAWatchingAdmin(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "logs2", Address: "203.0.113.41", EnrollToken: "tok-l2", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ws := dialNodeLogs(t, srv, n.ID, token)

	body, _ := json.Marshal(map[string]any{
		"token": "tok-l2", "logs": []string{"sing-box: started"},
		"log_seq": 0, "log_epoch": "p1",
	})
	if code, b := doPOST(t, s, "/api/node/heartbeat", "", string(body)); code != 200 {
		t.Fatalf("heartbeat: %d %s", code, b)
	}
	if got := readLine(t, ws); !strings.Contains(got, "sing-box: started") {
		t.Fatalf("live line = %q", got)
	}
}

// The agent re-sends anything the panel did not acknowledge, exactly as it
// re-sends traffic counters. Without a sequence number the panel would append
// the same lines twice on every dropped response and the panel would fill with
// duplicates of the one error the operator is trying to read.
func TestReSentNodeLogLinesAreNotDuplicated(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "logs3", Address: "203.0.113.42", EnrollToken: "tok-l3", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(map[string]any{
		"token": "tok-l3", "logs": []string{"a", "b"},
		"log_seq": 0, "log_epoch": "p1",
	})
	// The same batch again with one new line, as an agent whose previous
	// response was lost re-sends it: same process, same starting position.
	again, _ := json.Marshal(map[string]any{
		"token": "tok-l3", "logs": []string{"a", "b", "c"},
		"log_seq": 0, "log_epoch": "p1",
	})
	for _, b := range []string{string(first), string(again)} {
		if code, resp := doPOST(t, s, "/api/node/heartbeat", "", b); code != 200 {
			t.Fatalf("heartbeat: %d %s", code, resp)
		}
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ws := dialNodeLogs(t, srv, n.ID, token)

	var got []string
	for i := 0; i < 3; i++ {
		got = append(got, readLine(t, ws))
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("the stream replayed %v, want [a b c] — a re-sent batch was appended twice", got)
	}
}

// The one the Go tests would otherwise miss entirely. The admin group's auth is
// Authorization-header based and a browser's `new WebSocket()` cannot set a
// header, so a perfectly correct handler behind a correctly mounted route still
// answers 401 for the only client that will ever call it.
func TestTheLogStreamIsReachableWithoutAnAuthorizationHeader(t *testing.T) {
	s, _ := adminAPI(t)
	n := &store.Node{Name: "logs4", Address: "203.0.113.43", EnrollToken: "tok-l4", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	url := fmt.Sprintf("%s/api/admin/nodes/%d/logs", "ws"+strings.TrimPrefix(srv.URL, "http"), n.ID)
	if ws, err := websocket.Dial(url, "", srv.URL); err == nil {
		_ = ws.Close()
		t.Fatal("the log stream accepted an unauthenticated WebSocket")
	}
}

// A query token is not a general-purpose credential path. Accepting it on
// ordinary requests would put a working session token in every proxy log and
// Referer header the panel touches, so it is confined to the handshake that
// cannot carry a header.
func TestAQueryTokenDoesNotAuthenticateAnOrdinaryRequest(t *testing.T) {
	s, token := adminAPI(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/admin/nodes?access_token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("a plain GET authenticated by query token returned %d, want 401", resp.StatusCode)
	}
}

// The other half of the same problem: a restarted agent numbers from zero again,
// and reading that as a re-send would leave the log panel permanently silent for
// exactly the node that just restarted.
func TestARestartedAgentsLogsAreNotMistakenForARepeat(t *testing.T) {
	s, token := adminAPI(t)
	n := &store.Node{Name: "logs5", Address: "203.0.113.44", EnrollToken: "tok-l5", Enrolled: true}
	if err := s.db.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(map[string]any{
		"token": "tok-l5", "logs": []string{"old-1", "old-2"},
		"log_seq": 0, "log_epoch": "p1",
	})
	// A new agent process: same node, same starting position, different epoch.
	after, _ := json.Marshal(map[string]any{
		"token": "tok-l5", "logs": []string{"new-1"},
		"log_seq": 0, "log_epoch": "p2",
	})
	for _, b := range []string{string(before), string(after)} {
		if code, resp := doPOST(t, s, "/api/node/heartbeat", "", b); code != 200 {
			t.Fatalf("heartbeat: %d %s", code, resp)
		}
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ws := dialNodeLogs(t, srv, n.ID, token)

	var got []string
	for i := 0; i < 3; i++ {
		got = append(got, readLine(t, ws))
	}
	if strings.Join(got, ",") != "old-1,old-2,new-1" {
		t.Fatalf("the stream replayed %v; a restarted agent's output was dropped as a repeat", got)
	}
}
