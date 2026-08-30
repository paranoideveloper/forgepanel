package api

// Live core logs from a remote node.
//
// A node that will not serve says why in its own journal, on a machine the
// operator has to SSH into to read. The panel could see that a node was unhappy
// — a heartbeat arriving, a core that never comes up — and could not say one
// word about the cause, so every remote-node problem ended in a terminal on
// another continent.
//
// The transport is the heartbeat. The agent is strictly PULL: it polls the panel
// every ten seconds and the panel can never open a connection back, because a
// node is commonly behind NAT and always behind its own firewall. So the lines
// ride the request the node is already making, and the panel fans them out to
// whoever is watching.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/websocket"

	"github.com/forgepanel/forgepanel/internal/core/supervisor"
)

const (
	// nodeLogRing is how much of each node's output the panel keeps. Enough that
	// opening the panel after a failure shows the failure, small enough that a
	// fleet of chatty nodes cannot grow the panel's heap without bound.
	nodeLogRing = 400
	// nodeLogBurst bounds a node's contribution to ONE heartbeat. An agent whose
	// core is looping on a stack trace would otherwise hand the panel an
	// unbounded slice every ten seconds.
	nodeLogBurst = 200
	// nodeLogQueue is how far behind a watching browser may fall before lines are
	// dropped for it. Dropping is deliberate: the alternative is a blocked send
	// inside the heartbeat handler, where one stuck admin tab would stall the
	// node's config bundle and eventually the node itself.
	nodeLogQueue = 256
	// nodeLogKeepalive is how long the stream may be silent before it sends an
	// empty frame. Idle proxies commonly cut a connection at 60 seconds, and a
	// node that is behaving says nothing for far longer than that.
	nodeLogKeepalive = 30 * time.Second
	// nodeLogWriteTimeout stops a peer that has stopped reading — a closed laptop
	// lid, a tab the browser froze — from pinning a goroutine and a subscription
	// for as long as the kernel will hold the send buffer.
	nodeLogWriteTimeout = 10 * time.Second
)

// nodeLogHub holds each node's recent output and the admins watching it.
//
// The zero value is usable: it is a plain field on Server, and the panel has two
// constructors — a hub that needed constructing would be exactly the kind of
// thing that gets wired into one of them and not the other.
type nodeLogHub struct {
	mu    sync.Mutex
	rings map[uint]*supervisor.LogRing
	// next is the sequence position the panel expects from each node, which is
	// what makes a re-sent heartbeat idempotent. The agent advances its own
	// cursor only when a post SUCCEEDS, exactly as it does for traffic counters,
	// so a dropped response means the next heartbeat repeats lines the panel has
	// already filed. Without this, the operator's log panel fills with duplicates
	// of the one error they are trying to read.
	next map[uint]int
	// epochs is the agent process each node's sequence numbers belong to. A
	// restarted agent begins counting at zero again, which is indistinguishable
	// from a re-send of the very first batch unless it says which process it is —
	// and getting that wrong one way loses every line after a restart, the other
	// way duplicates lines on any dropped response.
	epochs map[uint]string
	subs   map[uint]map[chan string]struct{}
}

// ring returns the node's buffer, creating it on first use. Caller holds mu.
func (h *nodeLogHub) ring(id uint) *supervisor.LogRing {
	if h.rings == nil {
		h.rings = map[uint]*supervisor.LogRing{}
	}
	r := h.rings[id]
	if r == nil {
		r = supervisor.NewLogRing(nodeLogRing)
		h.rings[id] = r
	}
	return r
}

// publish files the lines a node reported, which began at absolute position seq
// of the agent process identified by epoch, and hands the new ones to every
// watcher.
func (h *nodeLogHub) publish(id uint, epoch string, seq int, lines []string) {
	if len(lines) == 0 || seq < 0 {
		return
	}
	if extra := len(lines) - nodeLogBurst; extra > 0 {
		// Keep the TAIL — when a core is looping, the newest lines describe the
		// state it is actually in — and carry the sequence forward with it, or
		// every later batch would be judged against a position that no longer
		// matches what was kept.
		lines, seq = lines[extra:], seq+extra
	}

	h.mu.Lock()
	if h.next == nil {
		h.next = map[uint]int{}
		h.epochs = map[uint]string{}
	}
	if h.epochs[id] != epoch {
		// A different agent process. Its numbering starts from zero and has
		// nothing to do with the last one's, so the expectation is reset rather
		// than the batch being read as a re-send and discarded — which is what
		// would make the log panel go permanently silent after every restart.
		h.epochs[id] = epoch
		h.next[id] = 0
	}
	want := h.next[id]
	if seq > want {
		// A gap: the panel restarted, or a heartbeat was lost outright. The
		// missing lines are unrecoverable, so take what there is.
		want = seq
	}
	end := seq + len(lines)
	if end <= want {
		// Entirely a re-send of what is already filed.
		h.mu.Unlock()
		return
	}
	lines = lines[want-seq:]
	h.next[id] = end
	r := h.ring(id)
	for _, ln := range lines {
		r.Add(ln)
	}
	watchers := make([]chan string, 0, len(h.subs[id]))
	for ch := range h.subs[id] {
		watchers = append(watchers, ch)
	}
	h.mu.Unlock()

	for _, ch := range watchers {
		for _, ln := range lines {
			select {
			case ch <- ln:
			default:
				// Full: this watcher loses lines rather than slowing the node
				// down. See nodeLogQueue.
			}
		}
	}
}

// subscribe returns everything the panel currently holds for a node, a channel
// of what comes next, and the func that unsubscribes.
func (h *nodeLogHub) subscribe(id uint) ([]string, <-chan string, func()) {
	ch := make(chan string, nodeLogQueue)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs == nil {
		h.subs = map[uint]map[chan string]struct{}{}
	}
	if h.subs[id] == nil {
		h.subs[id] = map[chan string]struct{}{}
	}
	h.subs[id][ch] = struct{}{}
	// Snapshotted under the same lock that registers the channel, so a line
	// published in between is delivered exactly once instead of falling into the
	// gap between the snapshot and the subscription.
	backlog := h.ring(id).Snapshot()
	return backlog, ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if subs := h.subs[id]; subs != nil {
			delete(subs, ch)
			if len(subs) == 0 {
				delete(h.subs, id)
			}
		}
	}
}

// forget drops a deleted node's buffer.
func (h *nodeLogHub) forget(id uint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.rings, id)
	delete(h.next, id)
	delete(h.epochs, id)
}

// handleNodeLogsStream streams one node's core output to a watching admin.
//
// A WebSocket rather than a polled endpoint because the thing being watched is a
// core coming up or failing, which happens in the seconds after a config change
// — and because a poll would be answered from this same ring anyway, with a
// cursor to keep per open tab.
func (s *Server) handleNodeLogsStream(c *gin.Context) {
	if s.db == nil {
		fail(c, 503, "no database")
		return
	}
	id := parseID(c)
	n, err := s.db.NodeByID(id)
	if err != nil {
		fail(c, 404, "not found")
		return
	}
	name := n.Name

	srv := websocket.Server{
		// A WebSocket handshake is NOT subject to the same-origin policy: any
		// page on the internet can open one against a panel the operator is
		// logged into. The token in the query is what authenticates this route
		// and a foreign page cannot read it, so this is defence in depth rather
		// than the lock — but x/net/websocket's default handshake accepts every
		// origin, and "the other check is good" is how both of them end up
		// missing.
		Handshake: func(cfg *websocket.Config, req *http.Request) error {
			if cfg.Origin == nil {
				// No Origin at all is a non-browser client — curl, the panel's
				// own tooling, a test. It cannot be tricked into sending one,
				// which is the entire risk this guards.
				return nil
			}
			if strings.EqualFold(cfg.Origin.Host, req.Host) {
				return nil
			}
			return fmt.Errorf("origin %s is not this panel", cfg.Origin.Host)
		},
		Handler: func(ws *websocket.Conn) { s.streamNodeLogs(ws, id, name) },
	}
	srv.ServeHTTP(c.Writer, c.Request)
}

func (s *Server) streamNodeLogs(ws *websocket.Conn, id uint, name string) {
	defer ws.Close()
	backlog, live, cancel := s.logs.subscribe(id)
	defer cancel()

	// A browser that closes a tab does not always close the socket cleanly.
	// Reading in parallel is what turns a vanished client into a closed channel
	// rather than a goroutine holding a subscription for the life of the panel.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		_, _ = io.Copy(io.Discard, ws)
	}()

	send := func(line string) bool {
		_ = ws.SetWriteDeadline(time.Now().Add(nodeLogWriteTimeout))
		return websocket.Message.Send(ws, line) == nil
	}

	if len(backlog) == 0 {
		// Say so. An empty box is indistinguishable from a stream that is not
		// working, and this panel exists for the moment the operator has already
		// stopped trusting what they are looking at.
		if !send(fmt.Sprintf("— %s has reported no output yet; lines appear as it does —", name)) {
			return
		}
	}
	for _, ln := range backlog {
		if !send(ln) {
			return
		}
	}

	tick := time.NewTicker(nodeLogKeepalive)
	defer tick.Stop()
	for {
		select {
		case <-gone:
			return
		case ln := <-live:
			if !send(ln) {
				return
			}
		case <-tick.C:
			// An empty frame: a node that is behaving says nothing for hours and
			// an idle proxy would close a stream that is working. The client
			// ignores empty messages.
			if !send("") {
				return
			}
		}
	}
}
