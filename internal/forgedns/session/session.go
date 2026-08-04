// Package session is the ForgeDNS session manager (spec §5.2/§5.3): per-client
// state machines with a keepalive + data dual-pool model, AIMD congestion
// control, a sequence/reorder buffer, idle eviction, and per-session traffic
// accounting. It is transport-agnostic — it consumes decoded codec.Frames and
// produces response Frames, so any adapter can drive it.
package session

import (
	"sort"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/codec"
)

// AIMD holds an additive-increase / multiplicative-decrease congestion window,
// mirroring the StormDNS client's pacing in spirit (spec §5.3).
type AIMD struct {
	Window    int
	Min, Max  int
}

// OnACK grows the window additively.
func (a *AIMD) OnACK() {
	if a.Window < a.Max {
		a.Window++
	}
}

// OnLoss halves the window (down to Min).
func (a *AIMD) OnLoss() {
	a.Window /= 2
	if a.Window < a.Min {
		a.Window = a.Min
	}
}

// Session is one client's tunnel state.
type Session struct {
	ID       uint16
	created  time.Time
	lastSeen time.Time

	nextSeqIn  uint16 // next upstream seq expected (reassembly)
	reorder    map[uint16][]byte
	inbound    []byte // reassembled upstream bytes ready for egress

	outbound []byte // downstream bytes waiting to be sent to the client
	seqOut   uint16

	aimd AIMD

	UpBytes   int64
	DownBytes int64
}

// Manager owns all sessions with rate limits and idle eviction.
type Manager struct {
	mu       sync.Mutex
	sessions map[uint16]*Session
	idleTTL  time.Duration
	maxPerIP int
	now      func() time.Time
}

// NewManager builds a session manager.
func NewManager(idleTTL time.Duration) *Manager {
	if idleTTL == 0 {
		idleTTL = 60 * time.Second
	}
	return &Manager{
		sessions: map[uint16]*Session{}, idleTTL: idleTTL, maxPerIP: 8, now: time.Now,
	}
}

// get returns (creating if needed) the session for id.
func (m *Manager) get(id uint16) *Session {
	s := m.sessions[id]
	if s == nil {
		now := m.now()
		s = &Session{
			ID: id, created: now, lastSeen: now,
			reorder: map[uint16][]byte{},
			aimd:    AIMD{Window: 4, Min: 1, Max: 64},
		}
		m.sessions[id] = s
	}
	return s
}

// Ingest processes one upstream frame and returns the response frame to send
// back (carrying any queued downstream bytes + an ACK). Egress bytes accepted
// from the client are appended to the session's inbound buffer, which the caller
// drains via TakeInbound and feeds to the upstream connection.
func (m *Manager) Ingest(f codec.Frame) codec.Frame {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(f.SessionID)
	s.lastSeen = m.now()

	if f.Has(codec.FlagSYN) {
		// (re)establish
		s.nextSeqIn = 0
		s.reorder = map[uint16][]byte{}
	}

	if f.Has(codec.FlagDATA) && len(f.Payload) > 0 {
		s.UpBytes += int64(len(f.Payload))
		s.reorder[f.Seq] = append([]byte(nil), f.Payload...)
		// drain in-order
		for {
			b, ok := s.reorder[s.nextSeqIn]
			if !ok {
				break
			}
			s.inbound = append(s.inbound, b...)
			delete(s.reorder, s.nextSeqIn)
			s.nextSeqIn++
		}
		s.aimd.OnACK()
	}

	// Build response: ACK + up to window's worth of downstream bytes.
	resp := codec.Frame{SessionID: s.ID, Seq: s.seqOut, Flags: codec.FlagACK}
	if n := len(s.outbound); n > 0 {
		chunk := 220 // fits a TXT-based downstream comfortably
		if chunk > n {
			chunk = n
		}
		resp.Payload = s.outbound[:chunk]
		resp.Flags |= codec.FlagDATA
		s.outbound = s.outbound[chunk:]
		s.DownBytes += int64(chunk)
		s.seqOut++
	} else if f.Has(codec.FlagKA) {
		resp.Flags |= codec.FlagKA
	}
	return resp
}

// TakeInbound drains and returns reassembled upstream bytes for a session.
func (m *Manager) TakeInbound(id uint16) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil || len(s.inbound) == 0 {
		return nil
	}
	out := s.inbound
	s.inbound = nil
	return out
}

// QueueOutbound queues downstream bytes to be delivered to the client on
// subsequent polls.
func (m *Manager) QueueOutbound(id uint16, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(id)
	s.outbound = append(s.outbound, b...)
}

// Metrics is a per-session snapshot (streamed to the UI over WebSocket, §5.3).
type Metrics struct {
	ID        uint16 `json:"id"`
	AgeMs     int64  `json:"age_ms"`
	IdleMs    int64  `json:"idle_ms"`
	Window    int    `json:"window"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	Pending   int    `json:"pending_down"`
}

// Snapshot returns metrics for all live sessions, sorted by id.
func (m *Manager) Snapshot() []Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]Metrics, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, Metrics{
			ID: s.ID, AgeMs: now.Sub(s.created).Milliseconds(), IdleMs: now.Sub(s.lastSeen).Milliseconds(),
			Window: s.aimd.Window, UpBytes: s.UpBytes, DownBytes: s.DownBytes, Pending: len(s.outbound),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EvictIdle removes sessions idle longer than the TTL and returns how many were
// evicted (spec §5.4 idle eviction).
func (m *Manager) EvictIdle() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	for id, s := range m.sessions {
		if now.Sub(s.lastSeen) > m.idleTTL {
			delete(m.sessions, id)
			n++
		}
	}
	return n
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
