// Package session is the ForgeDNS session manager (spec §5.2/§5.3): per-client
// state machines with a keepalive + data dual-pool model, AIMD congestion
// control, a sequence/reorder buffer, idle eviction, and per-session traffic
// accounting. It is transport-agnostic — it consumes decoded codec.Frames and
// produces response Frames, so any adapter can drive it.
//
// # Downstream delivery is stop-and-wait
//
// DNS over UDP is unreliable and a dropped answer is invisible to the server, so
// downstream bytes are NOT removed from the queue when they are sent. One chunk
// is held in flight; a repeat of the same query replays it byte-for-byte, and
// the queue only advances once the client has acknowledged it. Acknowledgement
// is explicit for v2 (codec.FlagEXT) peers, which carry FrameExt.AckSeq, and
// implicit for v1 peers, for which a *new* request sequence means the previous
// answer arrived. Without this, one lost packet silently deletes bytes from the
// tunnelled stream.
//
// # Session identity
//
// A v2 session id is a 64-bit CSPRNG value and every frame carries a truncated
// HMAC under a per-session key established at handshake. Both matter because the
// replay buffer above hands a stored chunk to whoever asks for a given
// (session, sequence): with a 16-bit guessable id and no authenticator, a third
// party could read another session's downstream data or forge an
// acknowledgement that discards it. v1 sessions have neither property; they stay
// accepted for compatibility and can be turned off with Options.AllowLegacy.
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
	Window   int
	Min, Max int
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

// Options bounds the manager. Every limit exists so that forged or abandoned
// sessions cannot pin unbounded memory; zero values take the defaults below.
type Options struct {
	IdleTTL          time.Duration // evict a session idle this long
	InFlightTTL      time.Duration // drop an unacknowledged chunk after this long
	MaxSessions      int           // hard cap on live sessions
	MaxOutboundBytes int           // per-session downstream queue cap
	MaxReorderFrames int           // per-session out-of-order upstream frames held
	ChunkSize        int           // downstream bytes per answer
	AllowLegacy      bool          // accept unauthenticated v1 frames

	// legacySet records whether AllowLegacy was set explicitly, so the zero
	// Options value can still default it to true.
	legacySet bool
}

func (o *Options) withDefaults() {
	if o.IdleTTL <= 0 {
		o.IdleTTL = 60 * time.Second
	}
	if o.InFlightTTL <= 0 {
		o.InFlightTTL = 30 * time.Second
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = 4096
	}
	if o.MaxOutboundBytes <= 0 {
		o.MaxOutboundBytes = 1 << 20
	}
	if o.MaxReorderFrames <= 0 {
		o.MaxReorderFrames = 256
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = 220 // fits a TXT-based downstream comfortably
	}
	if !o.legacySet {
		o.AllowLegacy = true
	}
}

// Counters are manager-wide observability counters for the transport's failure
// modes. They are snapshots; read them with Counters.
type Counters struct {
	Retransmits      uint64 `json:"retransmits"`
	DuplicateQueries uint64 `json:"duplicate_queries"`
	InvalidSequence  uint64 `json:"invalid_sequence"`
	ExpiredFrames    uint64 `json:"expired_frames"`
	AuthFailures     uint64 `json:"auth_failures"`
	SessionsRejected uint64 `json:"sessions_rejected"`
	OutboundDropped  uint64 `json:"outbound_dropped"`
	StaleUpstream    uint64 `json:"stale_upstream"`
	LegacyRejected   uint64 `json:"legacy_rejected"`
}

// Session is one client's tunnel state.
type Session struct {
	ID  uint64
	key []byte // per-session MAC key; nil for legacy (v1) sessions

	created  time.Time
	lastSeen time.Time

	nextSeqIn uint16 // next upstream seq expected (reassembly)
	reorder   map[uint16][]byte
	inbound   []byte // reassembled upstream bytes ready for egress

	// outbound holds downstream bytes not yet acknowledged. Its head is the
	// in-flight chunk, which is only removed once the client confirms receipt.
	outbound   []byte
	seqOut     uint16    // sequence of the chunk in flight / next to send
	inflight   []byte    // immutable copy of the unacknowledged chunk, nil if none
	inflightAt time.Time // when it was first sent

	lastReqSeq  uint16
	haveLastReq bool

	aimd AIMD

	UpBytes   int64
	DownBytes int64
}

// Manager owns all sessions with rate limits and idle eviction.
type Manager struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
	opts     Options
	counters Counters
	now      func() time.Time
}

// NewManager builds a session manager with default bounds.
func NewManager(idleTTL time.Duration) *Manager {
	return NewManagerWithOptions(Options{IdleTTL: idleTTL})
}

// NewManagerWithOptions builds a session manager with explicit bounds.
func NewManagerWithOptions(o Options) *Manager {
	o.withDefaults()
	return &Manager{sessions: map[uint64]*Session{}, opts: o, now: time.Now}
}

// AllowLegacy returns an Options value with AllowLegacy explicitly set, so that
// callers can disable unauthenticated v1 frames (which the zero value permits
// for compatibility).
func (o Options) WithLegacy(allow bool) Options {
	o.AllowLegacy = allow
	o.legacySet = true
	return o
}

// SetClock overrides the time source (tests).
func (m *Manager) SetClock(f func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = f
}

// Counters returns a snapshot of the manager's counters.
func (m *Manager) Counters() Counters {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters
}

// lookup returns an existing session without creating one.
func (m *Manager) lookup(id uint64) *Session { return m.sessions[id] }

// create allocates a session, honouring the table cap. It returns nil when the
// manager is full.
func (m *Manager) create(id uint64, key []byte) *Session {
	if len(m.sessions) >= m.opts.MaxSessions {
		m.counters.SessionsRejected++
		return nil
	}
	now := m.now()
	s := &Session{
		ID: id, key: key, created: now, lastSeen: now,
		reorder: map[uint16][]byte{},
		aimd:    AIMD{Window: 4, Min: 1, Max: 64},
	}
	m.sessions[id] = s
	return s
}

// getOrCreate is the legacy (v1) path: any 16-bit id may materialise a session.
func (m *Manager) getOrCreate(id uint64) *Session {
	if s := m.sessions[id]; s != nil {
		return s
	}
	return m.create(id, nil)
}

// Ingest processes one upstream frame and returns the response frame to send
// back (carrying any unacknowledged downstream bytes + an ACK). Egress bytes
// accepted from the client are appended to the session's inbound buffer, which
// the caller drains via TakeInbound and feeds to the upstream connection.
//
// A frame that fails authentication is dropped before any session state is
// touched or created, and yields an empty response.
func (m *Manager) Ingest(f codec.Frame) codec.Frame {
	m.mu.Lock()
	defer m.mu.Unlock()

	if f.Has(codec.FlagEXT) {
		return m.ingestExt(f)
	}
	if !m.opts.AllowLegacy {
		m.counters.LegacyRejected++
		return codec.Frame{}
	}
	s := m.getOrCreate(uint64(f.SessionID))
	if s == nil {
		return codec.Frame{}
	}
	return m.advance(s, f, 0, false)
}

// ingestExt handles authenticated v2 frames: handshake, then MAC-verified
// traffic. The caller holds m.mu.
func (m *Manager) ingestExt(f codec.Frame) codec.Frame {
	ext := f.Ext
	if ext == nil {
		m.counters.AuthFailures++
		return codec.Frame{}
	}

	// Handshake: a SYN with no session id asks the server to mint one.
	if f.Has(codec.FlagSYN) && ext.SessionID == 0 {
		id, key, err := codec.NewSessionSecret()
		if err != nil {
			return codec.Frame{}
		}
		s := m.create(id, key)
		if s == nil {
			return codec.Frame{}
		}
		resp := codec.Frame{
			Flags:   codec.FlagSYN | codec.FlagACK | codec.FlagEXT,
			Payload: codec.MakeHandshake(id, key),
			Ext:     &codec.FrameExt{SessionID: id},
		}
		codec.SignFrame(&resp, key)
		return resp
	}

	// Everything else must name a live session and prove it holds the key
	// before any state is read or written.
	s := m.lookup(ext.SessionID)
	if s == nil || s.key == nil || !codec.VerifyFrame(f, s.key) {
		m.counters.AuthFailures++
		return codec.Frame{}
	}
	return m.advance(s, f, ext.AckSeq, ext.HasAck)
}

// advance runs the common per-frame state machine. The caller holds m.mu and has
// already authenticated the frame.
func (m *Manager) advance(s *Session, f codec.Frame, ackSeq uint16, hasAck bool) codec.Frame {
	now := m.now()
	s.lastSeen = now

	isDup := s.haveLastReq && f.Seq == s.lastReqSeq
	if isDup {
		m.counters.DuplicateQueries++
	}

	// --- acknowledgement of the in-flight downstream chunk ------------------
	acked := false
	switch {
	case hasAck:
		// Explicit (v2). Only the sequence actually in flight may commit.
		if s.inflight != nil && ackSeq == s.seqOut {
			acked = true
		} else if s.inflight != nil {
			m.counters.InvalidSequence++
		}
	case s.inflight != nil && s.haveLastReq && f.Seq != s.lastReqSeq:
		// Implicit (v1): the client moved to a new request, so the previous
		// answer reached it. A repeat of the same request does not commit.
		acked = true
	}
	if acked {
		n := len(s.inflight)
		if n <= len(s.outbound) {
			s.outbound = s.outbound[n:]
		} else {
			s.outbound = nil
		}
		s.inflight = nil
		s.seqOut++
		s.aimd.OnACK()
	}

	s.lastReqSeq = f.Seq
	s.haveLastReq = true

	if f.Has(codec.FlagSYN) {
		// (re)establish the upstream reassembly state
		s.nextSeqIn = 0
		s.reorder = map[uint16][]byte{}
	}

	// --- upstream data ------------------------------------------------------
	if f.Has(codec.FlagDATA) && len(f.Payload) > 0 {
		switch {
		case seqBefore(f.Seq, s.nextSeqIn):
			// Already consumed: a retransmission. Dropping it keeps accounting
			// honest and stops the reorder buffer filling with dead entries.
			m.counters.StaleUpstream++
		case s.reorder[f.Seq] != nil:
			m.counters.StaleUpstream++
		case len(s.reorder) >= m.opts.MaxReorderFrames && f.Seq != s.nextSeqIn:
			// The reorder buffer is full: refuse further OUT-OF-ORDER frames so it
			// cannot grow without bound. The in-order head (f.Seq == nextSeqIn) is
			// the one exception — it drains immediately in the loop below and can
			// only shrink the buffer, never grow it. Rejecting it here would
			// permanently stall the stream on its own missing head once the buffer
			// filled with the frames waiting behind it.
			m.counters.InvalidSequence++
		default:
			s.UpBytes += int64(len(f.Payload))
			s.reorder[f.Seq] = append([]byte(nil), f.Payload...)
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
	}

	// --- build the response -------------------------------------------------
	resp := codec.Frame{Seq: s.seqOut, Flags: codec.FlagACK}
	if s.key != nil {
		resp.Flags |= codec.FlagEXT
		resp.Ext = &codec.FrameExt{SessionID: s.ID}
	} else {
		resp.SessionID = uint16(s.ID)
	}

	switch {
	case s.inflight != nil:
		// Replay the unacknowledged chunk byte-for-byte. Not re-billed.
		resp.Payload = s.inflight
		resp.Flags |= codec.FlagDATA
		m.counters.Retransmits++
	case len(s.outbound) > 0:
		n := m.opts.ChunkSize
		if n > len(s.outbound) {
			n = len(s.outbound)
		}
		// Copy, and leave the bytes queued: they are only dropped on ack.
		s.inflight = append([]byte(nil), s.outbound[:n]...)
		s.inflightAt = now
		s.DownBytes += int64(n)
		resp.Payload = s.inflight
		resp.Flags |= codec.FlagDATA
	case f.Has(codec.FlagKA):
		resp.Flags |= codec.FlagKA
	}

	if s.key != nil {
		codec.SignFrame(&resp, s.key)
	}
	return resp
}

// seqBefore reports whether a precedes b in the 16-bit sequence space, using
// wrap-around-safe comparison over half the space.
func seqBefore(a, b uint16) bool { return b != a && b-a < 1<<15 }

// TakeInbound drains and returns reassembled upstream bytes for a session.
func (m *Manager) TakeInbound(id uint64) []byte {
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
// subsequent polls. Bytes beyond the per-session cap are dropped and counted
// rather than growing the queue without bound.
func (m *Manager) QueueOutbound(id uint64, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		if s = m.create(id, nil); s == nil {
			m.counters.OutboundDropped += uint64(len(b))
			return
		}
	}
	room := m.opts.MaxOutboundBytes - len(s.outbound)
	if room <= 0 {
		m.counters.OutboundDropped += uint64(len(b))
		return
	}
	if len(b) > room {
		m.counters.OutboundDropped += uint64(len(b) - room)
		b = b[:room]
	}
	s.outbound = append(s.outbound, b...)
}

// OutboundRoom reports how many downstream bytes this session can accept right
// now.
//
// A producer MUST consult this before calling QueueOutbound. QueueOutbound
// truncates silently past the cap and counts the remainder as dropped, which is
// the correct policy for a queue but the wrong thing to do to a TCP stream:
// dropping bytes out of the middle of one does not slow the sender down, it
// corrupts the stream, and the client sees a protocol error somewhere far from
// the cause. Callers use this to apply backpressure instead.
func (m *Manager) OutboundRoom(id uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return m.opts.MaxOutboundBytes
	}
	room := m.opts.MaxOutboundBytes - len(s.outbound)
	if room < 0 {
		return 0
	}
	return room
}

// LiveIDs returns the ids of every session the manager currently holds.
//
// Used by an egress bridge to notice sessions the manager has evicted, so the
// upstream connection they own is closed rather than left holding a socket for
// a client that is never coming back.
func (m *Manager) LiveIDs() []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint64, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	return out
}

// PendingOutbound returns the queued (unacknowledged) downstream byte count.
func (m *Manager) PendingOutbound(id uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil {
		return len(s.outbound)
	}
	return 0
}

// PendingReorder returns how many out-of-order upstream frames are held.
func (m *Manager) PendingReorder(id uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil {
		return len(s.reorder)
	}
	return 0
}

// ExpireInFlight drops in-flight chunks the client never acknowledged, so an
// abandoned session does not pin them until idle eviction. The bytes stay
// queued; the next poll re-sends them. Returns how many were expired.
func (m *Manager) ExpireInFlight() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	for _, s := range m.sessions {
		if s.inflight != nil && now.Sub(s.inflightAt) > m.opts.InFlightTTL {
			s.inflight = nil
			s.aimd.OnLoss()
			n++
		}
	}
	m.counters.ExpiredFrames += uint64(n)
	return n
}

// Metrics is a per-session snapshot (streamed to the UI over WebSocket, §5.3).
type Metrics struct {
	ID        uint64 `json:"id"`
	AgeMs     int64  `json:"age_ms"`
	IdleMs    int64  `json:"idle_ms"`
	Window    int    `json:"window"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	Pending   int    `json:"pending_down"`
	InFlight  int    `json:"in_flight"`
	Auth      bool   `json:"authenticated"`
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
			Window: s.aimd.Window, UpBytes: s.UpBytes, DownBytes: s.DownBytes,
			Pending: len(s.outbound), InFlight: len(s.inflight), Auth: s.key != nil,
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
		if now.Sub(s.lastSeen) > m.opts.IdleTTL {
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
