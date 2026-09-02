// Package egress carries a ForgeDNS session's reassembled bytes to a real
// destination, and the destination's replies back.
//
// Without it the native tunnel was a well-built loop that discarded its input.
// The session manager reassembled upstream bytes into a per-session buffer and
// nothing ever drained it; nothing ever queued downstream bytes. TakeInbound and
// QueueOutbound — the two methods that exist for exactly this — had no callers
// outside their own tests. So the panel answered DNS correctly, created
// sessions, counted traffic, showed a client config, and moved nothing: an
// operator delegated a zone, imported the config, and got a tunnel that
// connected and then did nothing at all.
//
// The upstream-binary adapters (CottenDNS et al.) did tunnel, which is why this
// was survivable and easy to miss — the native path is the one that looked
// finished and was not.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/forgedns/session"
)

// Dialer opens the destination for one session's stream.
//
// A function rather than an address so the two modes the zone model already
// describes both fit: "tcp" dials a fixed forward address, and "socks5" hands
// back one end of an in-memory pipe whose other end is being served by this
// process's own SOCKS5 handler.
type Dialer func(ctx context.Context, sessionID uint64) (net.Conn, error)

// Options bound a bridge. Zero values take the defaults below.
type Options struct {
	// MaxConns caps simultaneous upstream connections. A DNS tunnel is reachable
	// by anyone who can send a UDP packet, so an unbounded map here is a file
	// descriptor exhaustion primitive.
	MaxConns int
	// IdleTimeout closes an upstream connection whose session has gone quiet.
	IdleTimeout time.Duration
	// DialTimeout bounds one dial.
	DialTimeout time.Duration
	// ReadChunk is the upstream read size.
	ReadChunk int
	// SweepInterval is how often evicted sessions are reaped.
	SweepInterval time.Duration
}

func (o *Options) withDefaults() {
	if o.MaxConns <= 0 {
		o.MaxConns = 1024
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 120 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.ReadChunk <= 0 {
		o.ReadChunk = 8 << 10
	}
	if o.SweepInterval <= 0 {
		o.SweepInterval = 15 * time.Second
	}
}

// Counters report what the bridge did, so a tunnel that carries nothing can be
// told apart from one nobody used.
type Counters struct {
	Opened       uint64
	DialFailed   uint64
	Refused      uint64 // over MaxConns
	BytesUp      uint64 // client -> destination
	BytesDown    uint64 // destination -> client
	Closed       uint64
	ClosedByPeer uint64
}

type upstreamConn struct {
	nc       net.Conn
	lastUsed time.Time
	closed   bool
	once     sync.Once
	done     chan struct{}
}

// Bridge joins a session manager to upstream connections.
type Bridge struct {
	sessions *session.Manager
	dial     Dialer
	opts     Options

	mu       sync.Mutex
	conns    map[uint64]*upstreamConn
	counters Counters
	closed   bool

	stop chan struct{}
	wg   sync.WaitGroup
	now  func() time.Time
}

// New creates a bridge and starts its sweeper.
func New(m *session.Manager, dial Dialer, opts Options) *Bridge {
	opts.withDefaults()
	b := &Bridge{
		sessions: m, dial: dial, opts: opts,
		conns: map[uint64]*upstreamConn{},
		stop:  make(chan struct{}), now: time.Now,
	}
	b.wg.Add(1)
	go b.sweep()
	return b
}

// Counters returns a snapshot.
func (b *Bridge) Counters() Counters {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counters
}

// Deliver moves whatever the session has reassembled to its destination.
//
// Called synchronously from the DNS query path, because that is when bytes
// arrive: a DNS tunnel has no other clock.
func (b *Bridge) Deliver(ctx context.Context, id uint64) {
	payload := b.sessions.TakeInbound(id)
	if len(payload) == 0 {
		// No new bytes. Still touch the connection so a session that is only
		// polling for downstream data does not look idle and get reaped out
		// from under a client that is waiting for a slow reply.
		b.touch(id)
		return
	}
	c, err := b.connFor(ctx, id)
	if err != nil {
		return
	}
	if _, err := c.nc.Write(payload); err != nil {
		b.Close(id)
		return
	}
	b.mu.Lock()
	b.counters.BytesUp += uint64(len(payload))
	b.mu.Unlock()
}

func (b *Bridge) touch(id uint64) {
	b.mu.Lock()
	if c := b.conns[id]; c != nil {
		c.lastUsed = b.now()
	}
	b.mu.Unlock()
}

// connFor returns the session's upstream connection, opening one on first use.
func (b *Bridge) connFor(ctx context.Context, id uint64) (*upstreamConn, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("egress: bridge is closed")
	}
	if c := b.conns[id]; c != nil {
		c.lastUsed = b.now()
		b.mu.Unlock()
		return c, nil
	}
	if len(b.conns) >= b.opts.MaxConns {
		b.counters.Refused++
		b.mu.Unlock()
		return nil, errors.New("egress: too many open tunnel connections")
	}
	// Reserve the slot before dialing so two concurrent queries for one session
	// cannot both dial and leave an orphaned socket that nothing ever closes.
	placeholder := &upstreamConn{lastUsed: b.now(), done: make(chan struct{})}
	b.conns[id] = placeholder
	b.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, b.opts.DialTimeout)
	nc, err := b.dial(dialCtx, id)
	cancel()
	if err != nil {
		b.mu.Lock()
		delete(b.conns, id)
		b.counters.DialFailed++
		b.mu.Unlock()
		close(placeholder.done)
		return nil, fmt.Errorf("egress: dial for session %d: %w", id, err)
	}

	b.mu.Lock()
	placeholder.nc = nc
	placeholder.lastUsed = b.now()
	b.counters.Opened++
	b.mu.Unlock()

	b.wg.Add(1)
	go b.pumpDown(id, placeholder)
	return placeholder, nil
}

// pumpDown reads from the destination and queues bytes for the client.
func (b *Bridge) pumpDown(id uint64, c *upstreamConn) {
	defer b.wg.Done()
	defer b.Close(id)
	buf := make([]byte, b.opts.ReadChunk)
	for {
		select {
		case <-c.done:
			return
		case <-b.stop:
			return
		default:
		}
		n, err := c.nc.Read(buf)
		if n > 0 {
			if !b.enqueue(id, buf[:n], c) {
				return
			}
			b.mu.Lock()
			b.counters.BytesDown += uint64(n)
			c.lastUsed = b.now()
			b.mu.Unlock()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return
			}
			b.mu.Lock()
			b.counters.ClosedByPeer++
			b.mu.Unlock()
			return
		}
	}
}

// enqueue hands bytes to the session queue without ever exceeding its room.
//
// QueueOutbound truncates past its cap and counts the rest as dropped, which is
// right for a queue and wrong for a byte stream: dropping from the middle of a
// TCP stream does not slow the sender, it corrupts the stream, and the client
// sees a protocol error nowhere near the cause. So this waits for room instead.
// Polling is the honest mechanism here — the tunnel's own clock is the client's
// next DNS query, and there is nothing else to wait on.
func (b *Bridge) enqueue(id uint64, data []byte, c *upstreamConn) bool {
	for len(data) > 0 {
		room := b.sessions.OutboundRoom(id)
		if room <= 0 {
			select {
			case <-c.done:
				return false
			case <-b.stop:
				return false
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		n := min(room, len(data))
		b.sessions.QueueOutbound(id, data[:n])
		data = data[n:]
	}
	return true
}

// Close tears down one session's upstream connection.
func (b *Bridge) Close(id uint64) {
	b.mu.Lock()
	c := b.conns[id]
	if c == nil {
		b.mu.Unlock()
		return
	}
	delete(b.conns, id)
	b.counters.Closed++
	b.mu.Unlock()

	c.once.Do(func() {
		close(c.done)
		if c.nc != nil {
			_ = c.nc.Close()
		}
	})
}

// sweep closes connections whose session the manager has evicted, or that have
// gone idle.
//
// Without this every abandoned tunnel session leaks a socket: the session
// manager evicts its own state on an idle timer, and the connection it was
// bound to would stay open forever with nobody left to read it.
func (b *Bridge) sweep() {
	defer b.wg.Done()
	t := time.NewTicker(b.opts.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			live := map[uint64]bool{}
			for _, id := range b.sessions.LiveIDs() {
				live[id] = true
			}
			cutoff := b.now().Add(-b.opts.IdleTimeout)
			b.mu.Lock()
			var doomed []uint64
			for id, c := range b.conns {
				if !live[id] || c.lastUsed.Before(cutoff) {
					doomed = append(doomed, id)
				}
			}
			b.mu.Unlock()
			for _, id := range doomed {
				b.Close(id)
			}
		}
	}
}

// Shutdown closes every connection and stops the sweeper.
func (b *Bridge) Shutdown() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	ids := make([]uint64, 0, len(b.conns))
	for id := range b.conns {
		ids = append(ids, id)
	}
	b.mu.Unlock()

	close(b.stop)
	for _, id := range ids {
		b.Close(id)
	}
	b.wg.Wait()
}

// TCPDialer forwards every session to one fixed address — the zone model's
// "tcp" mode with ForwardIP/ForwardPort.
func TCPDialer(addr string) Dialer {
	var d net.Dialer
	return func(ctx context.Context, _ uint64) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}
