package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// PoolState is where an entry sits in its lifecycle.
type PoolState string

// Pool entry states.
const (
	// PoolActive means the entry is healthy and handed out to clients.
	PoolActive PoolState = "active"
	// PoolDegraded means it failed at least one check but is under the
	// retirement threshold, so it is still handed out.
	PoolDegraded PoolState = "degraded"
	// PoolRetired means it failed enough checks to be pulled from rotation.
	PoolRetired PoolState = "retired"
)

// PoolEntry is one domain in the rotation pool.
type PoolEntry struct {
	// Domain is the fully-qualified hostname clients connect to.
	Domain string `json:"domain"`
	// Zone and RecordID let the pool delete the record when it retires the
	// entry, so a burned name does not linger in DNS.
	Zone     string    `json:"zone"`
	RecordID string    `json:"record_id,omitempty"`
	Provider string    `json:"provider,omitempty"`
	Target   string    `json:"target,omitempty"`
	Proxied  bool      `json:"proxied"`
	State    PoolState `json:"state"`
	// Failures is the consecutive-failure count; a passing check resets it.
	Failures  int       `json:"failures"`
	Checks    int       `json:"checks"`
	LatencyMs int64     `json:"latency_ms,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// Healthy reports whether the entry should still be handed to clients.
func (e PoolEntry) Healthy() bool { return e.State != PoolRetired }

// PoolRepo persists pool entries.
type PoolRepo interface {
	ListPoolEntries(pool string) ([]PoolEntry, error)
	PutPoolEntry(pool string, entry PoolEntry) error
	DeletePoolEntry(pool, domain string) error
	// ListPoolNames returns every pool that has entries.
	//
	// Without it a pool could only be reached by NAME, so nothing could sweep
	// them: the rotate handler's own comment says "rotating with no config just
	// health-checks and retires, which is a legitimate scheduled operation" —
	// and no scheduler could enumerate what to run it against. A pool whose
	// domains had all been blocked stayed that way until an operator happened
	// to open the page, which is the exact failure the pool exists to prevent.
	ListPoolNames() ([]string, error)
}

// ProbeResult is one health probe outcome.
type ProbeResult struct {
	OK      bool
	Latency time.Duration
	Detail  string
}

// Prober health-checks a pool domain. The default implementation completes a
// real TLS handshake, because a name that resolves but whose edge refuses the
// SNI is exactly the failure a pool exists to route around.
type Prober interface {
	Probe(ctx context.Context, domain string) ProbeResult
}

// TLSProber dials domain:Port and completes a TLS handshake against it.
type TLSProber struct {
	Port    int
	Timeout time.Duration
	// DialContext is injectable so tests probe a local listener.
	DialContext        func(ctx context.Context, network, addr string) (net.Conn, error)
	InsecureSkipVerify bool
	// MinVersion is the TLS floor; zero means 1.2, which is what a working
	// inbound must at least negotiate.
	MinVersion uint16
}

// Probe implements Prober.
func (p TLSProber) Probe(ctx context.Context, domain string) ProbeResult {
	port := p.Port
	if port == 0 {
		port = 443
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	minVersion := p.MinVersion
	if minVersion == 0 {
		minVersion = tls.VersionTLS12
	}
	host := NormalizeDomain(domain)
	addr := net.JoinHostPort(host, fmt.Sprint(port))

	start := time.Now()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := p.DialContext
	if dial == nil {
		d := net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	conn, err := dial(dctx, "tcp", addr)
	if err != nil {
		return ProbeResult{Detail: fmt.Sprintf("connect %s: %s", addr, tidyDialError(err))}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         minVersion,
		InsecureSkipVerify: p.InsecureSkipVerify, //nolint:gosec // health probe; caller opts in explicitly
	})
	if err := tlsConn.HandshakeContext(dctx); err != nil {
		tlsConn.Close()
		return ProbeResult{Detail: fmt.Sprintf("tls %s: %s", host, tidyTLSError(err))}
	}
	state := tlsConn.ConnectionState()
	tlsConn.Close()
	return ProbeResult{
		OK: true, Latency: time.Since(start),
		Detail: fmt.Sprintf("TLS %s handshake with %s", tlsVersionName(state.Version), host),
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
