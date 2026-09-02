package dns

import (
	"context"
	"net"
	"time"
)

// CloudflareIPv4Ranges is Cloudflare's published anycast IPv4 space. Every
// address in it terminates TLS for every orange-clouded hostname, which is what
// makes the clean-IP trick work: a client dials an address that is not blocked
// while sni/host stay on the real domain.
var CloudflareIPv4Ranges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// ScanConfig configures a clean-IP scan.
type ScanConfig struct {
	// CIDRs is the address space to sample. Empty uses CloudflareIPv4Ranges.
	CIDRs []string
	// Port is the TCP port to test, normally 443.
	Port int
	// SNI is the server name sent in the TLS handshake. It must be a hostname
	// the edge actually serves, or every handshake fails for the wrong reason.
	SNI string
	// Samples is how many addresses to draw. Zero means 256.
	Samples int
	// Concurrency bounds in-flight probes. Zero means 64.
	Concurrency int
	// TCPTimeout bounds phase one. Zero means 2s.
	TCPTimeout time.Duration
	// TLSTimeout bounds one phase-two handshake. Zero means 4s.
	TLSTimeout time.Duration
	// Probes is how many TLS handshakes per surviving address, which is what
	// makes a loss percentage meaningful. Zero means 3.
	Probes int
	// Keep is how many ranked results to return. Zero means all.
	Keep int
	// DialContext is injectable so tests scan a local listener.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// InsecureSkipVerify disables certificate validation. The scan measures
	// reachability and handshake latency, not trust, and a test listener uses a
	// self-signed certificate — but production scans against a real edge should
	// leave it false.
	InsecureSkipVerify bool
	// Addresses, when set, replaces sampling entirely and scans exactly these.
	Addresses []string
}

// IPResult is one scanned address.
type IPResult struct {
	IP string `json:"ip"`
	// TCPOK is phase one: the address accepted a TCP connection.
	TCPOK bool `json:"tcp_ok"`
	// TLSOK is phase two: at least one TLS handshake completed.
	TLSOK bool `json:"tls_ok"`
	// TLS13 is true when the negotiated version was TLS 1.3, which is what a
	// modern edge offers and what REALITY-adjacent transports assume.
	TLS13     bool    `json:"tls13"`
	Attempts  int     `json:"attempts"`
	Successes int     `json:"successes"`
	LossPct   float64 `json:"loss_pct"`
	MinRTTMs  int64   `json:"min_rtt_ms"`
	AvgRTTMs  int64   `json:"avg_rtt_ms"`
	// Score ranks results; lower is better.
	Score float64 `json:"score"`
	ALPN  string  `json:"alpn,omitempty"`
	Error string  `json:"error,omitempty"`
}

// ScanReport is a completed scan.
type ScanReport struct {
	SNI       string     `json:"sni"`
	Port      int        `json:"port"`
	Sampled   int        `json:"sampled"`
	TCPPassed int        `json:"tcp_passed"`
	TLSPassed int        `json:"tls_passed"`
	Results   []IPResult `json:"results"`
	StartedAt string     `json:"started_at"`
	Duration  string     `json:"duration"`
}

// Working returns the addresses that completed a TLS handshake, best first.
func (r ScanReport) Working() []IPResult {
	var out []IPResult
	for _, res := range r.Results {
		if res.TLSOK {
			out = append(out, res)
		}
	}
	return out
}

// WorkingIPs returns just the addresses, best first.
func (r ScanReport) WorkingIPs() []string {
	working := r.Working()
	out := make([]string, 0, len(working))
	for _, res := range working {
		out = append(out, res.IP)
	}
	return out
}

func (c ScanConfig) samples() int {
	if c.Samples > 0 {
		return c.Samples
	}
	return 256
}

func (c ScanConfig) concurrency() int {
	if c.Concurrency > 0 {
		return c.Concurrency
	}
	return 64
}

func (c ScanConfig) tcpTimeout() time.Duration {
	if c.TCPTimeout > 0 {
		return c.TCPTimeout
	}
	return 2 * time.Second
}

func (c ScanConfig) tlsTimeout() time.Duration {
	if c.TLSTimeout > 0 {
		return c.TLSTimeout
	}
	return 4 * time.Second
}

func (c ScanConfig) probes() int {
	if c.Probes > 0 {
		return c.Probes
	}
	return 3
}

func (c ScanConfig) dial(ctx context.Context, addr string) (net.Conn, error) {
	if c.DialContext != nil {
		return c.DialContext(ctx, "tcp", addr)
	}
	d := net.Dialer{Timeout: c.tcpTimeout()}
	return d.DialContext(ctx, "tcp", addr)
}
