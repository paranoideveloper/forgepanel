package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scan runs the two-phase scan: a cheap TCP connect across the whole sample,
// then repeated TLS 1.3 handshakes against the survivors. Splitting it this way
// matters because a blocked range fails at connect in milliseconds, so the
// expensive handshake budget is spent only on addresses that could work.
func Scan(ctx context.Context, cfg ScanConfig) (*ScanReport, error) {
	if strings.TrimSpace(cfg.SNI) == "" {
		return nil, &Error{Op: "scan", Kind: KindValidation,
			Message:     "a server name (SNI) is required",
			Remediation: "pass the proxied hostname, e.g. --scan-sni ws-node1.example.com. The edge only completes a handshake for a name it serves."}
	}
	port := cfg.Port
	if port == 0 {
		port = 443
	}
	started := time.Now()

	targets := cfg.Addresses
	if len(targets) == 0 {
		var err error
		targets, err = SampleIPs(cfg.CIDRs, cfg.samples())
		if err != nil {
			return nil, err
		}
	}
	report := &ScanReport{
		SNI: NormalizeDomain(cfg.SNI), Port: port, Sampled: len(targets),
		StartedAt: started.UTC().Format(time.RFC3339),
	}

	// Phase one: TCP reachability.
	phase1 := runConcurrent(ctx, targets, cfg.concurrency(), func(ctx context.Context, ip string) IPResult {
		res := IPResult{IP: ip}
		addr := net.JoinHostPort(ip, fmt.Sprint(port))
		dctx, cancel := context.WithTimeout(ctx, cfg.tcpTimeout())
		conn, err := cfg.dial(dctx, addr)
		cancel()
		if err != nil {
			res.Error = tidyDialError(err)
			return res
		}
		conn.Close()
		res.TCPOK = true
		return res
	})

	survivors := make([]string, 0, len(phase1))
	byIP := make(map[string]IPResult, len(phase1))
	for _, r := range phase1 {
		byIP[r.IP] = r
		if r.TCPOK {
			survivors = append(survivors, r.IP)
		}
	}
	report.TCPPassed = len(survivors)

	// Phase two: repeated TLS 1.3 handshakes for latency and loss.
	phase2 := runConcurrent(ctx, survivors, cfg.concurrency(), func(ctx context.Context, ip string) IPResult {
		return tlsProbe(ctx, cfg, ip, port)
	})
	for _, r := range phase2 {
		byIP[r.IP] = r
		if r.TLSOK {
			report.TLSPassed++
		}
	}

	results := make([]IPResult, 0, len(byIP))
	for _, r := range byIP {
		r.Score = score(r)
		results = append(results, r)
	}
	// Rank: working first, then by score (latency penalised by loss), then IP
	// for a stable order across runs.
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.TLSOK != b.TLSOK {
			return a.TLSOK
		}
		if a.TCPOK != b.TCPOK {
			return a.TCPOK
		}
		if a.Score != b.Score {
			return a.Score < b.Score
		}
		return a.IP < b.IP
	})
	if cfg.Keep > 0 && len(results) > cfg.Keep {
		results = results[:cfg.Keep]
	}
	report.Results = results
	report.Duration = time.Since(started).Round(time.Millisecond).String()
	return report, nil
}

// score ranks a result; lower is better. Loss is weighted heavily because a
// lossy edge address produces exactly the intermittent-disconnect complaint
// that is hardest to diagnose later.
func score(r IPResult) float64 {
	if !r.TLSOK {
		return 1e9
	}
	base := float64(r.AvgRTTMs)
	if base <= 0 {
		base = 1
	}
	return base * (1 + 4*r.LossPct/100)
}

// tlsProbe performs cfg.Probes TLS 1.3 handshakes against one address.
func tlsProbe(ctx context.Context, cfg ScanConfig, ip string, port int) IPResult {
	res := IPResult{IP: ip, TCPOK: true, Attempts: cfg.probes()}
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	var total time.Duration
	var min time.Duration
	var lastErr string
	for i := 0; i < cfg.probes(); i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		dctx, cancel := context.WithTimeout(ctx, cfg.tlsTimeout())
		conn, err := cfg.dial(dctx, addr)
		if err != nil {
			cancel()
			lastErr = tidyDialError(err)
			continue
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: NormalizeDomain(cfg.SNI),
			// Pinning both bounds to 1.3 is the point of this phase: an edge
			// that only offers 1.2 is not the modern anycast front the client
			// config assumes, and a middlebox that downgrades shows up here.
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // reachability probe, trust is checked by the client at connect time
		})
		err = tlsConn.HandshakeContext(dctx)
		elapsed := time.Since(start)
		if err != nil {
			tlsConn.Close()
			cancel()
			lastErr = tidyTLSError(err)
			continue
		}
		state := tlsConn.ConnectionState()
		res.TLSOK = true
		res.TLS13 = state.Version == tls.VersionTLS13
		if state.NegotiatedProtocol != "" {
			res.ALPN = state.NegotiatedProtocol
		}
		res.Successes++
		total += elapsed
		if min == 0 || elapsed < min {
			min = elapsed
		}
		tlsConn.Close()
		cancel()
	}
	if res.Attempts > 0 {
		res.LossPct = float64(res.Attempts-res.Successes) / float64(res.Attempts) * 100
	}
	if res.Successes > 0 {
		res.AvgRTTMs = (total / time.Duration(res.Successes)).Milliseconds()
		res.MinRTTMs = min.Milliseconds()
	}
	if !res.TLSOK {
		res.Error = lastErr
	}
	return res
}

// tidyDialError strips the noisy address prefix from a dial failure and names
// the likely cause, since "connection refused" and "i/o timeout" mean very
// different things when scanning for censorship-clean addresses.
func tidyDialError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "context deadline exceeded"):
		return "timeout (packets dropped — typically a blocked address)"
	case strings.Contains(msg, "connection refused"):
		return "connection refused (nothing listening, or an in-path reset)"
	case strings.Contains(msg, "connection reset"):
		return "connection reset (an in-path device closed the connection)"
	case strings.Contains(msg, "network is unreachable"):
		return "network unreachable (no route from this host)"
	}
	return truncate(msg, 160)
}

func tidyTLSError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "protocol version not supported"), strings.Contains(msg, "server does not support TLS 1.3"):
		return "no TLS 1.3 (edge or middlebox negotiated an older version)"
	case strings.Contains(msg, "certificate"):
		return "certificate rejected: " + truncate(msg, 120)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline"):
		return "handshake timeout (TCP connected but the handshake never completed — a classic SNI-based block)"
	case strings.Contains(msg, "connection reset"):
		return "handshake reset (an in-path device rejected the SNI)"
	}
	return truncate(msg, 160)
}

// runConcurrent runs fn over items with bounded parallelism.
func runConcurrent(ctx context.Context, items []string, workers int, fn func(context.Context, string) IPResult) []IPResult {
	if len(items) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}
	jobs := make(chan string)
	out := make([]IPResult, len(items))
	index := make(map[string]int, len(items))
	for i, item := range items {
		index[item] = i
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				res := fn(ctx, item)
				mu.Lock()
				out[index[item]] = res
				mu.Unlock()
			}
		}()
	}
	for _, item := range items {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
	return out
}
