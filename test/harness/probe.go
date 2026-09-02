//go:build harness

// probe.go generates the traffic whose arrival is the proof. Every probe here
// goes through the client core's local inbound and nothing else: the harness
// container has no route to the origin, so a probe that returns the right bytes
// can only have travelled through the tunnel.
package harness

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// Origin describes the isolated "internet" the probes talk to.
type Origin struct {
	Host     string // resolvable only from the panel's side of the topology
	HTTPPort int
	TLSPort  int
	DNSPort  int
	UDPPort  int
}

// TCPResult is the outcome of the HTTP payload probe.
type TCPResult struct {
	OK        bool   `json:"ok"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	WantSHA   string `json:"want_sha256,omitempty"`
	Intact    bool   `json:"intact"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Millis    int64  `json:"millis"`
	Error     string `json:"error,omitempty"`
	Scheme    string `json:"scheme"`
	RemoteDNS bool   `json:"remote_dns"`
}

// UDPResult is the outcome of the DNS-over-UDP probe.
type UDPResult struct {
	OK       bool   `json:"ok"`
	Question string `json:"question,omitempty"`
	Answer   string `json:"answer,omitempty"`
	Want     string `json:"want,omitempty"`
	Millis   int64  `json:"millis"`
	Error    string `json:"error,omitempty"`
}

// PayloadSize is the body the TCP probe pulls through the tunnel. It is large
// enough that the panel's byte accounting has something unambiguous to count
// and small enough that a full matrix run stays quick.
const PayloadSize = 262144

// httpClientVia builds an HTTP client whose every connection is a SOCKS5
// CONNECT through the proxy, with the hostname resolved on the far side.
func httpClientVia(socksAddr string, timeout time.Duration) *http.Client {
	d := SocksDialer{Addr: socksAddr, Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
			// Never fall back to a direct connection: a probe that quietly
			// bypassed the tunnel would report a pass it did not earn.
			Proxy: nil,
		},
	}
}

// ProbeHTTP pulls a deterministic payload from the origin through the tunnel
// and verifies it byte for byte. seed makes the body unique per case, so a
// cached or replayed response cannot pass for a fresh transfer.
func ProbeHTTP(socksAddr string, o Origin, seed int64, timeout time.Duration) TCPResult {
	res := TCPResult{Scheme: "http", RemoteDNS: true, WantSHA: ExpectedPayloadSHA(seed, PayloadSize)}
	start := time.Now()
	cl := httpClientVia(socksAddr, timeout)
	url := fmt.Sprintf("http://%s:%d/payload?size=%d&seed=%d", o.Host, o.HTTPPort, PayloadSize, seed)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	resp, err := cl.Do(req)
	if err != nil {
		res.Error = err.Error()
		res.Millis = time.Since(start).Milliseconds()
		return res
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, PayloadSize+1))
	res.Millis = time.Since(start).Milliseconds()
	res.Bytes = int(n)
	res.ExitIP = resp.Header.Get("X-Client-IP")
	if err != nil {
		res.Error = "read body: " + err.Error()
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("origin answered HTTP %d", resp.StatusCode)
		return res
	}
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	res.Intact = res.SHA256 == res.WantSHA && res.Bytes == PayloadSize
	res.OK = res.Intact
	if !res.Intact {
		res.Error = fmt.Sprintf("payload mismatch: got %d bytes sha=%s, want %d bytes sha=%s",
			res.Bytes, res.SHA256, PayloadSize, res.WantSHA)
	}
	return res
}

// ProbeHTTPS repeats the payload probe over TLS to the origin, so the tunnel is
// shown to carry an opaque byte stream and not just cleartext HTTP. certPin is
// the hex SHA-256 of the origin's leaf certificate, itself fetched through the
// tunnel — the origin is self-signed, and pinning is stricter than skipping
// verification while needing no shared trust store.
func ProbeHTTPS(socksAddr string, o Origin, seed int64, timeout time.Duration, certPin string) TCPResult {
	res := TCPResult{Scheme: "https", RemoteDNS: true, WantSHA: ExpectedPayloadSHA(seed, PayloadSize)}
	start := time.Now()
	cl := httpClientVia(socksAddr, timeout)
	tr := cl.Transport.(*http.Transport)
	tr.TLSClientConfig = pinnedTLSConfig(o.Host, certPin)
	url := fmt.Sprintf("https://%s:%d/payload?size=%d&seed=%d", o.Host, o.TLSPort, PayloadSize, seed)
	resp, err := cl.Get(url)
	if err != nil {
		res.Error = err.Error()
		res.Millis = time.Since(start).Milliseconds()
		return res
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, PayloadSize+1))
	res.Millis = time.Since(start).Milliseconds()
	res.Bytes = int(n)
	if err != nil {
		res.Error = "read body: " + err.Error()
		return res
	}
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	res.Intact = res.SHA256 == res.WantSHA && res.Bytes == PayloadSize
	res.OK = res.Intact
	return res
}

// pinnedTLSConfig verifies the peer by exact leaf-certificate digest.
func pinnedTLSConfig(serverName, pinHex string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the stricter pin check below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("origin presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if pinHex == "" {
				return fmt.Errorf("no certificate pin was fetched for the origin")
			}
			if got != pinHex {
				return fmt.Errorf("origin certificate %s does not match pin %s", got, pinHex)
			}
			return nil
		},
	}
}

// OriginCertPin fetches the origin's advertised leaf-certificate digest over
// plain HTTP through the tunnel.
func OriginCertPin(socksAddr string, o Origin, timeout time.Duration) (string, error) {
	cl := httpClientVia(socksAddr, timeout)
	resp, err := cl.Get(fmt.Sprintf("http://%s:%d/tlspin", o.Host, o.HTTPPort))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ProbeDNS resolves a name that only the isolated origin serves, over UDP,
// through the tunnel. It is the explicit UDP proof: a proxy that relays TCP but
// silently drops UDP fails here while passing every HTTP probe.
func ProbeDNS(socksAddr string, o Origin, timeout time.Duration) UDPResult {
	res := UDPResult{Question: ProbeName, Want: ProbeAddr}
	start := time.Now()
	d := SocksDialer{Addr: socksAddr, Timeout: timeout}
	conn, err := d.UDPAssociate(net.JoinHostPort(o.Host, fmt.Sprint(o.DNSPort)))
	if err != nil {
		res.Error = err.Error()
		res.Millis = time.Since(start).Milliseconds()
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(rand.Int31n(65535)) //nolint:gosec // a probe id, not a secret
	q, err := BuildQuery(id, ProbeName, TypeA)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	// One retry: a first datagram is occasionally lost while a UDP association
	// is still being set up inside the tunnel, and a retry is what a resolver
	// would do anyway.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := conn.Write(q); err != nil {
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			lastErr = err
			continue
		}
		gotID, _, answers, err := ParseMessage(buf[:n])
		if err != nil {
			lastErr = err
			continue
		}
		if gotID != id {
			lastErr = fmt.Errorf("dns reply id %d does not match query id %d", gotID, id)
			continue
		}
		for _, a := range answers {
			if a.Type == TypeA {
				res.Answer = a.A
				res.OK = a.A == ProbeAddr
				res.Millis = time.Since(start).Milliseconds()
				if !res.OK {
					res.Error = fmt.Sprintf("resolved to %s, want %s", a.A, ProbeAddr)
				}
				return res
			}
		}
		lastErr = ErrNoAnswer
	}
	res.Millis = time.Since(start).Milliseconds()
	if lastErr != nil {
		res.Error = lastErr.Error()
	}
	return res
}

// ProbeDirect checks whether the origin is reachable WITHOUT the tunnel. The
// matrix is only meaningful if this fails: it is the control that proves a
// passing case really used the proxy.
func ProbeDirect(o Origin, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(o.Host, fmt.Sprint(o.HTTPPort)), timeout)
	if err != nil {
		return err
	}
	_ = c.Close()
	return fmt.Errorf("origin %s:%d is reachable without the tunnel — the harness networks are not isolated",
		o.Host, o.HTTPPort)
}

// ProbeName / ProbeAddr are served only by the harness origin's DNS responder.
const (
	ProbeName = "probe.harness.test"
	ProbeAddr = "203.0.113.7"
)

// PayloadBytes generates the deterministic body the origin serves and the probe
// expects. Both sides call this, so a mismatch means the bytes changed in
// flight rather than that the two sides disagree about the content.
func PayloadBytes(seed int64, size int) []byte {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test data
	b := make([]byte, size)
	_, _ = r.Read(b)
	return b
}

// ExpectedPayloadSHA is the digest of PayloadBytes(seed, size).
func ExpectedPayloadSHA(seed int64, size int) string {
	sum := sha256.Sum256(PayloadBytes(seed, size))
	return hex.EncodeToString(sum[:])
}
