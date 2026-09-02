package realityprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// A dest is judged by measurement, so these drive real TLS servers rather than
// asserting on a name list — the name list is exactly what this replaces.

func selfSigned(t *testing.T, host string, filler int) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  ipsFor(host),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	// Padding in an extension, to grow the chain past the threshold on demand.
	if filler > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    []int{1, 2, 3, 4, 5},
			Value: make([]byte, filler),
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A certificate for a literal IP needs an IP SAN; a DNS SAN of "127.0.0.1" does
// not cover it.
func ipsFor(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	return nil
}

func serve(t *testing.T, cert tls.Certificate, alpn []string, maxVer uint16) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn}
	if maxVer != 0 {
		cfg.MaxVersion = maxVer
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				time.Sleep(50 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestAnOversizedCertificateChainIsRejected(t *testing.T) {
	// The measured failure: www.microsoft.com authenticates the client and then
	// cannot relay its own 8126-byte chain, so the tunnel is silent.
	addr := serve(t, selfSigned(t, "127.0.0.1", 9000), []string{"h2"}, 0)
	r := Probe(context.Background(), addr)
	if r.Usable {
		t.Fatalf("accepted a %d-byte chain; anything past %d has not been shown to relay",
			r.ChainBytes, LargestChainKnownToWork)
	}
	if r.ChainBytes <= LargestChainKnownToWork {
		t.Fatalf("test did not actually produce an oversized chain: %d", r.ChainBytes)
	}
}

func TestAnOrdinaryCertificateIsAccepted(t *testing.T) {
	addr := serve(t, selfSigned(t, "127.0.0.1", 0), []string{"h2"}, 0)
	r := Probe(context.Background(), addr)
	if !r.Usable {
		t.Fatalf("rejected a normal dest: %s", r.Why)
	}
	if !r.TLS13 || !r.ALPNH2 || !r.X25519 {
		t.Errorf("tls13=%v h2=%v x25519=%v, want all true", r.TLS13, r.ALPNH2, r.X25519)
	}
	if r.ChainBytes == 0 {
		t.Error("chain size not measured")
	}
}

// REALITY needs the dest to speak TLS 1.3. A 1.2-only site cannot be borrowed
// from at all, and reporting it as merely "unreachable" sends the operator
// looking at their firewall.
func TestATLS12OnlyDestIsRejectedForTheRightReason(t *testing.T) {
	addr := serve(t, selfSigned(t, "127.0.0.1", 0), nil, tls.VersionTLS12)
	r := Probe(context.Background(), addr)
	if r.Usable {
		t.Fatal("accepted a TLS 1.2-only dest")
	}
	if r.Reachable && r.TLS13 {
		t.Error("reported TLS 1.3 on a 1.2-only server")
	}
}

// The older, separate rule: the borrowed SNI must be HOSTED BY the dest. A
// certificate for another name means the client's SNI will not match what the
// dest serves.
func TestACertificateForAnotherNameIsRejected(t *testing.T) {
	addr := serve(t, selfSigned(t, "somewhere-else.example", 0), []string{"h2"}, 0)
	r := Probe(context.Background(), addr)
	if r.Usable {
		t.Fatal("accepted a dest whose certificate does not cover it")
	}
	if r.SNIMatchesDest {
		t.Error("claimed the certificate covers a name it does not")
	}
}

func TestAnUnreachableDestSaysSo(t *testing.T) {
	// Port 1 on loopback: nothing listens, and the refusal is immediate.
	r := Probe(context.Background(), "127.0.0.1:1")
	if r.Usable || r.Reachable {
		t.Fatal("reported an unreachable dest as usable")
	}
	if r.Why == "" {
		t.Error("no reason given")
	}
}

func TestEveryVerdictExplainsItself(t *testing.T) {
	for _, dest := range []string{"", "not a host", "127.0.0.1:1"} {
		if r := Probe(context.Background(), dest); r.Why == "" {
			t.Errorf("Probe(%q) gave a verdict with no reason", dest)
		}
	}
}

func TestSuggestedDestsAreWellFormed(t *testing.T) {
	s := Suggested()
	if len(s) == 0 {
		t.Fatal("no suggestions")
	}
	for _, d := range s {
		h, p := splitDest(d)
		if h == "" || p == "" {
			t.Errorf("suggestion %q does not split into host:port", d)
		}
	}
}

func TestSplitDestToleratesWhatOperatorsType(t *testing.T) {
	for _, tc := range []struct{ in, host, port string }{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"https://example.com", "example.com", "443"},
		{"https://example.com/", "example.com", "443"},
		{"  example.com  ", "example.com", "443"},
	} {
		h, p := splitDest(tc.in)
		if h != tc.host || p != tc.port {
			t.Errorf("splitDest(%q) = %q,%q want %q,%q", tc.in, h, p, tc.host, tc.port)
		}
	}
	if h, _ := splitDest(""); h != "" {
		t.Error("empty input should not produce a host")
	}
}

func TestProbeRespectsAContextDeadline(t *testing.T) {
	// A dest that accepts TCP and never completes a handshake must not hang the
	// caller: the panel probes on an operator's click.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // held open, never speaks TLS
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan Result, 1)
	go func() { done <- Probe(ctx, ln.Addr().String()) }()
	select {
	case r := <-done:
		if r.Usable {
			t.Error("a silent dest was reported usable")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Probe hung past its deadline")
	}
}
