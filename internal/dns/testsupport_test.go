package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fake resolver
// ---------------------------------------------------------------------------

// fakeResolver answers from maps. A name absent from a map produces an
// authoritative NXDOMAIN so tests can exercise the "record missing" path
// distinctly from "resolver unreachable".
type fakeResolver struct {
	mu    sync.Mutex
	IPs   map[string][]string
	NS    map[string][]string
	TXT   map[string][]string
	CNAME map[string]string
	// Fail maps a name to a non-NXDOMAIN transport error.
	Fail map[string]error
	// Calls counts LookupIP calls per name, for propagation-wait tests.
	Calls map[string]int
	// IPsAfter makes a name start resolving only after N LookupIP calls, which
	// is how propagation is simulated.
	IPsAfter map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		IPs: map[string][]string{}, NS: map[string][]string{},
		TXT: map[string][]string{}, CNAME: map[string]string{},
		Fail: map[string]error{}, Calls: map[string]int{}, IPsAfter: map[string]int{},
	}
}

func nxdomain(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupIP(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := NormalizeDomain(host)
	f.Calls[h]++
	if err, ok := f.Fail[h]; ok {
		return nil, err
	}
	if after, ok := f.IPsAfter[h]; ok && f.Calls[h] < after {
		return nil, nxdomain(h)
	}
	if ips, ok := f.IPs[h]; ok {
		return ips, nil
	}
	return nil, nxdomain(h)
}

func (f *fakeResolver) LookupNS(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := NormalizeDomain(host)
	if err, ok := f.Fail["NS:"+h]; ok {
		return nil, err
	}
	if ns, ok := f.NS[h]; ok {
		return ns, nil
	}
	return nil, nxdomain(h)
}

func (f *fakeResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := NormalizeDomain(host)
	if err, ok := f.Fail["TXT:"+h]; ok {
		return nil, err
	}
	if txt, ok := f.TXT[h]; ok {
		return txt, nil
	}
	return nil, nxdomain(h)
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := NormalizeDomain(host)
	if cname, ok := f.CNAME[h]; ok {
		return cname, nil
	}
	return "", nxdomain(h)
}

var _ Resolver = (*fakeResolver)(nil)

// ---------------------------------------------------------------------------
// Mock Cloudflare API

// ---------------------------------------------------------------------------

// tlsTestServer is a real TLS 1.3 listener used by the scanner, prober and
// wizard tests, so those paths are proven against an actual handshake rather
// than a stub.
type tlsTestServer struct {
	Listener net.Listener
	Host     string
	Port     int
	stop     chan struct{}
	wg       sync.WaitGroup
}

// newTLSTestServer starts a listener on 127.0.0.1 serving a self-signed
// certificate for sni, negotiating TLS 1.3 only.
func newTLSTestServer(t *testing.T, sni string) *tlsTestServer {
	t.Helper()
	cert := selfSignedCert(t, sni)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	s := &tlsTestServer{
		Listener: ln, Host: "127.0.0.1",
		Port: ln.Addr().(*net.TCPAddr).Port, stop: make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.stop:
					return
				default:
					return
				}
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				tc := tls.Server(conn, cfg)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		close(s.stop)
		ln.Close()
		s.wg.Wait()
	})
	return s
}

// dialer returns a DialContext that sends every address to this listener,
// which is what lets a scan of a fake CIDR reach a real handshake.
func (s *tlsTestServer) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", s.Port))
	}
}

func selfSignedCert(t *testing.T, sni string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{sni},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

func requireKind(t *testing.T, err error, want Kind) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s error, got nil", want)
	}
	e, ok := AsError(err)
	if !ok {
		t.Fatalf("expected a *dns.Error, got %T: %v", err, err)
	}
	if e.Kind != want {
		t.Fatalf("expected kind %q, got %q (%v)", want, e.Kind, err)
	}
	return e
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireContains(t *testing.T, haystack, needle, what string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s: expected %q to contain %q", what, haystack, needle)
	}
}
