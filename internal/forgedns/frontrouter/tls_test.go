package frontrouter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// tlsBackend starts a real TLS echo server holding a certificate for name.
//
// A real certificate is the point of the test. If the router terminated TLS,
// the client would be validating the ROUTER's certificate and this backend's
// would never be seen; the handshake below only succeeds against a pool
// containing this one.
func tlsBackend(t *testing.T, name string) (addr string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Echo with a marker, so the test can tell WHICH backend answered.
				buf := make([]byte, 256)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(append([]byte(name+":"), buf[:n]...))
			}(c)
		}
	}()
	return ln.Addr().String(), pool
}

// startTLSRouter runs ServeTLS on an ephemeral port and returns its address.
func startTLSRouter(t *testing.T, backends []Backend) (string, *Server) {
	t.Helper()
	table, err := NewTable(backends)
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	srv, err := New(table, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ServeTLS(ctx, ln, func(b Backend) string { return b.TLSAddr }) }()
	return ln.Addr().String(), srv
}

// speak completes a TLS handshake through the router and round-trips one message.
func speak(t *testing.T, routerAddr, sni string, pool *x509.CertPool) (string, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", routerAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: pool})
	if err := c.Handshake(); err != nil {
		return "", err
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(buf[:n]), nil
}

// The load-bearing test. A DoT client reaches its own backend through a shared
// public port, and the certificate it validates is the BACKEND's — which is only
// possible if the router never terminated the connection.
func TestTLSPassthroughReachesTheBackendWithoutTerminating(t *testing.T) {
	addr, pool := tlsBackend(t, "dot.example.com")
	router, srv := startTLSRouter(t, []Backend{{
		Name: "zone-a", Suffixes: []string{"dot.example.com"},
		UDPAddr: "127.0.0.1:5301", TLSAddr: addr,
	}})

	got, err := speak(t, router, "dot.example.com", pool)
	if err != nil {
		t.Fatalf("handshake through the router failed: %v", err)
	}
	if got != "dot.example.com:ping" {
		t.Fatalf("echo = %q, want the backend's own marker", got)
	}
	if s := srv.Stats(); s.Forwarded != 1 {
		t.Fatalf("Forwarded = %d, want 1 (%+v)", s.Forwarded, s)
	}
}

// Two zones on one port is the entire reason this exists.
func TestTLSPassthroughSeparatesTwoZonesOnOnePort(t *testing.T) {
	addrA, poolA := tlsBackend(t, "a.example.com")
	addrB, poolB := tlsBackend(t, "b.example.com")
	router, _ := startTLSRouter(t, []Backend{
		{Name: "a", Suffixes: []string{"a.example.com"}, UDPAddr: "127.0.0.1:5301", TLSAddr: addrA},
		{Name: "b", Suffixes: []string{"b.example.com"}, UDPAddr: "127.0.0.1:5302", TLSAddr: addrB},
	})

	if got, err := speak(t, router, "a.example.com", poolA); err != nil || got != "a.example.com:ping" {
		t.Fatalf("zone a: got %q err %v", got, err)
	}
	if got, err := speak(t, router, "b.example.com", poolB); err != nil || got != "b.example.com:ping" {
		t.Fatalf("zone b: got %q err %v", got, err)
	}
	// Cross-check: a's pool must NOT validate b's backend. If the router were
	// terminating and re-presenting one certificate, this would pass and the
	// test above would prove nothing.
	if _, err := speak(t, router, "b.example.com", poolA); err == nil {
		t.Fatal("zone b validated against zone a's CA — the router is not passing certificates through")
	}
}

// An unroutable name must be dropped, not sent somewhere. A stream handed to the
// wrong backend fails with a certificate error that names neither this router
// nor the real cause.
func TestTLSPassthroughRefusesWhatItCannotRoute(t *testing.T) {
	addr, pool := tlsBackend(t, "known.example.com")
	router, srv := startTLSRouter(t, []Backend{{
		Name: "known", Suffixes: []string{"known.example.com"},
		UDPAddr: "127.0.0.1:5301", TLSAddr: addr,
	}})

	if _, err := speak(t, router, "stranger.example.org", pool); err == nil {
		t.Fatal("an unrouted server name was served anyway")
	}
	if s := srv.Stats(); s.NoRoute != 1 {
		t.Fatalf("NoRoute = %d, want 1 (%+v)", s.NoRoute, s)
	}
}

// A backend that has no TLS listener configured must be refused explicitly
// rather than dialled — dialling an empty address produces a hang, and the DNS
// side of this package already treats "no address" as a real answer.
func TestTLSPassthroughRefusesABackendWithNoTLSListener(t *testing.T) {
	router, srv := startTLSRouter(t, []Backend{{
		Name: "dns-only", Suffixes: []string{"dns.example.com"},
		UDPAddr: "127.0.0.1:5301", // no TLSAddr
	}})

	if _, err := speak(t, router, "dns.example.com", nil); err == nil {
		t.Fatal("a backend with no TLS listener accepted a stream")
	}
	if s := srv.Stats(); s.NoRoute != 1 {
		t.Fatalf("NoRoute = %d, want 1 (%+v)", s.NoRoute, s)
	}
}
