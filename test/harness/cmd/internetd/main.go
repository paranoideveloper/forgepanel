//go:build harness

// Command internetd is the harness's stand-in for the internet. It serves the
// three endpoint families a proxy has to carry — plain HTTP, HTTPS, and UDP DNS
// — from a network the client container has no route to, so any byte the client
// receives from it must have travelled through the tunnel.
//
// The HTTP payload is deterministic from a seed, and the client computes the
// same bytes independently, which turns "the request succeeded" into "the exact
// bytes arrived intact".
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	harness "github.com/forgepanel/forgepanel/test/harness"
)

// zone is what the DNS responder is authoritative for. The names exist nowhere
// else, so resolving one is itself evidence the query reached this process.
var zone = map[string][]string{
	harness.ProbeName:      {harness.ProbeAddr},
	"origin.harness.test":  {"203.0.113.8"},
	"steal.harness.test":   {"203.0.113.9"},
}

func main() {
	httpPort := flag.Int("http", 8080, "plain HTTP listen port")
	tlsPort := flag.Int("tls", 8443, "HTTPS listen port")
	stealPort := flag.Int("steal", 443, "TLS-only port used as a REALITY dest")
	dnsPort := flag.Int("dns", 53, "UDP DNS listen port")
	health := flag.Bool("healthcheck", false, "probe a running internetd and exit")
	flag.Parse()

	if *health {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", *httpPort))
		if err != nil {
			fmt.Fprintln(os.Stderr, "internetd: unhealthy:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "internetd: unhealthy: HTTP %d\n", resp.StatusCode)
			os.Exit(1)
		}
		return
	}

	cert, pinHex, err := selfSigned()
	if err != nil {
		log.Fatalf("internetd: certificate: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Client-IP", clientIP(r))
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/tlspin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, pinHex)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "client=%s host=%s proto=%s\n", clientIP(r), r.Host, r.Proto)
	})
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		if size <= 0 || size > 16<<20 {
			size = harness.PayloadSize
		}
		seed, _ := strconv.ParseInt(r.URL.Query().Get("seed"), 10, 64)
		body := harness.PayloadBytes(seed, size)
		sum := sha256.Sum256(body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Payload-SHA256", hex.EncodeToString(sum[:]))
		w.Header().Set("X-Client-IP", clientIP(r))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})

	var wg sync.WaitGroup
	serve := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				log.Fatalf("internetd: %s: %v", name, err)
			}
		}()
	}

	serve("http", func() error {
		s := &http.Server{Addr: fmt.Sprintf(":%d", *httpPort), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		log.Printf("internetd: http on :%d", *httpPort)
		return s.ListenAndServe()
	})
	serve("https", func() error {
		s := &http.Server{
			Addr: fmt.Sprintf(":%d", *tlsPort), Handler: mux,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		}
		log.Printf("internetd: https on :%d (leaf sha256=%s)", *tlsPort, pinHex)
		return s.ListenAndServeTLS("", "")
	})
	// The steal site exists so REALITY has a TLS 1.3 target inside the isolated
	// topology: an xray REALITY inbound relays the client's handshake to its
	// dest, so without a reachable dest the whole security type is untestable.
	serve("steal", func() error {
		s := &http.Server{
			Addr: fmt.Sprintf(":%d", *stealPort), Handler: mux,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2", "http/1.1"},
			},
		}
		log.Printf("internetd: reality-dest TLS on :%d", *stealPort)
		return s.ListenAndServeTLS("", "")
	})
	serve("dns", func() error { return serveDNS(*dnsPort) })

	wg.Wait()
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// serveDNS answers A and TXT questions for the harness zone over UDP.
func serveDNS(port int) error {
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	log.Printf("internetd: dns/udp on :%d", port)
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		id, q, _, err := harness.ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		ips := zone[q.Name]
		txts := []string{}
		if q.Type == harness.TypeTXT {
			txts = append(txts, "forgepanel-harness-origin")
		}
		resp, err := harness.BuildResponse(id, q, ips, txts, 30)
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}

// selfSigned mints the certificate the HTTPS and steal listeners present, and
// returns its leaf digest so a client can pin it without a shared trust store.
func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "origin.harness.test"},
		DNSNames: []string{
			"origin.harness.test", "steal.harness.test", "www.harness.test",
			"internet", "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return cert, hex.EncodeToString(sum[:]), nil
}
