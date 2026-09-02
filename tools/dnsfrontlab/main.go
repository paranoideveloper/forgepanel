// Command dnsfrontlab exercises internal/forgedns/frontrouter on a real public
// port 53, against real resolvers. It is a lab harness, not a shipped service:
// the unit tests prove the routing logic, this proves the socket behaviour that
// only a real port and a real resolver can show.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/forgepanel/forgepanel/internal/forgedns/frontrouter"
)

// backend is a minimal authoritative responder that answers every A query with
// a fixed address, so a client can tell WHICH backend served it.
func backend(addr, answer string) (string, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(answer).To4()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, client, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			resp := buildAnswer(q, ip)
			if resp != nil {
				_, _ = pc.WriteTo(resp, client)
			}
		}
	}()
	// DNS-over-TCP for the same backend: the router dials TCP separately, and a
	// UDP socket cannot answer a stream connection.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				resp := buildAnswer(msg, ip)
				if resp == nil {
					return
				}
				var out [2]byte
				binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
				_, _ = c.Write(append(out[:], resp...))
			}(c)
		}
	}()
	return pc.LocalAddr().String(), nil
}

// buildAnswer echoes the question and appends one A record.
func buildAnswer(q []byte, ip net.IP) []byte {
	if len(q) < 12 {
		return nil
	}
	// walk the question to find where it ends
	off := 12
	for off < len(q) {
		l := int(q[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(q) {
			return nil
		}
		off += l
	}
	off += 4 // QTYPE + QCLASS
	if off > len(q) {
		return nil
	}
	out := append([]byte(nil), q[:off]...)
	binary.BigEndian.PutUint16(out[2:4], 0x8180) // QR + RA
	binary.BigEndian.PutUint16(out[6:8], 1)      // ANCOUNT = 1
	// The question is copied but the additional section is not, so NSCOUNT and
	// ARCOUNT must be zeroed. dig sends an EDNS0 OPT record, which leaves
	// ARCOUNT=1 in the echoed header and makes every reply parse as malformed.
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	// answer: compression pointer to the question name, A, IN, ttl 60, 4 bytes
	out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(out, ip...)
}

func main() {
	zone := os.Getenv("ZONE")
	if zone == "" {
		log.Fatal("set ZONE, e.g. dnslab.example.com")
	}
	b1, err := backend("127.0.0.1:5301", "10.0.0.1")
	if err != nil {
		log.Fatalf("backend 1: %v", err)
	}
	b2, err := backend("127.0.0.1:5302", "10.0.0.2")
	if err != nil {
		log.Fatalf("backend 2: %v", err)
	}
	log.Printf("backends: t1=%s (answers 10.0.0.1)  t2=%s (answers 10.0.0.2)", b1, b2)

	table, err := frontrouter.NewTable([]frontrouter.Backend{
		{Name: "tunnel-one", Suffixes: []string{"t1." + zone, zone}, UDPAddr: b1, TCPAddr: b1},
		{Name: "tunnel-two", Suffixes: []string{"t2." + zone, "alt." + zone}, UDPAddr: b2, TCPAddr: b2},
		{Name: "deep", Suffixes: []string{"deep.t1." + zone}, UDPAddr: b2, TCPAddr: b2},
	})
	if err != nil {
		log.Fatalf("route table: %v", err)
	}
	log.Printf("routes (match order): %s", strings.Join(table.Routes(), " | "))

	srv, err := frontrouter.New(table, frontrouter.Options{
		OnError: func(stage string, err error) { log.Printf("  [%s] %v", stage, err) },
	})
	if err != nil {
		log.Fatalf("router: %v", err)
	}

	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatalf("bind :53 udp: %v", err)
	}
	ln, err := net.Listen("tcp", ":53")
	if err != nil {
		log.Fatalf("bind :53 tcp: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = srv.ServeUDP(ctx, pc) }()
	go func() { _ = srv.ServeTCP(ctx, ln) }()
	log.Printf("front router listening on :53 (udp+tcp) for *.%s", zone)

	<-ctx.Done()
	s := srv.Stats()
	fmt.Printf("STATS queries=%d forwarded=%d noroute=%d malformed=%d backenderr=%d overloaded=%d\n",
		s.Queries, s.Forwarded, s.NoRoute, s.Malformed, s.BackendErr, s.Overloaded)
}
