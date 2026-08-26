package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socks5Client performs a CONNECT and returns the reply code.
func socks5Client(t *testing.T, conn net.Conn, atyp byte, addr []byte, port uint16) byte {
	t.Helper()
	if _, err := conn.Write([]byte{socks5Version, 1, authNone}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatal(err)
	}
	if sel[0] != socks5Version {
		t.Fatalf("server replied with version %d", sel[0])
	}
	if sel[1] != authNoneOK {
		return sel[1]
	}
	req := []byte{socks5Version, cmdConnect, 0x00, atyp}
	req = append(req, addr...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	return rep[1]
}

func TestSOCKS5ConnectReachesTheDestinationAndProxiesBothWays(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c) // echo
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	{
		p, _ := net.LookupPort("tcp", portStr)
		port = uint16(p)
	}

	dial := SOCKS5Dialer(SOCKS5Options{})
	conn, err := dial(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if code := socks5Client(t, conn, atypIPv4, net.ParseIP(host).To4(), port); code != repSuccess {
		t.Fatalf("CONNECT replied %d, want success", code)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("got %q through the proxy, want %q", got, "ping")
	}
}

func TestSOCKS5RefusesBindAndUDPExplicitly(t *testing.T) {
	// A client that gets no answer retries, and a DNS tunnel is far too slow to
	// spend on a retry that can never succeed. Saying "command not supported"
	// costs one packet and ends it.
	for _, cmd := range []byte{0x02 /* BIND */, 0x03 /* UDP ASSOCIATE */} {
		dial := SOCKS5Dialer(SOCKS5Options{})
		conn, err := dial(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{socks5Version, 1, authNone})
		sel := make([]byte, 2)
		io.ReadFull(conn, sel)
		req := []byte{socks5Version, cmd, 0x00, atypIPv4, 127, 0, 0, 1}
		req = binary.BigEndian.AppendUint16(req, 80)
		conn.Write(req)
		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatalf("command %d: no reply at all (%v) — the client would hang and retry", cmd, err)
		}
		if rep[1] != repCommandNotSupported {
			t.Errorf("command %d replied %d, want %d (command not supported)", cmd, rep[1], repCommandNotSupported)
		}
		conn.Close()
	}
}

func TestSOCKS5ReportsAnUnreachableDestinationInsteadOfHanging(t *testing.T) {
	dial := SOCKS5Dialer(SOCKS5Options{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("refused")
		},
	})
	conn, err := dial(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socks5Client(t, conn, atypIPv4, []byte{192, 0, 2, 1}, 80); code == repSuccess {
		t.Fatal("a failed dial reported success")
	}
}

func TestSOCKS5PolicyCanRefuseADestination(t *testing.T) {
	// A DNS tunnel is reachable by anyone who can send a UDP packet. Without a
	// policy the socks5 mode is a route into whatever private network the panel
	// sits in — its own admin interfaces, the cloud metadata endpoint, the
	// database on the next host.
	var dialled string
	dial := SOCKS5Dialer(SOCKS5Options{
		Allow: DenyPrivate,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = addr
			c, _ := net.Pipe()
			return c, nil
		},
	})
	conn, err := dial(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socks5Client(t, conn, atypIPv4, []byte{169, 254, 169, 254}, 80); code == repSuccess {
		t.Fatal("the cloud metadata endpoint was reachable through the tunnel")
	}
	if dialled != "" {
		t.Fatalf("the policy was consulted after dialling %s", dialled)
	}
}

func TestDenyPrivateCoversTheAddressesThatMatter(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // the panel's own loopback services
		"169.254.169.254",         // cloud metadata
		"10.0.0.5", "192.168.1.1", // RFC 1918
		"172.16.0.1", "0.0.0.0", // RFC 1918 and unspecified
		"fe80::1", // link-local
	}
	for _, ip := range blocked {
		if DenyPrivate(ip, 80) {
			t.Errorf("%s is allowed through the tunnel", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !DenyPrivate(ip, 443) {
			t.Errorf("%s is blocked but should not be", ip)
		}
	}
}

func TestSOCKS5RejectsAClientOfferingNoUsableAuthMethod(t *testing.T) {
	dial := SOCKS5Dialer(SOCKS5Options{})
	conn, err := dial(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Offer only GSSAPI (0x01).
	conn.Write([]byte{socks5Version, 1, 0x01})
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("no reply (%v) — the client cannot tell a bad method from a broken tunnel", err)
	}
	if sel[1] != authNoAccept {
		t.Fatalf("replied %d, want 0xFF (no acceptable methods)", sel[1])
	}
}

func TestSOCKS5AcceptsADomainDestination(t *testing.T) {
	var dialled string
	dial := SOCKS5Dialer(SOCKS5Options{
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = addr
			c, _ := net.Pipe()
			return c, nil
		},
	})
	conn, err := dial(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	name := "example.com"
	addr := append([]byte{byte(len(name))}, []byte(name)...)
	if code := socks5Client(t, conn, atypDomain, addr, 443); code != repSuccess {
		t.Fatalf("CONNECT to a domain replied %d", code)
	}
	if !strings.HasPrefix(dialled, "example.com:") {
		t.Fatalf("dialled %q, want example.com:443", dialled)
	}
}
