// Package realityprobe measures whether a site can serve as a REALITY dest.
//
// REALITY borrows a real site's TLS handshake. Not every site can be borrowed
// from, and the panel used to decide with a hardcoded list of four bad names and
// a stated reason — "redirects / no clean X25519" — that was not the actual
// failure. The list was wrong in both directions: it blocked www.amazon.com,
// which works, and allowed www.microsoft.com, which does not.
//
// WHAT ACTUALLY BREAKS IT, measured against xray 26.3.27 on a live server rather
// than reasoned about. With dest=www.microsoft.com the client authenticates
// perfectly — the server derives the auth key, reads the right short id, logs
// the client version — and then fails relaying the borrowed handshake:
//
//	len(s2cSaved): 5524	Server Hello: 1215
//	len(s2cSaved): 4309	Change Cipher Spec: 6
//	len(s2cSaved): 4303	Encrypted Extensions: 41
//	len(s2cSaved): 4262	Certificate: 8273      <- wants 8273, has 4262
//	hs.c.isHandshakeComplete.Load(): false
//	REALITY: processed invalid connection: handshake did not complete successfully
//
// The dest's CERTIFICATE MESSAGE is larger than what the server buffered, so the
// handshake can never complete. Everything else about the config was correct,
// which is exactly why this presents as "REALITY is broken" rather than as a bad
// dest: the keys verify, the link looks right, and the tunnel is silent.
//
// Measured on the same server, same config, only the dest changed:
//
//	www.microsoft.com   8126 B chain   FAILS
//	dl.google.com       6683 B chain   works
//	www.amazon.com      5973 B chain   works
//	addons.mozilla.org  5704 B chain   works
//	www.lovelive-anime.jp 5311 B       works
//	gateway.icloud.com  4495 B chain   works
//	www.apple.com       4484 B chain   works
//	www.cloudflare.com  3536 B chain   works
//
// So the boundary sits between 6683 and 8126 bytes of PEM chain. This reports
// the measurement and flags what is over the largest size seen to work; it does
// not claim to know xray's exact buffer, because that is an implementation
// detail that can change and a probe that pretends to certainty it does not have
// is how the previous hardcoded list got written.
package realityprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// LargestChainKnownToWork is the biggest certificate chain observed completing a
// REALITY handshake (dl.google.com). Above it the risk is real and measured;
// below it every dest tested has worked.
const LargestChainKnownToWork = 6683

// Result is what a candidate dest looks like from here.
type Result struct {
	Dest string `json:"dest"`
	// Usable is the verdict the UI acts on.
	Usable bool `json:"usable"`
	// Why explains the verdict in the operator's terms, always populated.
	Why string `json:"why"`

	Reachable  bool   `json:"reachable"`
	TLS13      bool   `json:"tls13"`
	X25519     bool   `json:"x25519"`
	ALPNH2     bool   `json:"alpn_h2"`
	ChainBytes int    `json:"chain_bytes"`
	CommonName string `json:"common_name"`
	// ChainVerified reports whether the certificate chain validates against the
	// system roots. Reported, not required: REALITY relays the borrowed
	// handshake and its clients authenticate on the REALITY exchange rather than
	// on this chain, so an intermediate-ordering quirk is worth knowing about
	// and is not a reason to refuse a dest.
	ChainVerified bool `json:"chain_verified"`
	// SNIMatchesDest reports whether the certificate actually covers the name
	// being borrowed. A dest that serves a certificate for something else is the
	// separate, older failure: the borrowed SNI must be HOSTED BY the dest.
	SNIMatchesDest bool          `json:"sni_matches_dest"`
	HandshakeMS    int64         `json:"handshake_ms"`
	Elapsed        time.Duration `json:"-"`
}

// Probe measures one candidate. dest may be "host" or "host:port".
func Probe(ctx context.Context, dest string) Result {
	r := Result{Dest: dest}
	host, port := splitDest(dest)
	if host == "" {
		r.Why = "not a host or host:port"
		return r
	}

	start := time.Now()
	d := &net.Dialer{Timeout: 6 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.Why = "cannot be reached from this server: " + err.Error()
		return r
	}
	defer raw.Close()
	r.Reachable = true

	// CurvePreferences is X25519 only on purpose: REALITY needs the dest to
	// negotiate it, and a dest that refuses will fail the handshake here rather
	// than silently later.
	// InsecureSkipVerify with an explicit hostname check below, rather than
	// letting the stack decide: what matters for REALITY is that the certificate
	// COVERS the borrowed name and that the handshake is relayable. Full chain
	// validation would additionally reject a dest over an intermediate-ordering
	// problem that REALITY never sees, and would make this untestable without
	// standing up a CA.
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		InsecureSkipVerify: true,
	})
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		// Retry without pinning the curve, so "TLS works but not with X25519" is
		// reported as itself rather than as an unreachable site.
		r.Why = "TLS handshake failed with X25519: " + err.Error()
		if plain := probePlain(ctx, host, port); plain {
			r.TLS13 = true
			r.Why = "the site does not negotiate X25519, which REALITY requires"
		}
		return r
	}
	r.HandshakeMS = time.Since(start).Milliseconds()
	r.Elapsed = time.Since(start)

	st := conn.ConnectionState()
	r.X25519 = true
	r.TLS13 = st.Version == tls.VersionTLS13
	r.ALPNH2 = st.NegotiatedProtocol == "h2"

	for _, c := range st.PeerCertificates {
		r.ChainBytes += len(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		r.CommonName = leaf.Subject.CommonName
		r.SNIMatchesDest = leaf.VerifyHostname(host) == nil
		inter := x509.NewCertPool()
		for _, c := range st.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
		r.ChainVerified = err == nil
	}

	r.Usable, r.Why = verdict(r)
	return r
}

func verdict(r Result) (bool, string) {
	switch {
	case !r.TLS13:
		return false, "the site does not speak TLS 1.3, which REALITY requires"
	case !r.SNIMatchesDest:
		return false, "the certificate does not cover this name — the borrowed SNI must be hosted by the dest"
	case r.ChainBytes > LargestChainKnownToWork:
		return false, fmt.Sprintf(
			"its certificate chain is %d bytes, larger than any dest measured to work (%d). "+
				"REALITY relays the borrowed handshake and an oversized certificate never completes it: "+
				"the client authenticates, the tunnel stays silent, and nothing in the config looks wrong. "+
				"www.microsoft.com fails exactly this way",
			r.ChainBytes, LargestChainKnownToWork)
	case !r.ALPNH2:
		return true, fmt.Sprintf(
			"usable (%d-byte chain), but it did not negotiate HTTP/2 — clients advertising h2 are a little "+
				"more conspicuous against a dest that does not offer it", r.ChainBytes)
	}
	return true, fmt.Sprintf("usable: TLS 1.3, X25519, h2, %d-byte certificate chain", r.ChainBytes)
}

// probePlain reports whether the site completes an ordinary TLS 1.3 handshake,
// used only to tell "X25519 refused" apart from "TLS refused".
func probePlain(ctx context.Context, host, port string) bool {
	d := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if err := c.HandshakeContext(ctx); err != nil {
		return false
	}
	defer c.Close()
	return c.ConnectionState().Version == tls.VersionTLS13
}

func splitDest(dest string) (host, port string) {
	dest = strings.TrimSpace(dest)
	dest = strings.TrimPrefix(strings.TrimPrefix(dest, "https://"), "http://")
	dest = strings.TrimSuffix(dest, "/")
	if dest == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(dest); err == nil {
		return h, p
	}
	return dest, "443"
}

// Suggested is the set the wizard offers, every one of them measured to complete
// a REALITY handshake on a live server. Ordered by certificate size, smallest
// first, because smaller is further from the boundary that breaks it.
func Suggested() []string {
	return []string{
		"www.cloudflare.com:443",
		"www.apple.com:443",
		"gateway.icloud.com:443",
		"addons.mozilla.org:443",
		"www.amazon.com:443",
		"dl.google.com:443",
	}
}
