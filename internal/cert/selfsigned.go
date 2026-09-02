package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureSelfSigned makes sure a self-signed certificate + key exist under
// dir/self.{crt,key} and returns their paths (spec §7 lets an inbound use an
// imported or generated cert). This is what makes TLS inbounds actually serve
// during setup / behind a CDN before a real ACME cert is issued; clients set
// allowInsecure or the CDN terminates TLS. It is generated once and reused.
func EnsureSelfSigned(dir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "self.crt")
	keyPath = filepath.Join(dir, "self.key")
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	// A 10-year, wildcard-ish self-signed cert. Deterministic-ish validity so
	// re-generation is unnecessary; SANs cover common test SNIs.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "forgepanel.local"},
		DNSNames:     []string{"forgepanel.local", "*.forgepanel.local", "localhost"},
		// IP SANs are required, not cosmetic. Before a domain is configured the
		// panel is reached by IP, and a certificate with no IP SAN cannot be
		// verified for one: Go reports
		//   "cannot validate certificate for <ip> because it doesn't contain any IP SANs".
		// That is not a browser-warning-level problem — it broke node
		// enrolment outright. Measured on live servers: forgenode on a second
		// host could not POST /api/node/register to the panel's IP at all, and
		// crash-looped on that error, so a fresh multi-node install could never
		// complete without a domain.
		//
		// The loopback addresses cover local tooling; the host's own routable
		// addresses are added below so a node dialling this panel by IP can
		// verify it.
		IPAddresses: append([]net.IP{
			net.ParseIP("127.0.0.1"), net.ParseIP("::1"),
		}, hostIPs()...),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	cp, _ := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	_ = pem.Encode(cp, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = cp.Close()
	kb, _ := x509.MarshalECPrivateKey(key)
	kp, _ := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	_ = pem.Encode(kp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	_ = kp.Close()
	return certPath, keyPath, nil
}

// ResetSelfSigned removes the existing self.crt/self.key pair and mints a fresh
// one, returning the new paths.
//
// EnsureSelfSigned is create-once on purpose — it sits on hot paths in
// core.Manager, the export defaults and forgenode, and must stay idempotent —
// so regeneration cannot be a side effect of asking for the certificate. It has
// to be the caller's explicit, destructive act: the IP SANs above are baked in
// at generation time, so after the host's address changes the only way to a
// correct certificate is to throw the old one away, and doing that invalidates
// every node fingerprint and every issued xray link carrying
// pinnedPeerCertSha256.
func ResetSelfSigned(dir string) (certPath, keyPath string, err error) {
	for _, name := range []string{"self.crt", "self.key"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
	}
	return EnsureSelfSigned(dir)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// hostIPs returns this host's own routable addresses, so the self-signed
// certificate can be verified when the panel is reached by IP.
//
// Link-local and loopback are skipped: loopback is added explicitly by the
// caller, and a link-local SAN is never what a remote node dials. A failure to
// enumerate interfaces is not fatal — the certificate is still valid for the
// loopback SANs and for any configured domain, and refusing to start over it
// would turn a cosmetic gap into an outage.
func hostIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}
