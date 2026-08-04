package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "forgepanel.local"},
		DNSNames:              []string{"forgepanel.local", "*.forgepanel.local", "localhost"},
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

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
