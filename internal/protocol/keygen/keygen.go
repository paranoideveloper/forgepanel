// Package keygen provides all cryptographic key/identity generation the panel
// needs (spec §3.2): X25519 REALITY keypairs, REALITY shortIds, UUID v4 and the
// Xray "UUID from any string" mapping, SS2022 PSKs of the correct length per
// method, WireGuard keypairs, and ed25519 SSH keypairs. Every generator is
// exposed via the API, the UI "generate" button, and `forgectl keygen`.
package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by the Xray UUIDv5-style mapping, not for security
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// UUID returns a fresh random UUID v4.
func UUID() string { return uuid.NewString() }

// UUIDFromString reproduces Xray's mapping from an arbitrary string to a UUID.
// Xray accepts a non-UUID "id" and maps it deterministically: if the string is
// already a valid UUID it is used verbatim, otherwise UUIDv5-style bytes are
// derived and stamped with version 5 / RFC 4122 variant. This must match Xray
// exactly or VLESS/VMess users created from a human-friendly id will not
// authenticate.
func UUIDFromString(s string) string {
	if u, err := uuid.Parse(s); err == nil {
		return u.String()
	}
	h := sha1.Sum([]byte(s)) //nolint:gosec
	var u uuid.UUID
	copy(u[:], h[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return u.String()
}

// RealityKeyPair is an X25519 keypair encoded the way Xray/REALITY expects:
// base64 raw-url, no padding.
type RealityKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// RealityKeys generates a fresh X25519 REALITY keypair. The private key is
// clamped per RFC 7748 before the public key is derived, matching `xray x25519`.
func RealityKeys() (RealityKeyPair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return RealityKeyPair{}, err
	}
	// RFC 7748 clamping.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return RealityKeyPair{}, err
	}
	enc := base64.RawURLEncoding
	return RealityKeyPair{
		PrivateKey: enc.EncodeToString(priv[:]),
		PublicKey:  enc.EncodeToString(pub),
	}, nil
}

// RealityPublicFromPrivate derives the public key from a base64 REALITY private
// key, so the panel can recover a client link from a server-only inbound.
func RealityPublicFromPrivate(privB64 string) (string, error) {
	raw, err := model.DecodeBase64Any(privB64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid reality private key")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// ShortID returns a random REALITY shortId of nBytes (1..8) as lowercase hex.
func ShortID(nBytes int) (string, error) {
	if nBytes < 1 || nBytes > 8 {
		return "", fmt.Errorf("shortId length must be 1..8 bytes, got %d", nBytes)
	}
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SS2022PSK returns a base64 (std, padded) PSK of the correct length for the
// given Shadowsocks method. It errors on non-2022 methods, which take an
// arbitrary passphrase rather than a fixed-length PSK.
func SS2022PSK(method string) (string, error) {
	size, is2022 := model.KeySizeForMethod(method)
	if !is2022 {
		return "", fmt.Errorf("method %q is not a 2022-blake3 method; use a passphrase", method)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Password returns a random URL-safe password of nBytes of entropy.
func Password(nBytes int) (string, error) {
	if nBytes < 8 {
		nBytes = 16
	}
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// WireGuardKeyPair is a base64 (std) Curve25519 keypair, WireGuard-formatted.
type WireGuardKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// WireGuardKeys generates a WireGuard keypair with the standard clamping.
func WireGuardKeys() (WireGuardKeyPair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return WireGuardKeyPair{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return WireGuardKeyPair{}, err
	}
	return WireGuardKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// SSHKeyPair carries an ed25519 SSH keypair: the private key in OpenSSH PEM and
// the public key in authorized_keys form.
type SSHKeyPair struct {
	PrivateKeyPEM  string `json:"private_key_pem"`
	AuthorizedKey  string `json:"authorized_key"`
	Fingerprint256 string `json:"fingerprint_sha256"`
}

// SSHKeys generates an ed25519 SSH keypair.
func SSHKeys() (SSHKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SSHKeyPair{}, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return SSHKeyPair{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return SSHKeyPair{}, err
	}
	return SSHKeyPair{
		PrivateKeyPEM:  string(encodePEM(pemBlock.Bytes, pemBlock.Type)),
		AuthorizedKey:  string(ssh.MarshalAuthorizedKey(sshPub)),
		Fingerprint256: ssh.FingerprintSHA256(sshPub),
	}, nil
}

// ML-DSA-65 seed generation for post-quantum REALITY. We generate the 32-byte
// seed; the actual ML-DSA verify key is derived by the pinned Xray build. We do
// not implement ML-DSA in-process (ADR-007): emitting the seed and letting the
// engine derive the rest keeps us interoperable with the exact upstream KAT.
func MLDSA65Seed() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// FingerprintCert returns the base64 SHA-256 of a DER certificate, for the
// Hysteria2/TUIC pinSHA256 option.
func FingerprintCert(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:])
}
