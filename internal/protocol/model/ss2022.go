package model

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// DeriveSSUserPSK derives a per-user Shadowsocks-2022 PSK from a stable seed
// (the user's email/identity) and the inbound's method. It is deterministic, so
// the engine and the subscription independently derive the SAME PSK for a user
// without storing an extra secret — the SERVED inbound's per-user key and the
// key inside that user's subscription always agree. The decoded length matches
// the cipher key size (16 or 32 bytes), which SIP022 requires.
func DeriveSSUserPSK(seed, method string) string {
	size, is2022 := KeySizeForMethod(method)
	if !is2022 || size <= 0 {
		size = 16
	}
	sum := sha256.Sum256([]byte("forgepanel-ss2022-user:" + seed)) // 32 bytes ≥ any 2022 keylen
	return base64.StdEncoding.EncodeToString(sum[:size])
}

// SS2022Combined builds the "serverPSK:userPSK" EIH password a multi-user
// SS-2022 client must present. For a non-2022 method (no EIH) it returns the
// shared password unchanged, so callers can use it unconditionally.
func SS2022Combined(serverPSK, userPSK, method string) string {
	if _, is2022 := KeySizeForMethod(method); !is2022 || userPSK == "" {
		return serverPSK
	}
	return serverPSK + ":" + userPSK
}

// validateSS2022PSK enforces the SIP022 rule that a "2022-blake3-*" password is
// a base64 PSK whose decoded length equals the cipher key size. Getting this
// wrong is one of the most common real-world panel misconfigurations, so it is
// a hard validation error rather than a warning (spec §8.6 Config Doctor).
//
// Multi-user SS2022 uses "serverPSK:userPSK" (EIH); every component must have
// the correct decoded length.
func validateSS2022PSK(password string, keySize int) error {
	if password == "" {
		return fmt.Errorf("shadowsocks 2022: %w", ErrNoCredential)
	}
	parts := strings.Split(password, ":")
	for i, p := range parts {
		raw, err := decodeB64Any(p)
		if err != nil {
			return fmt.Errorf("shadowsocks 2022: PSK segment %d is not valid base64: %w", i, err)
		}
		if len(raw) != keySize {
			return fmt.Errorf(
				"shadowsocks 2022: PSK segment %d decodes to %d bytes, method requires exactly %d",
				i, len(raw), keySize)
		}
	}
	return nil
}

// decodeB64Any accepts standard or URL-safe base64, padded or not. Client apps
// emit all four variants, so the parser must accept all four.
func decodeB64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, e := range encs {
		if raw, err := e.DecodeString(s); err == nil {
			return raw, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

// DecodeBase64Any is the exported form used by parse/ for subscription blobs.
func DecodeBase64Any(s string) ([]byte, error) { return decodeB64Any(s) }
