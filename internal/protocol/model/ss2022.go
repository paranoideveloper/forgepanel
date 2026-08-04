package model

import (
	"encoding/base64"
	"fmt"
	"strings"
)

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
