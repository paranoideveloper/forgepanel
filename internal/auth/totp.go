package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // HOTP/TOTP (RFC 4226/6238) mandate HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 time-based one-time passwords (spec §2/§12): 6 digits,
// 30-second step, HMAC-SHA1 — the algorithm every authenticator app expects. No
// third-party dependency.

const (
	totpDigits = 6
	totpPeriod = 30
)

// b32 is unpadded base32 (what authenticator apps expect in the secret).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh random base32 secret (160 bits).
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURI builds the otpauth:// URI an authenticator imports (rendered as a QR in
// the panel).
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpAt computes the code for a specific counter.
func totpAt(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("auth: bad TOTP secret: %w", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	code %= 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// TOTPCode returns the current code for a secret (used in tests / previews).
func TOTPCode(secret string, now time.Time) (string, error) {
	return totpAt(secret, uint64(now.Unix())/totpPeriod)
}

// VerifyTOTP checks a user-supplied code against the secret, tolerating one step
// of clock skew on either side (RFC 6238 §5.2). Constant-time compare.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	counter := uint64(now.Unix()) / totpPeriod
	for _, delta := range []int64{0, -1, 1} {
		want, err := totpAt(secret, uint64(int64(counter)+delta))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// RecoveryCodes returns n single-use recovery codes (spec §12).
func RecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s-%s", b32.EncodeToString(b[:2]), b32.EncodeToString(b[2:])))
	}
	return out, nil
}
