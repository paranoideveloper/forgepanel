package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// HashRecoveryCode returns the hex SHA-256 of a normalized recovery code. The
// codes produced by RecoveryCodes are high-entropy random tokens, so a fast hash
// is appropriate (no brute-force surface like a user password) — it lets us store
// only hashes and never the plaintext. Input is normalized (uppercased,
// whitespace removed) so a copy-pasted code with stray spaces still matches.
func HashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(code, " ", "")))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// RecoveryCodeMatches reports whether plaintext hashes to want, in constant time.
func RecoveryCodeMatches(want, plaintext string) bool {
	got := HashRecoveryCode(plaintext)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
