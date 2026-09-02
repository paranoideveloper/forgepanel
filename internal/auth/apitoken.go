package auth

// Minting and checking API tokens.
//
// WHY SHA-256 AND NOT ARGON2. Passwords are hashed slowly because people choose
// weak ones: the work factor is what stands between a leaked hash and a
// dictionary. An API token is 256 bits of output from a CSPRNG, so there is no
// dictionary to run and no weak choice to protect against — the entropy already
// makes brute force impossible.
//
// Running argon2 on every API request would instead hand anyone who can reach
// the endpoint a denial-of-service primitive: each unauthenticated guess costs
// the server ~50ms of CPU and the attacker nothing. A fast hash over a
// high-entropy secret is both safe and the standard choice for this exact case.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// TokenPrefixLen and tokenSecretBytes size the two halves.
const (
	// The prefix is a lookup key and an identifier, not a secret. 12 base64
	// characters is ~72 bits — far more than needed for uniqueness, and short
	// enough to read out loud when identifying a token in a log.
	tokenPrefixBytes = 9
	// 32 bytes = 256 bits. This is the part that must resist guessing.
	tokenSecretBytes = 32
)

// TokenScheme prefixes every issued token.
//
// A fixed, recognisable prefix is what lets secret scanners spot one in a commit
// or a log. A token that looks like arbitrary base64 gets leaked and never
// noticed.
const TokenScheme = "fp"

// NewAPIToken generates a token, returning the plaintext to show ONCE and the
// prefix/hash to store.
//
// The plaintext is never returned again by anything, because it is never kept.
func NewAPIToken() (plaintext, prefix, hash string, err error) {
	p := make([]byte, tokenPrefixBytes)
	if _, err := rand.Read(p); err != nil {
		return "", "", "", fmt.Errorf("api token: %w", err)
	}
	s := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(s); err != nil {
		return "", "", "", fmt.Errorf("api token: %w", err)
	}
	// The PREFIX is hex, not base64url. base64url's alphabet includes "_", which
	// is also the field separator — so a prefix containing one moved the
	// boundary and every token with an underscore in the wrong place failed to
	// parse. Hex has no separator character in it and the prefix is a lookup
	// key, not a place entropy density matters.
	prefix = hex.EncodeToString(p)
	// The SECRET stays base64url (denser) and is the LAST field, so an
	// underscore in it is harmless as long as the split is bounded.
	secret := base64.RawURLEncoding.EncodeToString(s)
	return TokenScheme + "_" + prefix + "_" + secret, prefix, HashAPIToken(secret), nil
}

// HashAPIToken hashes the secret half.
func HashAPIToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SplitAPIToken separates a presented token into its lookup prefix and secret.
//
// ok is false for anything that is not shaped like one of our tokens, which
// keeps a JWT or a random header value from reaching the token lookup at all.
func SplitAPIToken(presented string) (prefix, secret string, ok bool) {
	// SplitN with a limit of 3, so an underscore inside the base64url secret
	// stays part of the secret instead of producing a fourth field.
	parts := strings.SplitN(presented, "_", 3)
	if len(parts) != 3 || parts[0] != TokenScheme {
		return "", "", false
	}
	if parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// APITokenMatches compares a presented secret against a stored hash.
//
// Constant-time: a byte-by-byte early exit leaks how much of a guess was right,
// which over many attempts recovers the hash. The secret's entropy makes that
// impractical anyway, but comparing hashes in variable time is the kind of
// detail that is free to get right and expensive to notice later.
func APITokenMatches(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashAPIToken(secret)), []byte(storedHash)) == 1
}

// LooksLikeAPIToken reports whether a bearer value is one of ours, so the
// middleware knows whether to try the token path or the JWT path.
func LooksLikeAPIToken(v string) bool {
	return strings.HasPrefix(v, TokenScheme+"_")
}
