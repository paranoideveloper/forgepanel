package job

import (
	"strconv"
)

// UserEmail is the stats email tag for a user id: "u<ID>". Stable and parseable.
func UserEmail(userID uint) string { return "u" + strconv.FormatUint(uint64(userID), 10) }

// parseUserEmail is the package-local form of UserIDFromEmail, returning 0 for
// anything that is not a user tag. It delegates rather than re-implementing the
// parse: two copies of one encoding is exactly how the panel and a remote node
// end up disagreeing about which user owns a counter.
func parseUserEmail(email string) uint {
	id, ok := UserIDFromEmail(email)
	if !ok {
		return 0
	}
	return id
}

// UserIDFromEmail is the inverse of UserEmail.
//
// It lives beside the encoder deliberately. A remote node reports traffic keyed
// by the stats email the panel stamped into its config, and the panel has to map
// that back to a user before it can bill anyone. Splitting the two halves across
// packages is how the encoding drifts and remote traffic quietly stops matching
// any user — which looks identical to a node reporting nothing.
//
// Anything not in the exact "u<id>" shape returns ok=false rather than a guess:
// xray also emits counters for internal identities (an inbound's placeholder
// client, for instance), and attributing those to a user id would bill traffic
// to whoever happens to hold that number.
func UserIDFromEmail(email string) (uint, bool) {
	if len(email) < 2 || email[0] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(email[1:], 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}
