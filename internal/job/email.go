package job

import (
	"github.com/forgepanel/forgepanel/internal/store"
)

// UserEmail is the stats email tag for a user id: "u<ID>". Stable and parseable.
//
// The encoding itself lives in internal/store, which is the lowest layer that
// needs it: the traffic-snapshot table is keyed by this tag and the cascade has
// to find those rows when a user is deleted. These wrappers keep the name the
// engine-facing code uses while there stays exactly ONE definition.
func UserEmail(userID uint) string { return store.UserCounterKey(userID) }

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
func UserIDFromEmail(email string) (uint, bool) { return store.UserIDFromCounterKey(email) }
