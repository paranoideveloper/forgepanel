package store

import "strconv"

// The counter-key encoding, in one place.
//
// A user's traffic is counted under a stats tag the panel stamps into every
// engine config: "u<ID>". Xray reports it back, a remote node reports it back,
// the traffic snapshot table is keyed by it, and the cascade has to find those
// rows when the user is deleted. Four callers, in three packages, one encoding —
// and the two halves must live together, because a panel that encodes one way
// and decodes another quietly stops matching any user, which looks exactly like
// a node reporting nothing.
//
// It lives in store rather than in internal/job because store is the lowest
// layer: job imports store, so the reverse would be a cycle, and the cascade
// (here) needs the encoder.

// UserCounterKey is the stats tag for a user id.
func UserCounterKey(userID uint) string {
	return "u" + strconv.FormatUint(uint64(userID), 10)
}

// UserIDFromCounterKey is the inverse.
//
// Anything not in the exact "u<id>" shape returns ok=false rather than a guess:
// engines also emit counters for internal identities (an inbound's placeholder
// client, for instance), and attributing those to a user id would bill traffic
// to whoever happens to hold that number.
func UserIDFromCounterKey(key string) (uint, bool) {
	if len(key) < 2 || key[0] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(key[1:], 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint(n), true
}

// NodeScope is the traffic-snapshot scope for one remote node's counters.
//
// Scopes keep each counter namespace's baseline separate. Without it a node
// restarting would look like the local engine restarting, and the panel would
// re-count one plane's traffic against the other's baseline.
func NodeScope(nodeID uint) string {
	return "node:" + strconv.FormatUint(uint64(nodeID), 10)
}
