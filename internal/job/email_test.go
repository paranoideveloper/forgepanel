package job

import "testing"

// The encoder and decoder must round-trip, and the decoder must refuse anything
// that is not a user identity — xray emits counters for internal clients too,
// and billing those to a user id would charge traffic to a stranger.
func TestUserEmailRoundTripAndRejection(t *testing.T) {
	for _, id := range []uint{1, 7, 42, 1000, 999999} {
		got, ok := UserIDFromEmail(UserEmail(id))
		if !ok || got != id {
			t.Errorf("round trip for %d: got %d ok=%v", id, got, ok)
		}
	}
	for _, bad := range []string{
		"", "u", "u0", "x1", "inbound-1", "matrix-test", "u1x", "u-1", "1", "uu1",
	} {
		if id, ok := UserIDFromEmail(bad); ok {
			t.Errorf("%q was decoded as user %d; it is not a user identity", bad, id)
		}
	}
}
