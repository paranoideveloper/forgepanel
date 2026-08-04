package job

import (
	"strconv"
	"strings"
)

// UserEmail is the stats email tag for a user id: "u<ID>". Stable and parseable.
func UserEmail(userID uint) string { return "u" + strconv.FormatUint(uint64(userID), 10) }

// parseUserEmail is the inverse of UserEmail; returns 0 if not a user tag.
func parseUserEmail(email string) uint {
	if !strings.HasPrefix(email, "u") {
		return 0
	}
	n, err := strconv.ParseUint(email[1:], 10, 64)
	if err != nil {
		return 0
	}
	return uint(n)
}
