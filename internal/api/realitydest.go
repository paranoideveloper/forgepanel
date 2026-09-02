package api

// Probing a REALITY dest, instead of guessing from a list.
//
// The panel used to judge a dest against four hardcoded names with a stated
// reason ("redirects / no clean X25519") that was not the real failure. It was
// wrong in both directions: www.amazon.com was blocked and works, and plenty of
// unusable sites were not on the list at all. The measured cause is in
// internal/realityprobe — an oversized certificate chain that REALITY cannot
// relay — and it is something a probe can see and a list never could.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/realityprobe"
)

// handleRealityDestProbe measures one candidate and reports what it found.
//
// It is a separate call rather than part of the inbound preview because it makes
// a real TLS connection to a third-party site: doing that on every keystroke of
// a preview would be slow and would beat on the borrowed site.
func (s *Server) handleRealityDestProbe(c *gin.Context) {
	dest := strings.TrimSpace(c.Query("dest"))
	if dest == "" {
		fail(c, http.StatusBadRequest, "no dest given")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	c.JSON(http.StatusOK, realityprobe.Probe(ctx, dest))
}

// handleRealityDestSuggest lists dests measured to complete a handshake.
func (s *Server) handleRealityDestSuggest(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"suggested": realityprobe.Suggested(),
		"note": "Every entry has completed a REALITY handshake against a live server. " +
			"Smaller certificate chains sit further from the size that breaks the relay.",
	})
}
