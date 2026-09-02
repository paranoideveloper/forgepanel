package core

// The sing-box stats client lives in internal/core/singboxapi so the NODE AGENT
// can use the same code.
//
// It was here, unexported, which meant a remote node had no way to meter the
// sing-box protocols at all — a user could exhaust their plan on hysteria2 or
// tuic from a node and stay active forever. Two copies of a hand-rolled
// protobuf codec would have been the other way to solve that, and the copy that
// drifts is the one that silently under-counts.

import (
	"context"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
	"github.com/forgepanel/forgepanel/internal/core/singboxapi"
)

// SingboxStatsSupport reports whether a sing-box binary can report per-user
// traffic, and why not when it cannot.
type SingboxStatsSupport = singboxapi.Support

// SingboxStatsSupported reports whether the INSTALLED sing-box can meter users.
//
// Detected once from the binary itself rather than assumed: enabling the config
// section on a binary that cannot serve it is a STARTUP failure, which would
// take every sing-box inbound down rather than merely leaving them unmetered.
func (c *Controller) SingboxStatsSupported() SingboxStatsSupport {
	c.sbStatsOnce.Do(func() {
		c.sbStats = singboxapi.Detect(c.bins.Path(binmgr.EngineSingbox))
	})
	return c.sbStats
}

// querySingboxStats reads the per-user counters from a running sing-box.
func querySingboxStats(ctx context.Context, addr, pattern string, reset bool) (map[string]int64, error) {
	return singboxapi.Query(ctx, addr, pattern, reset)
}
