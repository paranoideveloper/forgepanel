package api

// Status for the cores that are not supervised subprocesses.
//
// Controller.BrookStatus, AWGStatus and AWGKernelStatus were implemented,
// tested, and had NO HTTP ROUTE — so the panel knew whether a Brook process was
// alive or whether the AmneziaWG kernel module was loaded, and had no way to
// say so. /admin/engines reports only the supervised cores, so an operator
// running Brook or AmneziaWG saw an engines list that simply did not mention
// them.
//
// The AmneziaWG kernel check is the one that matters most: without the module,
// AmneziaWG runs in userspace or not at all, and that is a property of the HOST
// which no amount of correct configuration fixes. An operator debugging a
// non-working AmneziaWG inbound has no way to discover it from the panel.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleAuxEngineStatus reports the cores that run outside the process
// supervisor.
func (s *Server) handleAuxEngineStatus(c *gin.Context) {
	if s.engine == nil {
		// A panel with no controller has no cores to report on, which is an
		// empty answer rather than an error.
		c.JSON(http.StatusOK, gin.H{"brook": []any{}, "amneziawg": []any{}, "amneziawg_kernel": gin.H{}})
		return
	}
	brook := s.engine.BrookStatus()
	if brook == nil {
		// A nil slice serialises as null, which every consumer then has to
		// special-case. An empty list is the same information in a shape that
		// needs no special case.
		brook = []map[string]any{}
	}
	awg := s.engine.AWGStatus()
	if awg == nil {
		awg = []map[string]any{}
	}
	c.JSON(http.StatusOK, gin.H{
		"brook":     brook,
		"amneziawg": awg,
		// Kernel readiness is separate from the interface list because it is a
		// property of the machine, not of any one inbound: with no module,
		// nothing an operator changes in the panel will make AmneziaWG work.
		"amneziawg_kernel": s.engine.AWGKernelStatus(),
	})
}
