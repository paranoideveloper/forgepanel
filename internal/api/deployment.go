package api

// What this deployment can actually do, served so the UI can remove what the
// platform owns rather than showing controls that do nothing.

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/deploy"
)

// deploySurface computes the surface for this process. A server built by the
// light constructor has no config, and a panel with no config is a plain server
// as far as its capabilities go.
func (s *Server) deploySurface() deploy.Surface {
	if s.cfg == nil {
		return deploy.Describe(config.PaaS{})
	}
	return deploy.Describe(s.cfg.PaaS())
}

// handleDeployment reports the environment and its capabilities.
//
// The `sections` map is served alongside so the frontend does not carry its own
// copy of which tab needs which capability — one table, in Go, tested against
// the sidebar's tab ids.
func (s *Server) handleDeployment(c *gin.Context) {
	sur := s.deploySurface()
	hide := map[string]string{}
	for section, cap := range deploy.Sections() {
		if !sur.Allows(cap) {
			hide[section] = sur.Why[cap]
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"surface": sur,
		// hidden_sections maps a tab id to WHY it is gone, so the UI can explain
		// itself if anyone asks rather than a section merely vanishing.
		"hidden_sections": hide,
	})
}
