package api

// Docker Compose generation.
//
// ROUTE TO REGISTER in Server.routes() (this file never edits server.go):
//
//	GET /api/deploy/compose  ->  s.handleDeployCompose
//
// It may reasonably be wired under the authenticated admin group instead
// (/api/admin/deploy/compose): it is an operator tool, and it is safe either
// way because the generated file contains no secrets -- the one service that
// needs a credential reads it from the environment.

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/deploy"
)

// handleDeployCompose renders a docker-compose file for the requested engine
// profiles. It GENERATES TEXT ONLY: nothing here runs, pulls or inspects a
// container, and the panel never becomes a Docker client. Query parameters:
//
//	profiles=xray,singbox   (required) which engine services to emit
//	host_network=1          put the services on the host network namespace
//	net_admin=1             grant NET_ADMIN to the port-hopping service only
func (s *Server) handleDeployCompose(c *gin.Context) {
	out, err := deploy.GenerateCompose(deploy.ComposeOpts{
		Profiles:      splitCSV(c.Query("profiles")),
		HostNetwork:   truthy(c.Query("host_network")),
		AllowNetAdmin: truthy(c.Query("net_admin")),
	})
	if err != nil {
		// The error names the valid profiles; echo the list too so a UI can
		// render a picker without a second round trip.
		apierr.Fail(c, &apierr.Error{Op: "compose-render", Kind: apierr.KindValidation,
			Message: err.Error(), Cause: err,
			Details: map[string]any{"profiles": deploy.Profiles()}})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="docker-compose.yml"`)
	c.Data(200, "text/yaml; charset=utf-8", []byte(out))
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
