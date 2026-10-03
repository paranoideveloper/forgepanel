package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/connkill"
	"github.com/forgepanel/forgepanel/internal/core/online"
	"github.com/forgepanel/forgepanel/internal/job"
)

// Disconnecting a user is two steps, and either alone does not work:
//
//  1. Hold them out of the cores for a while. Removing the credential stops new
//     connections and nothing else — measured: a transfer already in progress
//     on Xray ran to completion after its user was removed.
//  2. Close the TCP connections they already have, by their source addresses
//     on the inbound ports. Without the hold, the client reconnects at once.
//
// An address that another online user is also connecting from is NOT closed:
// behind a CDN or a carrier NAT many people share one address, and cutting it
// would disconnect all of them. It is reported instead, and the hold still
// keeps this user out once their own connection drops.

const (
	disconnectDefaultHold = 5 * time.Minute
	disconnectMaxHold     = 24 * time.Hour
)

type disconnectResult struct {
	HeldUntil time.Time `json:"held_until"`
	// Closed is the number of TCP connections closed on this server.
	Closed int `json:"closed"`
	// Addresses are the user's addresses whose connections were closed.
	Addresses []string `json:"addresses"`
	// Shared are the user's addresses also used by another online user, which
	// were left alone.
	Shared []string `json:"shared,omitempty"`
	// Note explains anything that could not be done immediately.
	Note string `json:"note,omitempty"`
}

// sessionAddresses splits presence into this user's addresses and those that
// any OTHER user is currently seen from.
func sessionAddresses(presence []online.Presence, user string) (mine []string, shared map[string]bool) {
	shared = map[string]bool{}
	seen := map[string]bool{}
	for _, p := range presence {
		for _, s := range p.Sessions {
			if p.User == user {
				if !seen[s.IP] {
					seen[s.IP] = true
					mine = append(mine, s.IP)
				}
			} else {
				shared[s.IP] = true
			}
		}
	}
	sort.Strings(mine)
	return mine, shared
}

// handleDisconnectUser holds a user out of the cores and closes their open
// connections. Body: {"hold_seconds": N} (default 300, at most 86400).
func (s *Server) handleDisconnectUser(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	var req struct {
		HoldSeconds int `json:"hold_seconds"`
	}
	_ = c.ShouldBindJSON(&req)
	hold := disconnectDefaultHold
	if req.HoldSeconds > 0 {
		hold = time.Duration(req.HoldSeconds) * time.Second
	}
	if hold > disconnectMaxHold {
		hold = disconnectMaxHold
	}
	until := time.Now().Add(hold).UTC()
	if err := s.db.UpdateUserFields(u.ID, map[string]any{"disconnected_until": until}, time.Time{}); err != nil {
		failErr(c, 500, err)
		return
	}

	// Reload BEFORE closing anything, so the client's immediate reconnect is
	// refused rather than accepted on the credential we are about to cut.
	s.reloadEngines()

	res := disconnectResult{HeldUntil: until, Addresses: []string{}}
	email := job.UserEmail(u.ID)
	switch {
	case s.engine == nil:
		res.Note = "no core is running on this server, so there was nothing to close"
	case s.cfg != nil && s.paas().Enabled:
		// Behind a platform edge every connection reaches the core from the
		// panel's own proxy on loopback, so there is no per-user address to
		// close by. The hold still applies.
		res.Note = "behind a platform edge open connections cannot be closed individually; " +
			"they end the next time the client reconnects, which the hold refuses"
	default:
		mine, others := sessionAddresses(s.engine.Presence(), email)
		var target []string
		for _, ip := range mine {
			if others[ip] {
				res.Shared = append(res.Shared, ip)
				continue
			}
			target = append(target, ip)
		}
		ports := s.localInboundPorts()
		if len(target) > 0 && len(ports) > 0 {
			n, err := connkill.Kill(connkill.Target{IPs: target, Ports: ports})
			switch {
			case errors.Is(err, connkill.ErrUnsupported):
				res.Note = err.Error() + "; the hold refuses the client's next connection instead"
			case err != nil:
				res.Note = "closing connections failed: " + err.Error()
			default:
				res.Closed = n
				res.Addresses = target
			}
		} else if len(mine) == 0 {
			res.Note = "the user had no open connections on this server"
		}
		if len(res.Shared) > 0 && res.Note == "" {
			res.Note = fmt.Sprintf("%d address(es) are shared with other online users and were left open", len(res.Shared))
		}
		s.engine.ForgetPresence(email)
	}
	s.audit(c, "user.disconnect", fmt.Sprintf("%s held until %s, %d connection(s) closed",
		u.Username, until.Format(time.RFC3339), res.Closed))
	c.JSON(http.StatusOK, res)
}

// handleReconnectUser lifts a disconnect hold early.
func (s *Server) handleReconnectUser(c *gin.Context) {
	u, _, ok := s.userOr404(c)
	if !ok {
		return
	}
	if err := s.db.UpdateUserFields(u.ID, map[string]any{"disconnected_until": nil}, time.Time{}); err != nil {
		failErr(c, 500, err)
		return
	}
	s.reloadEngines()
	s.audit(c, "user.reconnect", u.Username)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// localInboundPorts are the ports this server's cores listen on for clients.
func (s *Server) localInboundPorts() []int {
	var ports []int
	for _, sp := range s.candidateSpecs() {
		if sp.Node != nil && sp.Node.Port > 0 {
			ports = append(ports, sp.Node.Port)
		}
	}
	return ports
}
