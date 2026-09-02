package api

// Who is connected, right now.
//
// The panel could say how many bytes a user had ever moved and nothing about
// whether they were connected at this moment, from where, or on which inbound.
// That is the first question asked when a customer reports "it's not working",
// the only way to notice one account shared across a dozen households, and the
// data a per-user IP limit has to be enforced against.
//
// The presence itself is derived in internal/core/online from the cores' access
// logs and lives in memory only. This layer does one thing the tracker cannot:
// translate the engine-side identity back into a panel user, so the answer names
// people rather than counter keys.

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/core/online"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

type onlineSession struct {
	IP          string    `json:"ip"`
	Inbound     string    `json:"inbound"`
	Node        string    `json:"node"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Connections int64     `json:"connections"`
}

type onlineUser struct {
	UserID   uint            `json:"user_id"`
	Username string          `json:"username"`
	LastSeen time.Time       `json:"last_seen"`
	Sessions []onlineSession `json:"sessions"`
	// Addresses is the distinct source-address count, which is the number an
	// operator scans for when looking for a shared account.
	Addresses int `json:"addresses"`
}

// handleOnlineUsers reports current presence.
func (s *Server) handleOnlineUsers(c *gin.Context) {
	if s.engine == nil {
		// No core means nothing is serving traffic, which is a legitimate empty
		// answer rather than an error — a panel with no inbounds yet would
		// otherwise show a failure on a screen that is simply not applicable.
		c.JSON(http.StatusOK, gin.H{"users": []onlineUser{}, "ttl_seconds": int(online.DefaultTTL.Seconds())})
		return
	}

	presence := s.engine.Presence()

	// Resolve engine identities to usernames in ONE query. Doing a lookup per
	// session would issue a query per connected address on a screen that
	// refreshes on a timer.
	visible, ownerID := s.visibleUserIDs(c)

	names := map[uint]string{}
	if s.db != nil {
		if users, err := s.db.ListUsers(ownerID); err == nil {
			for _, u := range users {
				names[u.ID] = u.Username
			}
		}
	}

	out := make([]onlineUser, 0, len(presence))
	for _, p := range presence {
		id, ok := job.UserIDFromEmail(p.User)
		if !ok {
			// An identity the panel did not issue: an inbound configured by hand,
			// or a leftover from an imported config. It is real traffic and worth
			// showing, but it belongs to no user, so it cannot be scoped to a
			// reseller and is shown only to those who can see everything.
			if visible != nil {
				continue
			}
		} else if visible != nil && !visible[id] {
			// A reseller must not learn the connection addresses of users that
			// are not theirs.
			continue
		}

		row := onlineUser{
			UserID:    id,
			Username:  names[id],
			LastSeen:  p.LastSeen,
			Addresses: len(p.Sessions),
			Sessions:  make([]onlineSession, 0, len(p.Sessions)),
		}
		if row.Username == "" {
			// A deleted user whose sessions have not yet expired, or an identity
			// the panel never issued. Showing the raw tag beats showing a blank
			// row that looks like a rendering bug.
			row.Username = p.User
		}
		for _, sess := range p.Sessions {
			row.Sessions = append(row.Sessions, onlineSession{
				IP:          sess.IP,
				Inbound:     sess.Inbound,
				Node:        sess.Node,
				FirstSeen:   sess.First,
				LastSeen:    sess.Last,
				Connections: sess.Count,
			})
		}
		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].Username < out[j].Username
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	c.JSON(http.StatusOK, gin.H{
		"users": out,
		// The TTL is published because "online" is inferred from recency, and a
		// reader who does not know the window cannot tell whether an absent user
		// disconnected or merely went quiet.
		"ttl_seconds": int(online.DefaultTTL.Seconds()),
	})
}

// visibleUserIDs returns the set of user ids the caller may see, or nil when the
// caller may see everything.
//
// Returning nil for "unrestricted" rather than a set of every id keeps an owner's
// query from building a map of the whole user table on every poll.
func (s *Server) visibleUserIDs(c *gin.Context) (map[uint]bool, uint) {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil || claims.Role != string(store.RoleReseller) {
		return nil, 0
	}
	if s.db == nil {
		return map[uint]bool{}, claims.AdminID
	}
	owned, err := s.db.ListUsers(claims.AdminID)
	if err != nil {
		// A failure to determine ownership must DENY, not allow: the opposite
		// leaks every user's connection addresses to a reseller on a transient
		// database error.
		return map[uint]bool{}, claims.AdminID
	}
	set := make(map[uint]bool, len(owned))
	for _, u := range owned {
		set[u.ID] = true
	}
	return set, claims.AdminID
}
