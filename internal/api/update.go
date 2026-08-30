package api

import (
	"context"
	"net/http"
	"time"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/update"
	"github.com/forgepanel/forgepanel/internal/version"
	"github.com/gin-gonic/gin"
)

// applyHint is returned by both update endpoints, and the UI renders it.
//
// It is not decoration. This panel can download, verify and RUN a candidate
// binary, and it cannot install one: packaging/systemd/forgepanel.service sets
// ProtectSystem=full with ReadWritePaths covering only the data dir, so
// /usr/local/bin is read-only inside the unit's mount namespace — and a child
// process the panel spawns inherits that namespace, so shelling out does not
// escape it either. Saying so in the response is what stops the UI growing an
// Install button that would return EROFS on every real install while passing in
// a test's temp directory.
const applyHint = "forgectl update"

// updateChannel resolves the channel for one request: an explicit ?channel=
// wins, then the stored operator choice, then stable.
func (s *Server) updateChannel(c *gin.Context) update.Channel {
	if v := c.Query("channel"); v != "" {
		return update.Channel(v)
	}
	if v := s.knobs().String("update_channel"); v != "" {
		return update.Channel(v)
	}
	return update.ChannelStable
}

// handleUpdateCheck reports the newest release on the selected channel.
func (s *Server) handleUpdateCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()

	rel, err := update.Check(ctx, update.Repo, s.updateChannel(c), version.Get().Version)
	if err != nil {
		apierr.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"current": rel.Current, "latest": rel.Latest, "update_available": rel.UpdateAvailable,
		"channel": rel.Channel, "prerelease": rel.Prerelease, "html_url": rel.HTMLURL,
		"published_at": rel.PublishedAt, "apply_hint": applyHint,
	})
}

// handleUpdateChannel stores the operator's channel choice.
//
// This route is why update_channel is a setting rather than dead config: the
// panel mounts only typed settings endpoints and a read-only registry, so there
// is no generic writer a UI could use to reach this key.
func (s *Server) handleUpdateChannel(c *gin.Context) {
	var body struct {
		Channel string `json:"channel"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		apierr.Fail(c, apierr.Validation("update-channel", err.Error(),
			"send {\"channel\": \"stable\"} or {\"channel\": \"prerelease\"}."))
		return
	}
	// The registry's own enum validator is the authority on what a channel may
	// be; duplicating the list here is how the two copies drift apart.
	if err := s.knobs().Set("update_channel", body.Channel); err != nil {
		apierr.Fail(c, apierr.Validation("update-channel", err.Error(),
			"choose either \"stable\" or \"prerelease\"."))
		return
	}
	s.audit(c, "update.channel", body.Channel)
	c.JSON(http.StatusOK, gin.H{"channel": body.Channel})
}

// handleUpdateStage downloads and verifies the candidate binary without
// installing it, so the operator knows the artifact is intact and runs on this
// host before the live binary is touched.
func (s *Server) handleUpdateStage(c *gin.Context) {
	// Long enough for a release binary over a filtered link; internal/update
	// gives the download itself the same budget.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Minute)
	defer cancel()

	rel, err := update.Check(ctx, update.Repo, s.updateChannel(c), version.Get().Version)
	if err != nil {
		apierr.Fail(c, err)
		return
	}
	if !rel.UpdateAvailable {
		apierr.Fail(c, apierr.Validation("update-stage",
			"this panel is already running "+rel.Current+", the newest release on the "+string(rel.Channel)+" channel",
			"switch channel, or wait for a newer release."))
		return
	}
	staged, err := update.Stage(ctx, s.cfg.DataDir, rel)
	if err != nil {
		apierr.Fail(c, err)
		return
	}
	s.audit(c, "update.staged", staged.Tag)
	c.JSON(http.StatusOK, gin.H{
		"path": staged.Path, "tag": staged.Tag, "sha256": staged.SHA256,
		"smoke_output": staged.SmokeOutput, "staged_at": staged.StagedAt,
		"apply_hint": applyHint,
	})
}
