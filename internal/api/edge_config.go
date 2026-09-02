package api

// Editing a deployed Worker's configuration from the panel.
//
// The plumbing existed and the panel could not reach it: WorkerClient has
// GetConfigRaw/PutConfigRaw, and the Telegram bot has driven every field
// through them since it was built — clean IPs, fronting, ports, fingerprint,
// fragment, proxyIP/NAT64, chain proxy, backend mode, external subs, WARP
// tuning. The panel's own UI could edit NOTHING. An operator who deployed a
// Worker from the panel had to go and talk to the bot to configure it.
//
// # Why a patch, and why the panel keeps no schema
//
// A write sends only the keys that CHANGED and the panel merges them onto
// whatever the Worker currently holds. Two things fall out of that, both
// deliberate:
//
//   - A field this panel has never heard of survives. The Worker ships on its
//     own release cadence and its config has grown a key at a time; a panel
//     that PUT its own idea of the whole document would silently delete every
//     newer field on the first save, and the operator would discover it when
//     something stopped working days later.
//   - Two admins editing different sections do not clobber each other.
//
// The Worker validates. Mirroring its schema here would be a second copy of the
// truth that drifts, and the drift would show up as the panel rejecting a value
// the Worker accepts, or writing one it does not.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/edge"
)

// redactedSecrets are config keys whose value must not travel to a browser.
//
// Not everything in the config that looks secret is: vlessUUID and
// trojanPassword are embedded in every subscription link the Worker hands out,
// so hiding them from the operator who owns the Worker protects nothing and
// makes the editor useless for the field people most often need to rotate.
// These two are different — a Telegram bot token is a credential for a service
// that is not this one, and the feed pull token authorises writing to the
// Worker.
var redactedSecrets = []string{"telegramBotToken", "feedPullToken"}

// redactionSentinel replaces a secret's value on read.
//
// The editor sends it straight back when the operator did not touch the field,
// so the merge drops any key still carrying it. Without that, saving an
// untouched form would overwrite the real secret with this string — which is
// exactly the kind of bug that only shows up when the thing it broke is next
// used, hours later.
const redactionSentinel = "__unchanged__"

func isRedacted(key string) bool {
	for _, k := range redactedSecrets {
		if k == key {
			return true
		}
	}
	return false
}

// workerClientFor builds an authenticated client for a stored deployment.
func (s *Server) workerClientFor(id uint) (*edge.WorkerClient, string, bool) {
	d, err := s.db.EdgeDeploymentByID(id)
	if err != nil {
		return nil, "", false
	}
	if strings.TrimSpace(d.PushToken) == "" {
		return nil, d.Name, false
	}
	wc := edge.NewWorkerClient(d.Origin, d.SecurePath)
	wc.Bearer = d.PushToken
	return wc, d.Name, true
}

// handleEdgeGetConfig returns a deployed Worker's live configuration.
func (s *Server) handleEdgeGetConfig(c *gin.Context) {
	wc, name, ok := s.workerClientFor(parseID(c))
	if !ok {
		apierr.Fail(c, apierr.Validation("edge-config-read",
			"this deployment has no push token stored, so the panel cannot reach its configuration",
			"re-register the deployment with its push token, or read the token from the "+
				"Worker's own status page and save it against "+name))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	cfg, err := wc.GetConfigRaw(ctx)
	if err != nil {
		edgeFail(c, err)
		return
	}

	redacted := make([]string, 0, len(redactedSecrets))
	for k := range cfg {
		if isRedacted(k) {
			if str, _ := cfg[k].(string); strings.TrimSpace(str) != "" {
				cfg[k] = redactionSentinel
				redacted = append(redacted, k)
			}
		}
	}
	sort.Strings(redacted)

	// keys is the full field list as the WORKER reports it, so the editor can
	// offer everything this Worker actually has rather than everything this
	// panel's build happens to know about.
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	c.JSON(http.StatusOK, gin.H{"config": cfg, "keys": keys, "redacted": redacted})
}

// handleEdgeUpdateConfig merges a patch into a Worker's live configuration.
func (s *Server) handleEdgeUpdateConfig(c *gin.Context) {
	wc, name, ok := s.workerClientFor(parseID(c))
	if !ok {
		apierr.Fail(c, apierr.Validation("edge-config-write",
			"this deployment has no push token stored, so the panel cannot write its configuration",
			"re-register the deployment with its push token against "+name))
		return
	}
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		apierr.Fail(c, &apierr.Error{Op: "edge-config-write", Kind: apierr.KindValidation,
			Message: "invalid request body", Cause: err,
			Details: map[string]any{"detail": `send an object of the fields to change, e.g. {"fingerprint":"firefox"}`}})
		return
	}
	if len(patch) == 0 {
		fail(c, http.StatusBadRequest, "no fields were supplied")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	// Read-modify-write against the LIVE document, not against whatever the
	// browser last saw. This is what keeps a field the panel does not know about
	// from being deleted on save.
	cfg, err := wc.GetConfigRaw(ctx)
	if err != nil {
		edgeFail(c, err)
		return
	}

	changed := make([]string, 0, len(patch))
	for k, v := range patch {
		if strings.TrimSpace(k) == "" {
			continue
		}
		// A secret the operator did not retype comes back as the sentinel. Never
		// write it: that would replace a working credential with a placeholder.
		if isRedacted(k) {
			if str, _ := v.(string); str == redactionSentinel {
				continue
			}
		}
		cfg[k] = v
		changed = append(changed, k)
	}
	if len(changed) == 0 {
		c.JSON(http.StatusOK, gin.H{"changed": []string{}, "note": "nothing to write"})
		return
	}
	sort.Strings(changed)

	out, err := wc.PutConfigRaw(ctx, cfg)
	if err != nil {
		// The Worker validates, so its rejection is the useful message — relay it
		// rather than inventing a panel-side opinion about a schema the panel
		// deliberately does not mirror.
		edgeFail(c, err)
		return
	}
	s.audit(c, "edge.config.update", name+": "+strings.Join(changed, ","))

	for k := range out {
		if isRedacted(k) {
			if str, _ := out[k].(string); strings.TrimSpace(str) != "" {
				out[k] = redactionSentinel
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"config": out, "changed": changed})
}
