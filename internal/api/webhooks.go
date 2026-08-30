package api

// Outbound webhooks, from the panel.
//
// Telegram was the only sink the panel had, and an alert a person has to READ
// cannot open a ticket, suspend an account downstream or page whoever is on
// call. It is also, in the networks this panel is deployed on, blocked often
// enough that "the alerts stopped" and "nothing happened" look identical.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/netegress"

	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/telegram"
	"github.com/forgepanel/forgepanel/internal/webhook"
)

// The two lifecycle events that are facts rather than conditions, and so have
// no telegram.Event twin: an operator does not want a chat message per account
// created, but a provisioning system very much wants the POST.
const (
	eventUserCreated = "user.created"
	eventUserDeleted = "user.deleted"
)

// webhookEventTypes is every type the panel actually raises.
//
// It is a closed set on purpose: an endpoint subscribed to "node_down" instead
// of "node-down" is enabled, green, and permanently silent, and there is
// nothing in a working panel that would ever reveal the typo.
var webhookEventTypes = []string{
	string(telegram.EventTrafficLimit),
	string(telegram.EventExpiry),
	string(telegram.EventNodeDown),
	string(telegram.EventCertExpiry),
	string(telegram.EventPoolExhausted),
	string(telegram.EventSecurity),
	// The scheduler raises these two through the same Notify closure, as bare
	// strings rather than telegram.Event constants, which is why they are easy
	// to leave out of a list like this — see the guard test.
	"usage-reminder",
	"expiry-reminder",
	eventUserCreated,
	eventUserDeleted,
}

// webhookEndpoints is what the dispatcher asks for on every event.
//
// Read from the database per event rather than cached: an endpoint saved in the
// panel then receives the NEXT event instead of the next restart, and there is
// no reload path to forget to call from a handler somebody adds later.
func (s *Server) webhookEndpoints() []webhook.Endpoint {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.ListWebhooks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: webhook endpoints unreadable: %v\n", err)
		return nil
	}
	out := make([]webhook.Endpoint, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		out = append(out, endpointFor(r))
	}
	return out
}

func endpointFor(r store.WebhookEndpoint) webhook.Endpoint {
	return webhook.Endpoint{
		ID: r.ID, URL: r.URL, Secret: r.Secret,
		Events: splitEvents(r.Events), ProxyURL: r.ProxyURL,
	}
}

// recordWebhookAttempt stamps the outcome of every attempt onto the row, so the
// settings page can say "answered 401 four hours ago" rather than leaving the
// operator to conclude the panel never sends anything.
func (s *Server) recordWebhookAttempt(id uint, res webhook.Result) {
	if s.db == nil {
		return
	}
	if err := s.db.RecordWebhookAttempt(id, res.Status, res.Err, res.At); err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: recording webhook attempt: %v\n", err)
	}
}

func splitEvents(raw string) []string {
	var out []string
	for _, f := range strings.Split(raw, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// normalizeEvents canonicalises a subscription list and refuses a type the
// panel never raises.
func normalizeEvents(raw string) (string, error) {
	parts := splitEvents(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		known := ""
		for _, k := range webhookEventTypes {
			if strings.EqualFold(k, p) {
				known = k
				break
			}
		}
		if known == "" {
			return "", fmt.Errorf("%q is not an event this panel raises", p)
		}
		out = append(out, known)
	}
	return strings.Join(out, ","), nil
}

// validateWebhookURL refuses anything the delivery client could not, or must
// not, POST to.
//
// It refuses at SAVE time as well as at delivery time on purpose: a stored
// endpoint is retried by a background goroutine, so a target that only fails on
// delivery fails where nobody is looking. PolicyNoMetadata rather than
// PolicyStrict — an internal receiver is the documented case for a webhook
// (internal/webhook/transport.go), the cloud metadata endpoint never is.
func validateWebhookURL(ctx context.Context, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("a webhook needs a URL to post to")
	}
	_, err := netegress.GuardTarget(ctx, netegress.PolicyNoMetadata, raw)
	return err
}

type webhookRequest struct {
	URL *string `json:"url"`
	// Secret is optional on update: omitted, or left at the sentinel the read
	// endpoint returns, keeps the stored one. Saving the event list must not
	// require re-typing a secret the panel deliberately never showed back.
	Secret   *string `json:"secret"`
	Events   *string `json:"events"`
	Enabled  *bool   `json:"enabled"`
	ProxyURL *string `json:"proxy_url"`
}

// webhookView is the read shape. The secret is never in it.
func webhookView(r store.WebhookEndpoint) gin.H {
	out := gin.H{
		"id": r.ID, "url": r.URL, "events": r.Events, "enabled": r.Enabled,
		"proxy_url": r.ProxyURL, "has_secret": r.Secret != "",
		"last_status": r.LastStatus, "last_error": r.LastError,
	}
	if r.LastAttempt != nil {
		out["last_attempt"] = r.LastAttempt.UTC()
	}
	return out
}

func (s *Server) handleListWebhooks(c *gin.Context) {
	rows, err := s.db.ListWebhooks()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		out = append(out, webhookView(r))
	}
	c.JSON(http.StatusOK, gin.H{"webhooks": out, "events": webhookEventTypes})
}

func (s *Server) handleCreateWebhook(c *gin.Context) {
	var req webhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	row := &store.WebhookEndpoint{Enabled: true}
	if req.URL != nil {
		row.URL = strings.TrimSpace(*req.URL)
	}
	if err := validateWebhookURL(c.Request.Context(), row.URL); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if req.Events != nil {
		events, err := normalizeEvents(*req.Events)
		if err != nil {
			e := apierr.New(http.StatusUnprocessableEntity, err.Error())
			e.Op = "webhook.events"
			e.Remediation = "Leave the list empty to receive everything, or choose from: " +
				strings.Join(webhookEventTypes, ", ")
			apierr.Fail(c, e)
			return
		}
		row.Events = events
	}
	if req.ProxyURL != nil {
		row.ProxyURL = strings.TrimSpace(*req.ProxyURL)
		if err := webhook.ValidateProxy(row.ProxyURL); err != nil {
			failErr(c, http.StatusBadRequest, err)
			return
		}
	}
	if req.Enabled != nil {
		row.Enabled = *req.Enabled
	}
	reveal := ""
	if req.Secret != nil && strings.TrimSpace(*req.Secret) != "" && *req.Secret != redactionSentinel {
		row.Secret = strings.TrimSpace(*req.Secret)
	} else {
		// Minted rather than demanded. An unsigned webhook hands anyone who
		// learns the URL a remote control over whatever the receiver does with
		// it, and an operator asked to invent a secret picks a memorable one.
		secret, err := keygen.Password(32)
		if err != nil {
			failErr(c, http.StatusInternalServerError, err)
			return
		}
		row.Secret, reveal = secret, secret
	}
	if err := s.db.CreateWebhook(row); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "webhook.create", row.URL)
	out := webhookView(*row)
	if reveal != "" {
		// Shown ONCE, like the recovery codes: the receiver needs it to verify
		// the signature and the panel will never hand it back again.
		out["secret"] = reveal
		out["secret_note"] = "shown once — the receiver needs it to verify X-ForgePanel-Signature"
	}
	c.JSON(http.StatusCreated, out)
}

func (s *Server) handleUpdateWebhook(c *gin.Context) {
	row, err := s.db.WebhookByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such webhook")
		return
	}
	var req webhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL != nil {
		if err := validateWebhookURL(c.Request.Context(), *req.URL); err != nil {
			failErr(c, http.StatusBadRequest, err)
			return
		}
		row.URL = strings.TrimSpace(*req.URL)
	}
	if req.Events != nil {
		events, err := normalizeEvents(*req.Events)
		if err != nil {
			e := apierr.New(http.StatusUnprocessableEntity, err.Error())
			e.Op = "webhook.events"
			e.Remediation = "Leave the list empty to receive everything, or choose from: " +
				strings.Join(webhookEventTypes, ", ")
			apierr.Fail(c, e)
			return
		}
		row.Events = events
	}
	if req.ProxyURL != nil {
		if err := webhook.ValidateProxy(strings.TrimSpace(*req.ProxyURL)); err != nil {
			failErr(c, http.StatusBadRequest, err)
			return
		}
		row.ProxyURL = strings.TrimSpace(*req.ProxyURL)
	}
	if req.Enabled != nil {
		row.Enabled = *req.Enabled
	}
	if req.Secret != nil && *req.Secret != redactionSentinel && strings.TrimSpace(*req.Secret) != "" {
		row.Secret = strings.TrimSpace(*req.Secret)
	}
	if err := s.db.SaveWebhook(row); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "webhook.update", row.URL)
	c.JSON(http.StatusOK, webhookView(*row))
}

func (s *Server) handleDeleteWebhook(c *gin.Context) {
	row, err := s.db.WebhookByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such webhook")
		return
	}
	if err := s.db.DeleteWebhook(row.ID); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "webhook.delete", row.URL)
	c.JSON(http.StatusOK, gin.H{"deleted": row.ID})
}

// handleTestWebhook posts one delivery now and reports what came back.
//
// Synchronous, and deliberately NOT through the queue: an operator pressing
// test wants the receiver's answer — including "401" — in the response, not a
// green tick that only means the event was enqueued. It also bypasses the
// enabled flag and the subscription list, because testing an endpoint before
// turning it on is the whole point.
func (s *Server) handleTestWebhook(c *gin.Context) {
	row, err := s.db.WebhookByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such webhook")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	res := s.webhooks.Deliver(ctx, endpointFor(*row), webhook.Event{
		Type:    "test",
		Subject: "forgepanel",
		Message: "This is a test delivery from ForgePanel. Real events use the same signature.",
		At:      time.Now().UTC(),
	})
	s.recordWebhookAttempt(row.ID, res)
	s.audit(c, "webhook.test", row.URL)
	if !res.OK() {
		c.JSON(http.StatusBadGateway, gin.H{
			"ok": false, "status": res.Status, "error": res.Err,
			"remediation": "The receiver has to answer 2xx. Check the URL, and that whatever sits in front of it " +
				"is not asking for authentication the panel cannot provide.",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": res.Status})
}
