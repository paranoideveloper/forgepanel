package api

// Configuring the Telegram bot from the panel.
//
// The token was read once from FORGEPANEL_TELEGRAM_TOKEN at process start and
// nowhere else, so setting up alerts meant editing a compose file or a unit file
// and restarting the panel — for a feature whose whole point is telling an
// operator about things that happen while they are not looking. There was also
// no way to find out whether it worked short of waiting for an incident.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/telegram"
)

const (
	settingTGToken = "telegram_bot_token"
	settingTGChats = "telegram_admin_ids"
)

// telegramSettings is the resolved configuration, and where each half came from.
type telegramSettings struct {
	Token      string
	ChatIDs    []int64
	FromEnv    bool // the token fell back to the environment
	Configured bool
}

// resolveTelegram reads the panel's own settings, falling back to the environment.
//
// A value set in the panel WINS. The environment stays the deployment default so
// an existing compose file keeps working, but an operator who types a token into
// the panel and sees it ignored would have no way to understand why.
func (s *Server) resolveTelegram() telegramSettings {
	out := telegramSettings{}
	out.Token = s.knobs().String(settingTGToken)
	rawChats := s.knobs().String(settingTGChats)
	if out.Token == "" && s.cfg != nil {
		out.Token = strings.TrimSpace(s.cfg.TelegramToken)
		out.FromEnv = out.Token != ""
	}
	if rawChats == "" && s.cfg != nil {
		rawChats = s.cfg.TelegramAdmins
	}
	out.ChatIDs = parseChatIDs(rawChats)
	out.Configured = out.Token != "" && len(out.ChatIDs) > 0
	return out
}

// parseChatIDs accepts comma, space or newline separated ids and skips anything
// that is not one. A chat id is negative for a group, which is why this is not a
// uint parse — a group id silently dropped is the most common way this is set up
// wrong.
func parseChatIDs(raw string) []int64 {
	var out []int64
	seen := map[int64]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' || r == ';'
	}) {
		id, err := strconv.ParseInt(strings.TrimSpace(f), 10, 64)
		if err != nil || id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func formatChatIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ", ")
}

// --- the running bot ------------------------------------------------------

// botControl owns the goroutine the bot runs on, so a settings change can stop
// the old one and start a new one without restarting the panel.
//
// It lives on the Server, not in a package variable: two panels in one process
// must not share one bot, and the mistake of putting long-lived state in a
// package-level sync.Once has been made twice in this codebase already.
type botControl struct {
	mu     sync.Mutex
	base   context.Context
	cancel context.CancelFunc
}

// restartBot stops whatever bot is running and starts one from the current
// settings. Safe with no token: it simply leaves nothing running.
func (s *Server) restartBot() {
	if s.bots == nil {
		return
	}
	s.bots.mu.Lock()
	defer s.bots.mu.Unlock()
	if s.bots.cancel != nil {
		s.bots.cancel()
		s.bots.cancel = nil
	}
	s.notifier = nil

	base := s.bots.base
	if base == nil || base.Err() != nil {
		return
	}
	cfg := s.resolveTelegram()
	if cfg.Token == "" {
		return
	}
	bot := telegram.New(cfg.Token, cfg.ChatIDs, tgPanelData{s})
	// The bot could always SEND; nothing ever asked it to. Without this the
	// panel knew a node was down, a quota had tripped or an account had expired
	// and told nobody until someone thought to ask.
	s.notifier = telegram.NewNotifier(bot, cfg.ChatIDs)
	ctx, cancel := context.WithCancel(base)
	s.bots.cancel = cancel
	go bot.Run(ctx)
}

// --- endpoints ------------------------------------------------------------

// handleGetTelegramSettings reports the configuration WITHOUT the token.
//
// The token is a bearer credential for the bot: anyone holding it can read every
// message the bot receives and post as it. It is write-only from the panel's
// point of view, the same treatment the Worker config gives its secrets.
func (s *Server) handleGetTelegramSettings(c *gin.Context) {
	cfg := s.resolveTelegram()
	c.JSON(200, gin.H{
		"configured":      cfg.Configured,
		"has_token":       cfg.Token != "",
		"token_source":    tokenSource(cfg),
		"chat_ids":        formatChatIDs(cfg.ChatIDs),
		"running":         s.notifier != nil,
		"backup_delivery": s.telegramBackupDelivery(),
	})
}

func tokenSource(cfg telegramSettings) string {
	switch {
	case cfg.Token == "":
		return "none"
	case cfg.FromEnv:
		return "environment"
	}
	return "panel"
}

type telegramSettingsRequest struct {
	// Token is optional on update: omitted or left at the sentinel keeps the
	// stored one, so saving the chat ids does not require re-typing a secret the
	// panel deliberately never showed back.
	Token   *string `json:"token"`
	ChatIDs *string `json:"chat_ids"`
	// Test sends a message before persisting anything. A configuration that
	// cannot deliver is the whole failure mode here.
	Test bool `json:"test"`
	// BackupDelivery ships each scheduled backup to the configured chats.
	BackupDelivery *bool `json:"backup_delivery"`
}

// handleSetTelegramSettings persists the token and chat ids and restarts the bot.
func (s *Server) handleSetTelegramSettings(c *gin.Context) {
	if s.db == nil {
		fail(c, 501, "no store")
		return
	}
	var req telegramSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}

	current := s.resolveTelegram()
	token := current.Token
	if req.Token != nil && *req.Token != redactionSentinel {
		token = strings.TrimSpace(*req.Token)
	}
	chats := current.ChatIDs
	if req.ChatIDs != nil {
		chats = parseChatIDs(*req.ChatIDs)
		if strings.TrimSpace(*req.ChatIDs) != "" && len(chats) == 0 {
			apierr.Fail(c, &apierr.Error{Op: "telegram-settings", Kind: apierr.KindValidation,
				Status:  http.StatusUnprocessableEntity,
				Message: "no usable chat id in that list",
				Remediation: "a chat id is a whole number, negative for a group. " +
					"Message @userinfobot from the account that should receive alerts to find yours."})
			return
		}
	}

	if req.Test {
		if err := s.sendTelegramTest(token, chats); err != nil {
			apierr.Fail(c, telegramFailure(err))
			return
		}
	}

	// One batch through the registry, so the token is type-checked (a pasted
	// token with a stray newline in it produced a bot that failed on every send
	// with a header error nobody could trace back to this form) and so the
	// backup toggle can no longer be written on its own after the token write
	// failed.
	pending := map[string]string{
		settingTGToken: token,
		settingTGChats: formatChatIDs(chats),
	}
	if req.BackupDelivery != nil {
		pending[settingTGBackup] = strconv.FormatBool(*req.BackupDelivery)
	}
	if err := s.knobs().SetAll(pending); err != nil {
		var ve *settings.ValidationError
		if errors.As(err, &ve) {
			// Per-input detail, so the UI can put each message under the field
			// that caused it rather than one toast for the whole form.
			failFields(c, 400, ve.Error(), ve.Fields())
			return
		}
		failErr(c, 500, err)
		return
	}
	s.restartBot()
	// The token is never echoed, not even the one just supplied.
	s.audit(c, "settings.telegram.update", fmt.Sprintf("%d chat(s)", len(chats)))
	cfg := s.resolveTelegram()
	c.JSON(200, gin.H{
		"ok": true, "configured": cfg.Configured, "has_token": cfg.Token != "",
		"token_source": tokenSource(cfg), "chat_ids": formatChatIDs(cfg.ChatIDs),
		"running": s.notifier != nil, "tested": req.Test,
		"backup_delivery": s.telegramBackupDelivery(),
	})
}

// handleTestTelegram sends a message with the supplied configuration and saves
// nothing, so a token can be checked before it replaces a working one.
func (s *Server) handleTestTelegram(c *gin.Context) {
	var req telegramSettingsRequest
	_ = c.ShouldBindJSON(&req)

	current := s.resolveTelegram()
	token := current.Token
	if req.Token != nil && *req.Token != redactionSentinel && strings.TrimSpace(*req.Token) != "" {
		token = strings.TrimSpace(*req.Token)
	}
	chats := current.ChatIDs
	if req.ChatIDs != nil && strings.TrimSpace(*req.ChatIDs) != "" {
		chats = parseChatIDs(*req.ChatIDs)
	}
	if err := s.sendTelegramTest(token, chats); err != nil {
		apierr.Fail(c, telegramFailure(err))
		return
	}
	s.audit(c, "settings.telegram.test", fmt.Sprintf("%d chat(s)", len(chats)))
	c.JSON(200, gin.H{"ok": true, "delivered": len(chats)})
}

// telegramTestSender is the seam a test replaces. Nil means the real Bot API.
// On the Server for the same reason botControl is.
type telegramTestSender func(token string, chatID int64, text string) error

// sendTelegramTest delivers one message to every configured chat.
//
// EVERY chat, not the first: an operator who added a second admin needs to know
// that the bot cannot write to it, and the usual cause — that person never
// pressed Start — is invisible from the first chat succeeding.
func (s *Server) sendTelegramTest(token string, chats []int64) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("no bot token: create one with @BotFather and paste it here")
	}
	if len(chats) == 0 {
		return fmt.Errorf("no chat id to send to: add the id of the account or group that should receive alerts")
	}
	send := s.tgSend
	if send == nil {
		bot := telegram.New(token, chats, nil)
		send = func(_ string, chatID int64, text string) error { return bot.Send(chatID, text) }
	}
	const msg = "ForgePanel is connected. This is a test message; alerts will arrive here."
	for _, id := range chats {
		if err := send(token, id, msg); err != nil {
			return err
		}
	}
	return nil
}

// telegramFailure turns a send error into a body that says what to do.
//
// The classification of a Bot API refusal (dead token vs. a chat nobody has
// pressed Start in vs. a bot that was blocked) now lives in apierr alongside
// every other adapter, so it reaches the UI as a kind rather than as prose only
// this handler could interpret. The 422 is kept explicitly: "we could not
// deliver your test message" is the answer to a settings save that was itself
// well-formed, and the settings tests pin it.
func telegramFailure(err error) *apierr.Error {
	e := apierr.From(err)
	e.Status = http.StatusUnprocessableEntity
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details["ok"] = false
	return e
}

// --- off-box backup delivery ----------------------------------------------

// settingTGBackup enables shipping each scheduled backup to the configured
// chats. OFF by default, and deliberately so: it sends the panel's whole state
// to a third party's servers, where it stays in a chat history indefinitely.
//
// The blob is encrypted (AES-256-GCM under a key derived from the master
// secret), so possession alone does not read it — but that is an argument for
// the feature being SAFE, not for it being on without being asked for.
const settingTGBackup = "telegram_backup_delivery"

func (s *Server) telegramBackupDelivery() bool { return s.knobs().Bool(settingTGBackup) }

// deliverBackupToTelegram uploads a written backup to every configured chat.
//
// Errors are reported to the log and nowhere else on purpose: this runs on the
// scheduler, the backup itself already succeeded and is on disk, and failing the
// backup because a chat could not be written to would trade a working local copy
// for no copy at all.
func (s *Server) deliverBackupToTelegram(path string) {
	if !s.telegramBackupDelivery() {
		return
	}
	cfg := s.resolveTelegram()
	if cfg.Token == "" || len(cfg.ChatIDs) == 0 {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forgepanel: telegram backup delivery: %v\n", err)
		return
	}
	bot := telegram.New(cfg.Token, cfg.ChatIDs, nil)
	caption := fmt.Sprintf("ForgePanel backup · %s · %d KB", filepath.Base(path), len(data)>>10)
	for _, id := range cfg.ChatIDs {
		if err := bot.SendDocument(id, filepath.Base(path), data, caption); err != nil {
			fmt.Fprintf(os.Stderr, "forgepanel: telegram backup delivery to %d: %v\n", id, err)
		}
	}
}
