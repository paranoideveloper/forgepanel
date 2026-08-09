// Package telegram is the ForgePanel Telegram bot (spec §13). It long-polls the
// Bot API with the standard library only (no dependency), routes admin commands
// and user self-service, and pushes notifications. It runs only when a bot token
// is configured; the command router is transport-agnostic and unit-tested.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PanelData is the view of the panel the bot needs: read queries plus the
// admin-only user-management mutations. Every mutation returns a plain error the
// bot relays verbatim (e.g. "user not found"), so the router stays transport- and
// store-agnostic and fully unit-testable.
type PanelData interface {
	Stats() (inbounds, users, groups int)
	UserByName(name string) (username, status string, usedGB, limitGB float64, ok bool)
	SubURLForToken(token string) (string, bool)

	// Management (admin commands).
	SetUserStatus(name, status string) error       // "active" | "disabled"
	ResetUserTraffic(name string) error             // zero usage, un-limit
	SetUserLimitGB(name string, gb float64) error   // 0 = unlimited
	ExtendUserDays(name string, days int) (expiry string, err error)
	CreateUser(name string) (subToken string, err error)
	DeleteUser(name string) error
}

// Sender abstracts the Telegram transport so the router is testable.
type Sender interface {
	Send(chatID int64, text string) error
}

// Bot routes updates to command handlers.
type Bot struct {
	token      string
	adminIDs   map[int64]bool
	data       PanelData
	sender     Sender
	client     *http.Client
	sendClient *http.Client
	offset     int64
}

// New builds a bot. adminIDs are the Telegram chat IDs allowed to run admin
// commands. token may be empty (the bot then does nothing).
func New(token string, adminIDs []int64, data PanelData) *Bot {
	m := map[int64]bool{}
	for _, id := range adminIDs {
		m[id] = true
	}
	b := &Bot{token: token, adminIDs: m, data: data, client: &http.Client{Timeout: 65 * time.Second}, sendClient: &http.Client{Timeout: 10 * time.Second}}
	b.sender = b // default: real transport
	return b
}

// Enabled reports whether a token is configured.
func (b *Bot) Enabled() bool { return b.token != "" }

// Send implements Sender via the Bot API.
var apiBaseURL = "https://api.telegram.org"

func (b *Bot) Send(chatID int64, text string) error {
	if b.token == "" {
		return nil
	}
	v := url.Values{}
	v.Set("chat_id", strconv.FormatInt(chatID, 10))
	v.Set("text", text)
	v.Set("parse_mode", "Markdown")
	resp, err := b.sendClient.PostForm(apiBaseURL+"/bot"+b.token+"/sendMessage", v)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Run long-polls until ctx is cancelled.
func (b *Bot) Run(ctx context.Context) {
	if !b.Enabled() {
		return
	}
	for ctx.Err() == nil {
		updates, err := b.getUpdates(ctx)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		for _, u := range updates {
			b.offset = u.UpdateID + 1
			if u.Message != nil && u.Message.Text != "" {
				b.Handle(u.Message.Chat.ID, u.Message.Text)
			}
		}
	}
}

// Handle routes one text message. Exposed for tests.
func (b *Bot) Handle(chatID int64, text string) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return
	}
	cmd := strings.ToLower(fields[0])
	args := fields[1:]
	admin := b.adminIDs[chatID]
	switch cmd {
	case "/start", "/help":
		b.sender.Send(chatID, helpText(admin))
	case "/stats":
		if !admin {
			b.sender.Send(chatID, "⛔ admin only")
			return
		}
		i, u, g := b.data.Stats()
		b.sender.Send(chatID, fmt.Sprintf("*ForgePanel*\nInbounds: %d\nUsers: %d\nGroups: %d", i, u, g))
	case "/user":
		if !admin {
			b.sender.Send(chatID, "⛔ admin only")
			return
		}
		if len(args) == 0 {
			b.sender.Send(chatID, "usage: /user <username>")
			return
		}
		name, status, used, limit, ok := b.data.UserByName(args[0])
		if !ok {
			b.sender.Send(chatID, "user not found")
			return
		}
		lim := "∞"
		if limit > 0 {
			lim = fmt.Sprintf("%.1f GB", limit)
		}
		b.sender.Send(chatID, fmt.Sprintf("*%s*\nstatus: %s\ntraffic: %.2f / %s", escapeMarkdown(name), escapeMarkdown(status), used, lim))
	case "/sub":
		if len(args) == 0 {
			b.sender.Send(chatID, "usage: /sub <token>")
			return
		}
		if url, ok := b.data.SubURLForToken(args[0]); ok {
			b.sender.Send(chatID, "your subscription:\n`"+url+"`")
		} else {
			b.sender.Send(chatID, "unknown subscription token")
		}

	// --- admin: user management ------------------------------------------
	case "/enable", "/disable":
		if !b.requireAdmin(chatID, admin) || !b.requireArg(chatID, args, "usage: "+cmd+" <username>") {
			return
		}
		status := "active"
		if cmd == "/disable" {
			status = "disabled"
		}
		if err := b.data.SetUserStatus(args[0], status); err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		b.sender.Send(chatID, fmt.Sprintf("✅ %s is now *%s*", escapeMarkdown(args[0]), status))

	case "/reset":
		if !b.requireAdmin(chatID, admin) || !b.requireArg(chatID, args, "usage: /reset <username>") {
			return
		}
		if err := b.data.ResetUserTraffic(args[0]); err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		b.sender.Send(chatID, "✅ traffic reset for *"+escapeMarkdown(args[0])+"*")

	case "/limit":
		if !b.requireAdmin(chatID, admin) {
			return
		}
		if len(args) < 2 {
			b.sender.Send(chatID, "usage: /limit <username> <GB>  (0 = unlimited)")
			return
		}
		gb, err := strconv.ParseFloat(args[1], 64)
		if err != nil || gb < 0 {
			b.sender.Send(chatID, "the limit must be a number of GB (0 = unlimited)")
			return
		}
		if err := b.data.SetUserLimitGB(args[0], gb); err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		lim := "∞"
		if gb > 0 {
			lim = fmt.Sprintf("%.0f GB", gb)
		}
		b.sender.Send(chatID, fmt.Sprintf("✅ %s limit set to *%s*", escapeMarkdown(args[0]), lim))

	case "/extend":
		if !b.requireAdmin(chatID, admin) {
			return
		}
		if len(args) < 2 {
			b.sender.Send(chatID, "usage: /extend <username> <days>")
			return
		}
		days, err := strconv.Atoi(args[1])
		if err != nil || days == 0 {
			b.sender.Send(chatID, "days must be a non-zero whole number (negative shortens)")
			return
		}
		expiry, err := b.data.ExtendUserDays(args[0], days)
		if err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		b.sender.Send(chatID, fmt.Sprintf("✅ %s now expires *%s*", escapeMarkdown(args[0]), escapeMarkdown(expiry)))

	case "/adduser":
		if !b.requireAdmin(chatID, admin) || !b.requireArg(chatID, args, "usage: /adduser <username>") {
			return
		}
		tok, err := b.data.CreateUser(args[0])
		if err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		b.sender.Send(chatID, fmt.Sprintf("✅ created *%s*\nsubscription token:\n`%s`\nfetch the link with `/sub %s`", escapeMarkdown(args[0]), tok, tok))

	case "/deluser":
		if !b.requireAdmin(chatID, admin) || !b.requireArg(chatID, args, "usage: /deluser <username>") {
			return
		}
		if err := b.data.DeleteUser(args[0]); err != nil {
			b.sender.Send(chatID, "⚠️ "+err.Error())
			return
		}
		b.sender.Send(chatID, "🗑 deleted *"+escapeMarkdown(args[0])+"*")

	default:
		b.sender.Send(chatID, "unknown command — /help")
	}
}

// requireAdmin messages and returns false when a non-admin runs an admin command.
func (b *Bot) requireAdmin(chatID int64, admin bool) bool {
	if !admin {
		b.sender.Send(chatID, "⛔ admin only")
		return false
	}
	return true
}

// requireArg messages the usage line and returns false when no argument is given.
func (b *Bot) requireArg(chatID int64, args []string, usage string) bool {
	if len(args) == 0 {
		b.sender.Send(chatID, usage)
		return false
	}
	return true
}

func helpText(admin bool) string {
	base := "*ForgePanel bot*\n/sub <token> — get your subscription link\n/help — this message"
	if admin {
		base += "\n\n*admin*" +
			"\n/stats — panel counts" +
			"\n/user <name> — status & traffic" +
			"\n/adduser <name> — create a user" +
			"\n/deluser <name> — delete a user" +
			"\n/enable <name> · /disable <name>" +
			"\n/reset <name> — zero traffic" +
			"\n/limit <name> <GB> — set data cap (0=∞)" +
			"\n/extend <name> <days> — extend expiry"
	}
	return base
}

// --- Bot API types ---

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Text string `json:"text"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

func (b *Bot) getUpdates(ctx context.Context) ([]update, error) {
	v := url.Values{}
	v.Set("timeout", "60")
	v.Set("offset", strconv.FormatInt(b.offset, 10))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		apiBaseURL+"/bot"+b.token+"/getUpdates?"+v.Encode(), nil)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func escapeMarkdown(s string) string {
	r := strings.NewReplacer("_", "\\_", "*", "\\*", "`", "\\`", "[", "\\[")
	return r.Replace(s)
}
