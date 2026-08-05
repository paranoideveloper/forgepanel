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

// PanelData is the read-only view of the panel the bot needs.
type PanelData interface {
	Stats() (inbounds, users, groups int)
	UserByName(name string) (username, status string, usedGB, limitGB float64, ok bool)
	SubURLForToken(token string) (string, bool)
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
func (b *Bot) Send(chatID int64, text string) error {
	if b.token == "" {
		return nil
	}
	v := url.Values{}
	v.Set("chat_id", strconv.FormatInt(chatID, 10))
	v.Set("text", text)
	v.Set("parse_mode", "Markdown")
	resp, err := b.sendClient.PostForm("https://api.telegram.org/bot"+b.token+"/sendMessage", v)
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
	default:
		b.sender.Send(chatID, "unknown command — /help")
	}
}

func helpText(admin bool) string {
	base := "*ForgePanel bot*\n/sub <token> — get your subscription link\n/help — this message"
	if admin {
		base += "\n\n*admin*\n/stats — panel counts\n/user <name> — user status & traffic"
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
		"https://api.telegram.org/bot"+b.token+"/getUpdates?"+v.Encode(), nil)
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
