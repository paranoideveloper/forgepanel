package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Customers: end users of the panel talking to the bot.
//
// A customer links their Telegram account to their panel account by opening an
// invite link, t.me/<bot>?start=<subscription token>. Telegram turns that into a
// "/start <token>" message from their account; the first account to arrive is
// bound and any later one is refused, so a forwarded link cannot be claimed by
// someone else once it has been used.
//
// The token in the link is the user's subscription token. That is not a new
// secret being exposed: it is already the credential in their subscription
// URL, and anyone holding it can already fetch every config the account has.
//
// An account that is neither an administrator nor linked can only see /start,
// /help and /id, plus the long-standing /sub <token>. Everything else asks them
// to use their invite link, so the bot gives a stranger nothing to probe.

// Customer is what the bot shows a linked customer about their own account.
type Customer struct {
	Username string
	Status   string
	UsedGB   float64
	LimitGB  float64 // 0 = unlimited
	Expiry   string  // empty = never
	SubURL   string
}

// CustomerData is implemented by a PanelData that supports linked customers.
// Optional, discovered by type assertion like BackupProvider.
type CustomerData interface {
	// LinkChat binds chatID to the user owning token and returns their username.
	LinkChat(token string, chatID int64) (string, error)
	// CustomerByChat returns the customer linked to chatID.
	CustomerByChat(chatID int64) (Customer, bool)
	// LinkedChats lists every linked customer chat, for broadcasts.
	LinkedChats() []int64
	// SubTokenForUser returns a user's subscription token, for /invite.
	SubTokenForUser(name string) (string, error)
}

func (b *Bot) customers() (CustomerData, bool) {
	c, ok := b.data.(CustomerData)
	return c, ok && c != nil
}

// broadcastPace spaces broadcast messages. Telegram allows about 30 messages a
// second to different chats; staying well under it keeps a large broadcast
// from being rate limited half way through.
var broadcastPace = 40 * time.Millisecond

// Broadcast sends text to every linked customer and reports how it went.
func (b *Bot) Broadcast(text string) (sent, failed int) {
	cd, ok := b.customers()
	if !ok {
		return 0, 0
	}
	for i, chat := range cd.LinkedChats() {
		if i > 0 && broadcastPace > 0 {
			time.Sleep(broadcastPace)
		}
		if err := b.sender.Send(chat, text); err != nil {
			failed++
			continue
		}
		sent++
	}
	return sent, failed
}

// InviteLink is the deep link that links a Telegram account to the user owning
// token, or "" when the bot's username is not known.
func (b *Bot) InviteLink(token string) string {
	name := b.Username()
	if name == "" || token == "" {
		return ""
	}
	return "https://t.me/" + name + "?start=" + token
}

var usernameCache struct {
	mu    sync.Mutex
	token string
	name  string
}

// Username asks Telegram (getMe) for the bot's @username, once per token.
func (b *Bot) Username() string {
	if b.token == "" {
		return ""
	}
	usernameCache.mu.Lock()
	defer usernameCache.mu.Unlock()
	if usernameCache.token == b.token && usernameCache.name != "" {
		return usernameCache.name
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+"/bot"+b.token+"/getMe", nil)
	resp, err := b.sendClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || !out.OK || out.Result.Username == "" {
		return ""
	}
	usernameCache.token, usernameCache.name = b.token, out.Result.Username
	return out.Result.Username
}

// validStartToken reports whether s can be a deep-link payload: Telegram allows
// only A-Z a-z 0-9 _ - and at most 64 characters.
func validStartToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func customerCard(c Customer) string {
	lim := "∞"
	if c.LimitGB > 0 {
		lim = fmt.Sprintf("%.1f GB", c.LimitGB)
	}
	exp := "never"
	if c.Expiry != "" {
		exp = c.Expiry
	}
	var sb strings.Builder
	sb.WriteString("*" + escapeMarkdown(c.Username) + "*\n")
	sb.WriteString("status: " + escapeMarkdown(c.Status) + "\n")
	sb.WriteString(fmt.Sprintf("traffic: %.2f / %s\n", c.UsedGB, lim))
	sb.WriteString("expires: " + escapeMarkdown(exp))
	return sb.String()
}

// handleCustomer answers the commands a linked customer or a stranger may use.
// It returns false when the command is not one of them, so Handle can carry on
// to the administrator commands.
func (b *Bot) handleCustomer(chatID int64, cmd string, args []string, admin bool) bool {
	cd, hasCustomers := b.customers()
	switch cmd {
	case "/start":
		if len(args) > 0 && hasCustomers {
			if !validStartToken(args[0]) {
				b.sender.Send(chatID, "That invite link is not valid. Ask your provider for a new one.")
				return true
			}
			name, err := cd.LinkChat(args[0], chatID)
			if err != nil {
				b.sender.Send(chatID, "Could not link this account: "+err.Error())
				return true
			}
			b.sender.Send(chatID, "✅ Linked to *"+escapeMarkdown(name)+"*.\n/me — your account · /sub — your subscription link")
			return true
		}
		b.sender.Send(chatID, helpText(admin, b.isLinked(chatID)))
		return true
	case "/help":
		b.sender.Send(chatID, helpText(admin, b.isLinked(chatID)))
		return true
	case "/id":
		b.sender.Send(chatID, fmt.Sprintf("Your chat id is `%d`", chatID))
		return true
	case "/me":
		if !hasCustomers {
			return false
		}
		c, ok := cd.CustomerByChat(chatID)
		if !ok {
			b.sender.Send(chatID, notLinked)
			return true
		}
		b.sender.Send(chatID, customerCard(c))
		return true
	case "/sub":
		if len(args) > 0 {
			return false // the long-standing /sub <token>, handled by Handle
		}
		if !hasCustomers {
			return false
		}
		c, ok := cd.CustomerByChat(chatID)
		if !ok {
			b.sender.Send(chatID, notLinked)
			return true
		}
		b.sender.Send(chatID, "your subscription:\n`"+c.SubURL+"`")
		return true
	}
	return false
}

const notLinked = "This Telegram account is not linked to a subscription. Open the invite link your provider gave you."

func (b *Bot) isLinked(chatID int64) bool {
	cd, ok := b.customers()
	if !ok {
		return false
	}
	_, linked := cd.CustomerByChat(chatID)
	return linked
}
