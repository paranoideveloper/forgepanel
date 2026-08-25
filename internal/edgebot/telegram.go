package edgebot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// telegram.go is the Bot API transport: long-poll getUpdates plus the handful of
// send methods the bot needs. Standard library only, no dependency — the same
// approach as the panel's built-in bot.

const defaultTGBase = "https://api.telegram.org"

type tgClient struct {
	token  string
	base   string
	poll   *http.Client
	send   *http.Client
	offset int64
}

func newTGClient(token string) *tgClient {
	return &tgClient{
		token: token,
		base:  defaultTGBase,
		poll:  &http.Client{Timeout: 65 * time.Second},
		send:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (t *tgClient) method(name string) string {
	return t.base + "/bot" + t.token + "/" + name
}

// --- inbound update shapes --------------------------------------------------

type tgFrom struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (f tgFrom) displayName() string {
	n := f.FirstName
	if f.LastName != "" {
		n += " " + f.LastName
	}
	return n
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgFrom `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	From    tgFrom     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUpdate struct {
	UpdateID      int64       `json:"update_id"`
	Message       *tgMessage  `json:"message"`
	CallbackQuery *tgCallback `json:"callback_query"`
}

// BotCommand is one entry in the Telegram "/" command menu.
type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// SetMyCommands populates the blue "Menu" button and the "/" autocomplete list,
// so a user discovers what the bot can do without reading a wall of help text.
func (t *tgClient) SetMyCommands(ctx context.Context, cmds []BotCommand) error {
	return t.call(ctx, t.send, "setMyCommands", map[string]any{"commands": cmds}, nil)
}

// GetMe verifies the token and returns the bot's @username.
func (t *tgClient) GetMe(ctx context.Context) (string, error) {
	var res struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if err := t.call(ctx, t.send, "getMe", nil, &res); err != nil {
		return "", err
	}
	if !res.OK {
		return "", fmt.Errorf("getMe: telegram rejected the token")
	}
	return res.Result.Username, nil
}

// GetUpdates long-polls for the next batch, advancing the offset.
func (t *tgClient) GetUpdates(ctx context.Context) ([]tgUpdate, error) {
	q := url.Values{}
	q.Set("timeout", "50")
	q.Set("offset", strconv.FormatInt(t.offset, 10))
	q.Set("allowed_updates", `["message","callback_query"]`)
	var res struct {
		OK     bool       `json:"ok"`
		Result []tgUpdate `json:"result"`
	}
	if err := t.call(ctx, t.poll, "getUpdates?"+q.Encode(), nil, &res); err != nil {
		return nil, err
	}
	for _, u := range res.Result {
		if u.UpdateID >= t.offset {
			t.offset = u.UpdateID + 1
		}
	}
	return res.Result, nil
}

// Send delivers one outbound message, with an optional inline keyboard.
func (t *tgClient) Send(ctx context.Context, out Out) error {
	payload := map[string]any{
		"chat_id":                  out.ChatID,
		"text":                     out.Text,
		"disable_web_page_preview": true,
	}
	if len(out.Buttons) > 0 {
		rows := make([][]map[string]string, 0, len(out.Buttons))
		for _, row := range out.Buttons {
			cells := make([]map[string]string, 0, len(row))
			for _, b := range row {
				cells = append(cells, map[string]string{"text": b.Text, "callback_data": b.Data})
			}
			rows = append(rows, cells)
		}
		payload["reply_markup"] = map[string]any{"inline_keyboard": rows}
	}
	return t.call(ctx, t.send, "sendMessage", payload, nil)
}

// AnswerCallback dismisses the loading spinner on a tapped inline button.
func (t *tgClient) AnswerCallback(ctx context.Context, id, text string) error {
	return t.call(ctx, t.send, "answerCallbackQuery", map[string]any{
		"callback_query_id": id, "text": text,
	}, nil)
}

// DeleteMessage removes a message — used to scrub a /cf credential from history.
func (t *tgClient) DeleteMessage(ctx context.Context, chatID, messageID int64) error {
	return t.call(ctx, t.send, "deleteMessage", map[string]any{
		"chat_id": chatID, "message_id": messageID,
	}, nil)
}

// call POSTs (or GETs, when body is nil) a Bot API method and decodes into out.
func (t *tgClient) call(ctx context.Context, hc *http.Client, method string, body any, out any) error {
	var (
		req *http.Request
		err error
	)
	if body != nil {
		raw, merr := json.Marshal(body)
		if merr != nil {
			return merr
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, t.method(method), bytes.NewReader(raw))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, t.method(method), nil)
	}
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	// Even when the caller ignores the body, a non-2xx is worth surfacing.
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("telegram %s: %s", method, truncateTG(string(raw), 200))
	}
	return nil
}

func truncateTG(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
