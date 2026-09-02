package telegram

// Delivering a file to Telegram.
//
// The bot could only ever send text, so "send the nightly backup to Telegram" —
// the one off-box copy a single-server operator is realistically going to have —
// had no transport at all.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

// MaxDocumentBytes is the Bot API's upload ceiling for a bot-sent document.
//
// 50 MB, and Telegram enforces it by refusing the request. Checking it here
// turns "the nightly backup silently stopped arriving" into a message that says
// the backup outgrew the transport.
const MaxDocumentBytes = 50 << 20

// SendDocument uploads a file to a chat.
func (b *Bot) SendDocument(chatID int64, filename string, data []byte, caption string) error {
	if b.token == "" {
		return fmt.Errorf("telegram: no bot token configured")
	}
	if len(data) == 0 {
		return fmt.Errorf("telegram: refusing to send an empty file")
	}
	if len(data) > MaxDocumentBytes {
		return fmt.Errorf("telegram: %s is %d MB and the Bot API refuses anything over %d MB",
			filename, len(data)>>20, MaxDocumentBytes>>20)
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("chat_id", strconv.FormatInt(chatID, 10)); err != nil {
		return err
	}
	if caption != "" {
		if err := w.WriteField("caption", caption); err != nil {
			return err
		}
	}
	part, err := w.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, apiBaseURL+"/bot"+b.token+"/sendDocument", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	// The upload client, not the long-poll one: a 65-second timeout is for
	// waiting on updates, and a stalled upload should not hold that long.
	resp, err := b.sendClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: could not upload %s: %w", filename, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var out struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.OK {
		return nil
	}
	desc := strings.TrimSpace(out.Description)
	if desc == "" {
		desc = resp.Status
	}
	return &SendError{ChatID: chatID, Code: out.ErrorCode, Status: resp.StatusCode, Description: desc}
}

// DocumentSender is the file half of Sender, kept separate so a caller that only
// sends text is not forced to implement uploads.
type DocumentSender interface {
	SendDocument(chatID int64, filename string, data []byte, caption string) error
}
