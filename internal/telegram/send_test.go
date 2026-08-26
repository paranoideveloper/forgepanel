package telegram

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Send read the response into io.Discard and returned nil whatever came back, so
// EVERY failure looked like success: a revoked token, a chat id that does not
// exist, a user who never pressed Start. The notifier reported alerts as
// delivered that Telegram had refused, and a "test your configuration" button
// built on this could only ever say yes.
func TestSendReportsTelegramsRefusal(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		wantIn      string
		wantRemedy  string
	}{
		{
			name: "revoked token", status: 401,
			body:       `{"ok":false,"error_code":401,"description":"Unauthorized"}`,
			wantIn:     "Unauthorized",
			wantRemedy: "BotFather",
		},
		{
			name: "wrong chat id", status: 400,
			body:       `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`,
			wantIn:     "chat not found",
			wantRemedy: "never been in that chat",
		},
		{
			name: "never pressed start", status: 403,
			body:       `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`,
			wantIn:     "blocked",
			wantRemedy: "press Start",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			old := apiBaseURL
			apiBaseURL = srv.URL
			defer func() { apiBaseURL = old }()

			b := New("tok", []int64{1}, nil)
			err := b.Send(1, "hello")
			if err == nil {
				t.Fatal("a refusal was reported as success")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not carry Telegram's own description %q", err, tc.wantIn)
			}
			var se *SendError
			if !errors.As(err, &se) {
				t.Fatalf("error is %T, not a *SendError a caller can inspect", err)
			}
			if got := se.Remediation(); !strings.Contains(got, tc.wantRemedy) {
				t.Errorf("remediation = %q, want something about %q", got, tc.wantRemedy)
			}
		})
	}
}

func TestSendSucceedsWhenTelegramSaysOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()
	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	if err := New("tok", []int64{1}, nil).Send(1, "hello"); err != nil {
		t.Fatalf("a successful send returned %v", err)
	}
}

// The bot could only ever send text, so the one off-box copy a single-server
// operator is realistically going to have had no transport at all.
func TestSendDocumentUploadsTheFile(t *testing.T) {
	var gotName, gotCaption, gotChat string
	var gotBytes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("not a multipart upload: %v", err)
		}
		gotChat = r.FormValue("chat_id")
		gotCaption = r.FormValue("caption")
		f, hdr, err := r.FormFile("document")
		if err != nil {
			t.Errorf("no document part: %v", err)
		} else {
			gotName = hdr.Filename
			buf := make([]byte, 64)
			n, _ := f.Read(buf)
			gotBytes = n
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	old := apiBaseURL
	apiBaseURL = srv.URL
	defer func() { apiBaseURL = old }()

	err := New("tok", []int64{5}, nil).SendDocument(5, "backup.fpbk", []byte("encrypted-bytes"), "a caption")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if gotChat != "5" || gotName != "backup.fpbk" || gotCaption != "a caption" || gotBytes != len("encrypted-bytes") {
		t.Errorf("uploaded chat=%q name=%q caption=%q bytes=%d", gotChat, gotName, gotCaption, gotBytes)
	}
}

// Telegram enforces 50 MB by refusing the request, which shows up as "the
// nightly backup silently stopped arriving". Saying so locally is the difference
// between a diagnosable problem and a mystery.
func TestSendDocumentRefusesAnOversizedFileLocally(t *testing.T) {
	b := New("tok", []int64{1}, nil)
	err := b.SendDocument(1, "huge.fpbk", make([]byte, MaxDocumentBytes+1), "")
	if err == nil {
		t.Fatal("an oversized upload was attempted")
	}
	if !strings.Contains(err.Error(), "50 MB") {
		t.Errorf("error %q does not name the limit", err)
	}
}

func TestSendDocumentRefusesAnEmptyFile(t *testing.T) {
	if err := New("tok", []int64{1}, nil).SendDocument(1, "x", nil, ""); err == nil {
		t.Fatal("an empty upload was attempted")
	}
}
