package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeSender struct{ last string }

func (f *fakeSender) Send(_ int64, text string) error { f.last = text; return nil }

type fakeData struct{}

func (fakeData) Stats() (int, int, int) { return 3, 5, 2 }
func (fakeData) UserByName(n string) (string, string, float64, float64, bool) {
	if n == "alice" {
		return "alice", "active", 1.5, 10, true
	}
	return "", "", 0, 0, false
}
func (fakeData) SubURLForToken(t string) (string, bool) {
	if t == "tok" {
		return "https://p/sub/tok", true
	}
	return "", false
}

func TestBotRouting(t *testing.T) {
	fs := &fakeSender{}
	b := New("", []int64{42}, fakeData{})
	b.sender = fs
	b.Handle(99, "/stats")
	if !strings.Contains(fs.last, "admin only") {
		t.Fatalf("non-admin stats: %q", fs.last)
	}
	b.Handle(42, "/stats")
	if !strings.Contains(fs.last, "Inbounds: 3") {
		t.Fatalf("admin stats: %q", fs.last)
	}
	b.Handle(42, "/user alice")
	if !strings.Contains(fs.last, "active") || !strings.Contains(fs.last, "1.50") {
		t.Fatalf("user: %q", fs.last)
	}
	b.Handle(7, "/sub tok")
	if !strings.Contains(fs.last, "/sub/tok") {
		t.Fatalf("sub: %q", fs.last)
	}
	b.Handle(7, "/sub bad")
	if !strings.Contains(fs.last, "unknown") {
		t.Fatalf("bad sub: %q", fs.last)
	}
	b.Handle(7, "/help")
	if !strings.Contains(fs.last, "subscription") {
		t.Fatalf("help: %q", fs.last)
	}
	if New("", nil, fakeData{}).Enabled() {
		t.Fatal("empty token must be disabled")
	}
}

func TestBot_SendEmptyToken(t *testing.T) {
	b := New("", nil, fakeData{})
	if err := b.Send(123, "test"); err != nil {
		t.Fatalf("expected nil error for empty token, got %v", err)
	}
}

func TestBot_RealSendAndGetUpdates(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "sendMessage") {
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":10}}`))
			return
		}
		if strings.Contains(r.URL.Path, "getUpdates") {
			count++
			if count == 1 {
				_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":100,"message":{"chat":{"id":42},"text":"/stats"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer ts.Close()

	origBase := apiBaseURL
	apiBaseURL = ts.URL
	defer func() { apiBaseURL = origBase }()

	b := New("mocktoken", []int64{42}, fakeData{})
	if err := b.Send(42, "hello world"); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	b.Run(ctx)
}

func TestBot_HandleAllCommands(t *testing.T) {
	fs := &fakeSender{}
	b := New("token", []int64{42}, fakeData{})
	b.sender = fs

	b.Handle(42, "/start")
	if !strings.Contains(fs.last, "ForgePanel") {
		t.Fatalf("/start failed: %q", fs.last)
	}

	b.Handle(42, "/user")
	if !strings.Contains(fs.last, "usage") {
		t.Fatalf("/user no arg failed: %q", fs.last)
	}

	b.Handle(42, "/user bob")
	if !strings.Contains(fs.last, "not found") {
		t.Fatalf("/user non-existent failed: %q", fs.last)
	}

	b.Handle(42, "/sub")
	if !strings.Contains(fs.last, "usage") {
		t.Fatalf("/sub no arg failed: %q", fs.last)
	}

	b.Handle(42, "/unknowncmd")
	if !strings.Contains(fs.last, "unknown command") {
		t.Fatalf("unknown command handling failed: %q", fs.last)
	}
}

func TestBot_RunCancelDisabled(t *testing.T) {
	b := New("", nil, fakeData{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Run(ctx)
}
