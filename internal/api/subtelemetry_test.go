package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/forgepanel/forgepanel/internal/store"
)

// TestSubFetchIsRecordedAndVisibleToTheOperator drives the real router, so the
// route registration and the auth claims userOr404 needs are both part of what
// this proves. A hand-assembled router 404s on nil claims whether or not the
// feature works.
func TestSubFetchIsRecordedAndVisibleToTheOperator(t *testing.T) {
	srv, st, token := createComprehensiveTestServer(t)
	u := &store.User{Username: "tele", SubToken: "teletok123456",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: store.StatusActive}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	get := func(path, ua, accept, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", accept)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	// A proxy client pulls the subscription. "sing-box" in the UA is what makes
	// detectFormat pick sing-box; Accept keeps isBrowserSubRequest false.
	if w := get("/sub/teletok123456", "sing-box 1.9.0", "*/*", ""); w.Code != 200 {
		t.Fatalf("client sub fetch: %d %s", w.Code, w.Body.String())
	}
	// A human opens the same URL in a browser: the landing-page exit.
	if w := get("/sub/teletok123456",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"text/html,application/xhtml+xml", ""); w.Code != 200 {
		t.Fatalf("browser sub fetch: %d %s", w.Code, w.Body.String())
	}
	// An unknown token is guessed. This must write nothing at all, or a public
	// unauthenticated endpoint becomes a way to fill the operator's database.
	get("/sub/definitely-not-a-token", "sing-box 1.9.0", "*/*", "")

	w := get("/api/admin/users/"+strconv.FormatUint(uint64(u.ID), 10)+"/sub-requests", "test", "application/json", token)
	if w.Code != 200 {
		t.Fatalf("inspect: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Items []struct {
			Format    string `json:"format"`
			UserAgent string `json:"user_agent"`
			IP        string `json:"ip"`
		} `json:"items"`
		Total         int64   `json:"total"`
		LastFetchAt   *string `json:"last_fetch_at"`
		LastUserAgent string  `json:"last_user_agent"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if got.Total != 2 || len(got.Items) != 2 {
		t.Fatalf("total=%d items=%d, want 2 (the client pull AND the browser open)", got.Total, len(got.Items))
	}
	if got.Items[0].Format != "browser" {
		t.Fatalf("newest item format = %q, want %q — the landing-page exit records nothing",
			got.Items[0].Format, "browser")
	}
	if got.Items[1].Format != "sing-box" {
		t.Fatalf("client item format = %q, want %q", got.Items[1].Format, "sing-box")
	}
	if got.Items[1].UserAgent != "sing-box 1.9.0" {
		t.Fatalf("client item user_agent = %q, want %q", got.Items[1].UserAgent, "sing-box 1.9.0")
	}
	if got.Items[1].IP == "" {
		t.Fatal("client item recorded no source IP")
	}
	if got.LastFetchAt == nil {
		t.Fatal("last_fetch_at is null: the denormalised users.sub_updated_at half was not stamped")
	}
	if got.LastUserAgent == "" {
		t.Fatal("last_user_agent is empty: users.sub_last_ua was not stamped")
	}

	// Asserted at the store so it cannot be satisfied by a handler that merely
	// filters a row it should never have written.
	var n int64
	if err := st.DB().Model(&store.SubRequest{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("sub_requests holds %d rows, want 2: the guessed token wrote one", n)
	}
}
