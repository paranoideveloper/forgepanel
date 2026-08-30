package edge

import (
	"github.com/forgepanel/forgepanel/internal/warp"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterWarpAccounts(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		// The registration must carry a base64 WireGuard public key.
		var body struct {
			Key         string `json:"key"`
			WarpEnabled bool   `json:"warp_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("bad body: %v", err)
		}
		if _, err := base64.StdEncoding.DecodeString(body.Key); err != nil || body.Key == "" {
			t.Errorf("key is not base64: %q", body.Key)
		}
		if !body.WarpEnabled {
			t.Errorf("warp_enabled must be true")
		}
		// Vary the v6 per call so the two accounts differ.
		suffix := map[int]string{1: "aa", 2: "bb"}[got]
		_, _ = w.Write([]byte(`{"config":{"client_id":"Y2lk","interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::` +
			suffix + `"}},"peers":[{"public_key":"UEVFUlBVQg=="}]}}`))
	}))
	defer srv.Close()

	old, oldPause := warp.RegBase, warp.RegPause
	warp.RegBase, warp.RegPause = srv.URL, 0
	defer func() { warp.RegBase, warp.RegPause = old, oldPause }()

	accts, err := RegisterWarpAccounts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 2 {
		t.Fatalf("expected a WoW pair of 2 accounts, got %d", len(accts))
	}
	if got != 2 {
		t.Fatalf("expected 2 registration calls, saw %d", got)
	}
	for i, a := range accts {
		if a.PrivateKey == "" {
			t.Fatalf("account %d has no client private key", i)
		}
		if a.PublicKey == "" {
			t.Fatalf("account %d has no peer public key", i)
		}
		if !strings.HasSuffix(a.WarpIPv6, "/128") {
			t.Fatalf("account %d IPv6 missing /128: %q", i, a.WarpIPv6)
		}
		if a.Reserved == "" {
			t.Fatalf("account %d has no reserved/client_id", i)
		}
	}
}
