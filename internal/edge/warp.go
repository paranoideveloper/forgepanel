package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
)

// WARP self-registration has to run from the ForgePanel VPS, NOT from inside the
// Worker: a Cloudflare Worker's fetch() to api.cloudflareclient.com (a
// Cloudflare-owned host) is refused with edge error 1104, the same CF→CF block
// that stops a Worker connect()ing to a Cloudflare IP. So the panel registers
// the accounts here and pushes them into the Worker's KV, where the subscription
// picks them up as WireGuard + AmneziaWG nodes.

// WarpRegBase is Cloudflare's consumer WARP registration API. No account or
// credential is required — it is the same endpoint the WARP app itself uses.
// It is a var so tests can point it at a mock instead of the live API.
var WarpRegBase = "https://api.cloudflareclient.com/v0a4005/reg"

// WarpRegPause is the gap between the two registrations — the API rate-limits
// back-to-back registrations from one IP. A var so tests can zero it.
var WarpRegPause = 2 * time.Second

// WarpAccount mirrors the Worker's WarpAccount (src/warp/account.ts): the fields
// the .conf / node renderers read. The JSON tags match exactly so it round-trips
// through the Worker's KV.
type WarpAccount struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	WarpIPv6   string `json:"warpIPv6"`
	Reserved   string `json:"reserved"`
}

type warpRegResponse struct {
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	} `json:"config"`
}

// registerOneWarp registers a single WARP account and returns it.
func registerOneWarp(ctx context.Context, hc *http.Client) (WarpAccount, error) {
	kp, err := keygen.WireGuardKeys()
	if err != nil {
		return WarpAccount{}, &Error{Op: "warp-register", Kind: KindServer, Message: "key generation failed: " + err.Error(), Cause: err}
	}
	body, _ := json.Marshal(map[string]any{
		"install_id":   "",
		"fcm_token":    "",
		"tos":          time.Now().UTC().Format(time.RFC3339),
		"type":         "Android",
		"model":        "PC",
		"locale":       "en_US",
		"warp_enabled": true,
		"key":          kp.PublicKey,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, WarpRegBase, bytes.NewReader(body))
	if err != nil {
		return WarpAccount{}, &Error{Op: "warp-register", Kind: KindValidation, Message: err.Error(), Cause: err}
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return WarpAccount{}, &Error{Op: "warp-register", Kind: KindNetwork,
			Message:     "could not reach Cloudflare's WARP API: " + err.Error(),
			Remediation: "the panel host needs outbound HTTPS to api.cloudflareclient.com.", Cause: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return WarpAccount{}, &Error{Op: "warp-register", Kind: KindServer, Status: resp.StatusCode,
			Message: fmt.Sprintf("WARP registration returned %d: %s", resp.StatusCode, truncate(string(raw), 200))}
	}
	var rr warpRegResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return WarpAccount{}, decodeError("warp-register", err)
	}
	if len(rr.Config.Peers) == 0 || rr.Config.Peers[0].PublicKey == "" {
		return WarpAccount{}, &Error{Op: "warp-register", Kind: KindServer, Message: "WARP API returned no peer public key"}
	}
	return WarpAccount{
		PrivateKey: kp.PrivateKey,
		PublicKey:  rr.Config.Peers[0].PublicKey,
		WarpIPv6:   rr.Config.Interface.Addresses.V6 + "/128",
		Reserved:   rr.Config.ClientID,
	}, nil
}

// RegisterWarpAccounts registers a WoW pair (two accounts) against Cloudflare's
// consumer WARP API. Two accounts are minted because the Worker chains them
// (WARP-on-WARP) for a non-Iran exit. The API rate-limits back-to-back
// registrations from one IP, so there is a short pause between the two.
func RegisterWarpAccounts(ctx context.Context, hc *http.Client) ([]WarpAccount, error) {
	if hc == nil {
		hc = netegress.Client(30 * time.Second)
	}
	out := make([]WarpAccount, 0, 2)
	for i := 0; i < 2; i++ {
		acct, err := registerOneWarp(ctx, hc)
		if err != nil {
			return nil, err
		}
		out = append(out, acct)
		if i == 0 && WarpRegPause > 0 {
			select {
			case <-time.After(WarpRegPause):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return out, nil
}
