package edge

// WARP accounts for the Worker.
//
// The Cloudflare API contract lives in internal/warp, which owns registration,
// license activation and the outbound rendering for the VPS cores. This file is
// only the adapter: it maps a warp.Account onto the shape the Worker's KV
// expects, so the endpoint, the headers and the rate-limit pause are described
// once rather than in two places that quietly disagree after the first change.

import (
	"context"
	"net/http"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/warp"
)

// WarpAccount mirrors the Worker's WarpAccount (src/warp/account.ts): the
// fields the .conf / node renderers read. The JSON tags match exactly so it
// round-trips through the Worker's KV.
//
// Reserved is the raw base64 client id, NOT the decoded triple — the Worker
// does its own decoding with reservedFromClientID, and handing it three
// integers would leave it decoding a string that is already bytes.
type WarpAccount struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	WarpIPv6   string `json:"warpIPv6"`
	Reserved   string `json:"reserved"`
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
		acct, err := warp.Register(ctx, hc)
		if err != nil {
			return nil, &Error{Op: "warp-register", Kind: KindServer, Message: err.Error(), Cause: err}
		}
		out = append(out, WarpAccount{
			PrivateKey: acct.PrivateKey,
			PublicKey:  acct.PeerPublicKey,
			WarpIPv6:   acct.V6,
			Reserved:   acct.ClientID,
		})
		if i == 0 && warp.RegPause > 0 {
			select {
			case <-time.After(warp.RegPause):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return out, nil
}
