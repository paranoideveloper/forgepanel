// Package warp manages Cloudflare WARP as an outbound this panel owns.
//
// WARP is free egress that is not the VPS's own IP, which makes it useful for
// two unrelated jobs: giving traffic a different exit than the one the server
// advertises, and reaching things the datacentre's own address is blocked from.
// Both cores can dial it — it is an ordinary WireGuard outbound once the account
// exists — so the work here is entirely in getting an account and shaping it
// into something the renderers already understand.
//
// The registration half already existed in internal/edge, but only to push
// accounts into a Cloudflare Worker's KV. This package owns the API contract
// now and internal/edge delegates to it, so Cloudflare's endpoint is described
// in one place rather than drifting between two.
//
// WHAT IS DELIBERATELY NOT HERE: a handshake prober. Verifying a WARP endpoint
// honestly means completing a WireGuard Noise handshake — a silent UDP port
// answers nothing either way — and that needs a full implementation this
// repository does not depend on. Rotation therefore changes the endpoint and
// reports what it changed it to; it does not claim the new one is healthy.
// Saying so is better than a probe that returns "up" for every address.
package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// RegBase is Cloudflare's consumer WARP registration API. No account or
// credential is required — it is the same endpoint the WARP app itself uses.
// A var so tests can point it at a mock.
var RegBase = "https://api.cloudflareclient.com/v0a4005/reg"

// RegPause is the gap between two back-to-back registrations, which the API
// rate-limits from a single IP. A var so tests can zero it.
var RegPause = 2 * time.Second

// DefaultEndpoint is WARP's published hostname. It resolves to the same anycast
// edge as the numeric endpoints below; the numbers exist for hosts whose DNS is
// interfered with, and for rotation.
const DefaultEndpoint = "engage.cloudflareclient.com:2408"

// DefaultMTU is what the WARP client itself uses. WireGuard's own default of
// 1420 leaves no room for Cloudflare's encapsulation and shows up as large
// packets vanishing while pings succeed — the classic MTU black hole, which is
// far harder to recognise than a tunnel that simply fails.
const DefaultMTU = 1280

// Account is one registered WARP device.
type Account struct {
	// PrivateKey is ours and never leaves this panel. PeerPublicKey is
	// Cloudflare's.
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	// ClientID is base64 and becomes WireGuard's three reserved bytes. Without
	// it Cloudflare drops the session, which presents as a tunnel that
	// handshakes and then carries nothing.
	ClientID string `json:"client_id"`
	// V4 and V6 are the addresses Cloudflare assigned, carried with their
	// prefix length so they can be used as interface addresses directly.
	V4 string `json:"v4"`
	V6 string `json:"v6"`
	// DeviceID and Token authenticate later calls about this device — which is
	// what WARP+ license activation is.
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	// Premium reports whether Cloudflare considers this device WARP+.
	Premium bool `json:"premium"`
	// Endpoint is the address the outbound dials. Stored per account because
	// rotation changes it and the rest of the account stays valid.
	Endpoint string `json:"endpoint"`
	// RotatedAt is when Endpoint last changed, so a scheduled rotation can tell
	// whether its interval has elapsed without a second place to keep state.
	RotatedAt time.Time `json:"rotated_at,omitempty"`
}

type regResponse struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
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
	Account accountInfo `json:"account"`
}

// accountInfo is Cloudflare's account object. It arrives NESTED under "account"
// in a registration response and FLAT at the top level in the reply to a
// license update — the same fields, two shapes, which is why they are decoded
// separately rather than through one struct that would silently read zero for
// whichever shape it was not written for.
type accountInfo struct {
	License     string `json:"license"`
	WarpPlus    bool   `json:"warp_plus"`
	PremiumData int64  `json:"premium_data"`
	AccountType string `json:"account_type"`
}

// Register mints one WARP device.
func Register(ctx context.Context, hc *http.Client) (Account, error) {
	if hc == nil {
		hc = netegress.Client(30 * time.Second)
	}
	kp, err := keygen.WireGuardKeys()
	if err != nil {
		return Account{}, fmt.Errorf("warp: generating a keypair: %w", err)
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
	raw, err := call(ctx, hc, http.MethodPost, RegBase, "", body)
	if err != nil {
		return Account{}, err
	}
	var rr regResponse
	if err := json.Unmarshal(raw, &rr); err != nil {
		return Account{}, fmt.Errorf("warp: could not decode the registration reply: %w", err)
	}
	if len(rr.Config.Peers) == 0 || rr.Config.Peers[0].PublicKey == "" {
		return Account{}, fmt.Errorf("warp: registration returned no peer public key, so there is nothing to dial")
	}
	return Account{
		PrivateKey:    kp.PrivateKey,
		PeerPublicKey: rr.Config.Peers[0].PublicKey,
		ClientID:      rr.Config.ClientID,
		V4:            withPrefix(rr.Config.Interface.Addresses.V4, "/32"),
		V6:            withPrefix(rr.Config.Interface.Addresses.V6, "/128"),
		DeviceID:      rr.ID,
		Token:         rr.Token,
		Premium:       rr.Account.WarpPlus,
		Endpoint:      DefaultEndpoint,
	}, nil
}

// ActivateLicense attaches a WARP+ license key to an already-registered device
// and returns the account as Cloudflare then describes it.
//
// The returned Premium is read back from Cloudflare rather than assumed from a
// 2xx: the API accepts a well-formed but exhausted or already-bound key and
// answers 200 with warp_plus still false, so trusting the status code would
// report a plan the device does not have.
func ActivateLicense(ctx context.Context, hc *http.Client, acct Account, license string) (Account, error) {
	license = strings.TrimSpace(license)
	if license == "" {
		return acct, fmt.Errorf("warp: no license key given")
	}
	if acct.DeviceID == "" || acct.Token == "" {
		return acct, fmt.Errorf("warp: this account was registered without a device id or token, " +
			"so Cloudflare cannot be told which device the license belongs to; register it again")
	}
	if hc == nil {
		hc = netegress.Client(30 * time.Second)
	}
	body, _ := json.Marshal(map[string]string{"license": license})
	url := strings.TrimRight(RegBase, "/") + "/" + acct.DeviceID + "/account"
	raw, err := call(ctx, hc, http.MethodPut, url, acct.Token, body)
	if err != nil {
		return acct, err
	}
	// Flat, not nested: this endpoint answers with the account object itself.
	// Decoding it as a registration reply would read warp_plus from a field that
	// is not there and report every activation as a failure.
	var updated accountInfo
	if err := json.Unmarshal(raw, &updated); err != nil {
		return acct, fmt.Errorf("warp: could not decode the license reply: %w", err)
	}
	acct.Premium = updated.WarpPlus || updated.PremiumData > 0
	if !acct.Premium {
		return acct, fmt.Errorf("warp: Cloudflare accepted the request but the device is still not WARP+ — " +
			"the key is typically already bound to another device, or its quota is spent")
	}
	return acct, nil
}

// call performs one WARP API request and decodes it.
func call(ctx context.Context, hc *http.Client, method, url, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("warp: %w", err)
	}
	// The API is only served to what looks like the WARP client.
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warp: could not reach Cloudflare's WARP API (%s): %w — "+
			"this host needs outbound HTTPS to api.cloudflareclient.com", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("warp: Cloudflare answered %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

// ReservedFromClientID turns the base64 client id into the three bytes
// WireGuard carries as `reserved`.
//
// Ported from the Worker's reservedFromClientID (deploy/cloudflare/forgeedge/
// src/warp/account.ts) so both halves of this project decode it identically.
// The id is base64URL in some responses and standard base64 in others, hence the
// substitution; short input is zero-padded because the field is fixed-width and
// a two-byte reserved is rejected outright by both cores.
func ReservedFromClientID(clientID string) []int {
	s := strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimSpace(clientID))
	// Tolerate a missing pad: encoders differ and RawStdEncoding would reject
	// the padded form, so normalise to padded and use the strict decoder.
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw = nil
	}
	out := make([]int, 3)
	for i := 0; i < 3 && i < len(raw); i++ {
		out[i] = int(raw[i])
	}
	return out
}

// Node shapes an account into the canonical node the existing renderers accept,
// so the outbound JSON is produced by the same code that renders every other
// WireGuard node rather than by a second hand-written copy of Xray's schema.
//
// Both PrivateKey and PeerPrivateKey carry our key on purpose: the Xray
// renderer reads the first and the sing-box renderer reads the second (there it
// means "the dialling side's key"). Setting only one produces a config that is
// valid, silent, and wrong on whichever core was not considered.
func Node(acct Account) (*model.Node, error) {
	if acct.PrivateKey == "" || acct.PeerPublicKey == "" {
		return nil, fmt.Errorf("warp: this account is missing a key, so no outbound can be built from it")
	}
	host, port, err := splitHostPort(endpointOr(acct.Endpoint))
	if err != nil {
		return nil, err
	}
	var local []string
	if acct.V4 != "" {
		local = append(local, acct.V4)
	}
	if acct.V6 != "" {
		local = append(local, acct.V6)
	}
	if len(local) == 0 {
		return nil, fmt.Errorf("warp: this account has no assigned address, so the tunnel has no source to dial from")
	}
	return &model.Node{
		Protocol: model.ProtoWireGuard,
		Address:  host,
		Port:     port,
		WireGuard: &model.WireGuardOptions{
			PrivateKey:     acct.PrivateKey,
			PeerPrivateKey: acct.PrivateKey,
			PublicKey:      acct.PeerPublicKey,
			LocalAddress:   local,
			AllowedIPs:     []string{"0.0.0.0/0", "::/0"},
			MTU:            DefaultMTU,
			Reserved:       ReservedFromClientID(acct.ClientID),
		},
	}, nil
}

// Endpoints is the rotation pool: Cloudflare's published WARP anycast addresses
// on the standard port, plus the hostname.
//
// They all terminate on the same edge, so rotating between them changes which
// address a censor sees rather than where the traffic comes out. That is the
// actual purpose — a blocked address is the common failure, a dead WARP edge is
// not — and it is why rotation does not try to prove the new one is faster.
var Endpoints = []string{
	DefaultEndpoint,
	"162.159.192.1:2408",
	"162.159.193.10:2408",
	"162.159.195.1:2408",
}

// NextEndpoint picks a rotation target that is not the one in use.
//
// Random rather than round-robin: rotation is scheduled, so a fixed order makes
// the sequence of exit addresses predictable from a single observation, and the
// pool is small enough that the cycle would be short.
func NextEndpoint(current string) string {
	pool := make([]string, 0, len(Endpoints))
	for _, e := range Endpoints {
		if e != current {
			pool = append(pool, e)
		}
	}
	if len(pool) == 0 {
		return current
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	if err != nil {
		return pool[0]
	}
	return pool[n.Int64()]
}

func endpointOr(e string) string {
	if strings.TrimSpace(e) == "" {
		return DefaultEndpoint
	}
	return e
}

func splitHostPort(e string) (string, int, error) {
	i := strings.LastIndex(e, ":")
	if i <= 0 || i == len(e)-1 {
		return "", 0, fmt.Errorf("warp: endpoint %q is not host:port", e)
	}
	host, portStr := e[:i], e[i+1:]
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("warp: endpoint %q has no usable port", e)
	}
	return host, port, nil
}

func withPrefix(addr, prefix string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, "/") {
		return addr
	}
	return addr + prefix
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
