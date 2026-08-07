package api

// ForgeEdge wiring (§6). This is the Go side of the contract in
// deploy/cloudflare/forgeedge/docs/GO_WIRING.md: the panel builds one canonical
// feed from its own database and either pushes it to every registered edge or
// serves it for the Worker's cron to pull. The result is that a subscriber's
// single URL resolves to the union of their VPS inbounds and the edge entries.
//
// The one invariant that matters here: every node in the feed has been through
// redactNodesForClient(). The edge does NOT re-redact — a REALITY or WireGuard
// server private key that reaches KV is a key you have published.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// EdgeFeedVersion is bumped when the document shape changes. It must stay in
// step with FEED_VERSION in deploy/cloudflare/forgeedge/src/edge/feed.ts.
const EdgeFeedVersion = 1

// edgeFeedPullTokenKey is the settings key holding the bearer the Worker's cron
// presents to GET /api/edge/feed.
const edgeFeedPullTokenKey = "edge_feed_pull_token"

// edgePushDebounce coalesces a burst of changes into one push. A bulk import
// touches every user in turn; without this it would fire one PUT per user at
// every registered edge.
const edgePushDebounce = 5 * time.Second

// EdgeFeedPanel identifies the panel that produced a feed.
type EdgeFeedPanel struct {
	Name    string `json:"name,omitempty"`
	BaseURL string `json:"base_url,omitempty"`
}

// EdgeFeedUser is one subscriber as the edge sees them.
type EdgeFeedUser struct {
	ID          string `json:"id"`
	SubToken    string `json:"sub_token"`
	Email       string `json:"email,omitempty"`
	Enabled     bool   `json:"enabled"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	UsedTraffic int64  `json:"used_traffic"`
	DataLimit   int64  `json:"data_limit"`
	// VLESSUUID / TrojanPassword are what make the edge multi-tenant: they are
	// the identity the edge stamps onto the entries it mints itself. Omit them
	// and every subscriber shares one edge identity.
	VLESSUUID      string        `json:"vless_uuid,omitempty"`
	TrojanPassword string        `json:"trojan_password,omitempty"`
	Nodes          []*model.Node `json:"nodes"`
}

// EdgeFeedDoc is the canonical feed (GO_WIRING.md §2.1).
type EdgeFeedDoc struct {
	Version     int            `json:"version"`
	GeneratedAt string         `json:"generated_at"`
	Panel       *EdgeFeedPanel `json:"panel,omitempty"`
	Users       []EdgeFeedUser `json:"users"`
	SharedNodes []*model.Node  `json:"shared_nodes,omitempty"`
}

// EdgeFeed builds the canonical feed from the panel database.
//
// Per-user nodes come from the same subscriptionNodes() that serves /sub/:token,
// so the edge and the VPS never disagree about what a user is entitled to, and
// every node — per-user and shared alike — is passed through
// redactNodesForClient() before it leaves this function.
func (s *Server) EdgeFeed() (*EdgeFeedDoc, error) {
	if s.db == nil {
		return nil, fmt.Errorf("edge feed: this panel has no database attached")
	}
	users, err := s.db.ListUsers(0)
	if err != nil {
		return nil, fmt.Errorf("edge feed: could not list users: %w", err)
	}
	host := hostOnly(s.panelHost())
	doc := &EdgeFeedDoc{
		Version:     EdgeFeedVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Panel:       &EdgeFeedPanel{Name: "ForgePanel", BaseURL: s.panelBaseURL()},
		Users:       make([]EdgeFeedUser, 0, len(users)),
	}
	for i := range users {
		u := &users[i]
		if u.SubToken == "" {
			// A user with no subscription token has no URL to resolve; sending
			// them would just be a row the edge drops with a warning.
			continue
		}
		fu := EdgeFeedUser{
			ID:             strconv.FormatUint(uint64(u.ID), 10),
			SubToken:       u.SubToken,
			Email:          u.Username,
			Enabled:        edgeUserEnabled(u),
			UsedTraffic:    u.UsedTraffic,
			DataLimit:      u.DataLimit,
			VLESSUUID:      u.UUID,
			TrojanPassword: u.Password,
			Nodes:          redactNodesForClient(s.subscriptionNodes(u.SubToken, host)),
		}
		if u.ExpireAt != nil {
			fu.ExpiresAt = u.ExpireAt.UTC().Format(time.RFC3339)
		}
		doc.Users = append(doc.Users, fu)
	}
	doc.SharedNodes = redactNodesForClient(s.edgeSharedNodes())
	return doc, nil
}

// edgeUserEnabled mirrors what subscriptionNodes() will actually return: a
// revoked, disabled, expired, or over-quota (limited) account gets an empty list,
// so reporting it as enabled would tell the edge to serve a subscription that
// resolves to nothing — and, for a limited account, would let the edge keep
// carrying traffic the VPS has already cut off. The VPS enforces the same set in
// enabledInboundSpecs, so the two planes agree on who is served.
func edgeUserEnabled(u *store.User) bool {
	return u.SubRevoked == nil &&
		u.Status != store.StatusDisabled &&
		u.Status != store.StatusExpired &&
		u.Status != store.StatusLimited
}

// edgeSharedNodes are the nodes every subscriber receives in addition to their
// own — in practice the panel's ForgeDNS tunnels, which are not bound to an
// inbound and so never appear in subscriptionNodes().
func (s *Server) edgeSharedNodes() []*model.Node {
	zones, err := s.db.ListZones()
	if err != nil {
		return nil
	}
	var out []*model.Node
	for i := range zones {
		z := &zones[i]
		if !z.Enabled {
			continue
		}
		addr := z.NSHost
		if addr == "" {
			addr = z.Zone
		}
		if addr == "" {
			continue
		}
		port := z.BindPort
		if port == 0 {
			port = 53
		}
		out = append(out, &model.Node{
			Protocol: model.ProtoForgeDNS,
			Address:  addr,
			Port:     port,
			Remark:   "ForgeDNS " + z.Zone,
			Tag:      "ForgeDNS " + z.Zone,
			ForgeDNS: &model.ForgeDNSOptions{
				Adapter: z.Adapter,
				Zone:    z.Zone,
				NSHost:  z.NSHost,
				// Key is the client-facing tunnel key, the same one the client
				// bundle carries. The server-side EncryptKey is never included.
				Key:    z.Key,
				RRType: "TXT",
			},
		})
	}
	return out
}

// panelBaseURL is the panel's public origin without the randomised admin path —
// the edge shows it to operators, it is not somewhere it posts.
func (s *Server) panelBaseURL() string {
	// A panel constructed without persisted settings (the light constructor, and
	// most unit tests) has no public address to advertise. Reporting "" is
	// correct there: it is omitted from the feed rather than invented.
	if s.cfg == nil || s.cfg.Panel() == nil {
		return ""
	}
	full := s.PublicURL()
	if p := s.cfg.Panel(); p.AdminPath != "" && p.AdminPath != "/" {
		full = strings.TrimSuffix(full, p.AdminPath)
	}
	return strings.TrimSuffix(full, "/")
}

// panelHost is the host exported links should dial, used as the fallback when
// an inbound listens on 0.0.0.0.
func (s *Server) panelHost() string {
	base := s.panelBaseURL()
	base = strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(base, '/'); i >= 0 {
		base = base[:i]
	}
	return base
}

// --- push -------------------------------------------------------------------

// EdgePushResult is one edge's outcome from a push.
type EdgePushResult struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	OK          bool     `json:"ok"`
	Users       int      `json:"users,omitempty"`
	SharedNodes int      `json:"shared_nodes,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// edgePushState carries the debounce timer. It lives on the Server rather than
// in a package global so two panels in one test binary do not share it.
type edgePushState struct {
	mu    sync.Mutex
	timer *time.Timer
}

// EdgePushSoon schedules a debounced push of the canonical feed. Call it after
// anything that changes what a subscriber should receive — user created,
// edited, enabled, disabled or deleted; inbound created, edited or deleted;
// traffic or quota reset (GO_WIRING.md §2.4).
//
// It returns immediately and is safe to call in a tight loop: fifty calls in a
// bulk import collapse into one push.
func (s *Server) EdgePushSoon() {
	if s.db == nil || s.isClosed() {
		return
	}
	s.edgePush.mu.Lock()
	defer s.edgePush.mu.Unlock()
	if s.edgePush.timer != nil {
		s.edgePush.timer.Reset(edgePushDebounce)
		return
	}
	s.edgePush.timer = time.AfterFunc(edgePushDebounce, func() {
		s.edgePush.mu.Lock()
		s.edgePush.timer = nil
		s.edgePush.mu.Unlock()
		if s.isClosed() {
			return
		}
		_, _ = s.pushFeedToAll()
	})
}

// pushFeedToAll builds the feed once and POSTs it to every registered edge.
func (s *Server) pushFeedToAll() ([]EdgePushResult, error) {
	doc, err := s.EdgeFeed()
	if err != nil {
		return nil, err
	}
	deps, err := s.db.ListEdgeDeployments()
	if err != nil {
		return nil, err
	}
	out := make([]EdgePushResult, 0, len(deps))
	for i := range deps {
		out = append(out, s.pushFeedTo(&deps[i], doc))
	}
	return out, nil
}

// pushFeedTo POSTs one document to one edge and records the outcome.
func (s *Server) pushFeedTo(d *store.EdgeDeployment, doc *EdgeFeedDoc) EdgePushResult {
	res := EdgePushResult{ID: d.ID, Name: d.Name}
	if d.PushToken == "" {
		res.Error = "no push token is stored for this edge"
		res.Remediation = "open the Worker's panel, copy feedPushToken from its status page, and re-register the deployment with it."
		_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), res.Error)
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pr, err := edge.PushFeed(ctx, nil, d.FeedURL(), d.PushToken, doc)
	if err != nil {
		res.Error = err.Error()
		if e, ok := edge.AsError(err); ok {
			res.Error = e.Message
			res.Remediation = e.Remediation
		}
		_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), res.Error)
		return res
	}
	res.OK = true
	res.Users, res.SharedNodes, res.Warnings = pr.Users, pr.SharedNodes, pr.Warnings
	status := fmt.Sprintf("ok: %d user(s)", pr.Users)
	if len(pr.Warnings) > 0 {
		// Surfaced, never swallowed: a warning means the edge dropped users or
		// nodes it could not parse, and those subscribers get a short list
		// without knowing it.
		status += "; warnings: " + strings.Join(pr.Warnings, "; ")
	}
	_ = s.db.UpdateEdgePushStatus(d.ID, time.Now(), status)
	return res
}
