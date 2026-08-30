package api

import (
	warppkg "github.com/forgepanel/forgepanel/internal/warp"
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/edge"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The secrets a REALITY / WireGuard / TLS inbound holds that a subscriber must
// NEVER receive. The edge does not re-redact, so anything here that reaches the
// feed is a key published to Cloudflare KV.
const (
	realityPrivate = "SERVER-REALITY-PRIVATE-KEY-MUST-NOT-LEAK"
	wgPrivate      = "SERVER-WIREGUARD-PRIVATE-KEY-MUST-NOT-LEAK"
	tlsKeyFile     = "/etc/forgepanel/certs/server.key"
)

// edgeFixture is a panel with one REALITY inbound and one WireGuard inbound,
// both carrying server-only key material, assigned to one user.
type edgeFixture struct {
	s    *Server
	user *store.User
}

func newEdgeFixture(t *testing.T) *edgeFixture {
	t.Helper()
	s := dbServerT(t)

	reality := &model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.10", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "vps-reality",
		Flow: "xtls-rprx-vision",
		Security: model.Security{
			Type: model.SecReality, KeyFile: tlsKeyFile,
			Reality: &model.Reality{
				PrivateKey: realityPrivate, PublicKey: "PUB", ShortID: "aabb",
				ServerNames: []string{"www.datadoghq.com"},
			},
		},
	}
	wg := &model.Node{
		Protocol: model.ProtoWireGuard, Address: "203.0.113.11", Port: 51820,
		Remark: "vps-wg",
		WireGuard: &model.WireGuardOptions{
			PrivateKey: wgPrivate, PeerPublicKey: "PEERPUB",
			PeerPrivateKey: "CLIENT-OWN-KEY", PeerAddress: []string{"10.0.0.2/32"},
		},
	}
	var ids []uint
	for _, n := range []*model.Node{reality, wg} {
		in, err := s.db.CreateInbound(n)
		if err != nil {
			t.Fatalf("CreateInbound: %v", err)
		}
		ids = append(ids, in.ID)
	}
	g := &store.Group{Name: "g", InboundIDs: store.IntSlice(ids)}
	if err := s.db.CreateGroup(g); err != nil {
		t.Fatal(err)
	}
	expire := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	u := &store.User{
		Username: "alice", GroupID: g.ID, Status: store.StatusActive,
		SubToken: "tok-alice", UUID: "11111111-2222-4333-8444-555555555555",
		Password: "alice-secret", UsedTraffic: 1234567, DataLimit: 10 << 30,
		ExpireAt: &expire,
	}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return &edgeFixture{s: s, user: u}
}

// TestEdgeFeed_IsRedacted is the single most important test in this file: it
// proves that no server-only key material can ride the feed into Cloudflare KV.
func TestEdgeFeed_IsRedacted(t *testing.T) {
	f := newEdgeFixture(t)

	doc, err := f.s.EdgeFeed()
	if err != nil {
		t.Fatalf("EdgeFeed: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{realityPrivate, wgPrivate, tlsKeyFile} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("server-only secret %q reached the canonical feed; the edge does not re-redact, so this key is published", secret)
		}
	}

	// Redaction must not gut the config: the client-facing halves survive.
	if len(doc.Users) != 1 {
		t.Fatalf("want 1 user, got %d", len(doc.Users))
	}
	nodes := doc.Users[0].Nodes
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	var sawReality, sawWG bool
	for _, n := range nodes {
		switch n.Protocol {
		case model.ProtoVLESS:
			sawReality = true
			if n.Security.Reality == nil || n.Security.Reality.PublicKey != "PUB" {
				t.Error("the REALITY public key a client needs was stripped too")
			}
			if n.Security.Reality.PrivateKey != "" {
				t.Error("REALITY private key survived redaction")
			}
		case model.ProtoWireGuard:
			sawWG = true
			if n.WireGuard == nil || n.WireGuard.PeerPrivateKey != "CLIENT-OWN-KEY" {
				t.Error("the client's own WireGuard key was stripped; the config would not connect")
			}
			if n.WireGuard.PrivateKey != "" {
				t.Error("WireGuard server private key survived redaction")
			}
		}
	}
	if !sawReality || !sawWG {
		t.Fatal("expected both inbounds in the feed")
	}

	// The stored inbound must be untouched — redaction works on deep copies.
	in, err := f.s.db.InboundByID(1)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := in.Node()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Security.Reality.PrivateKey != realityPrivate {
		t.Fatal("redaction mutated the stored inbound; the server would stop being able to serve REALITY")
	}
}

func TestEdgeFeed_Shape(t *testing.T) {
	f := newEdgeFixture(t)
	doc, err := f.s.EdgeFeed()
	if err != nil {
		t.Fatalf("EdgeFeed: %v", err)
	}
	if doc.Version != EdgeFeedVersion {
		t.Errorf("version = %d, want %d", doc.Version, EdgeFeedVersion)
	}
	if _, err := time.Parse(time.RFC3339, doc.GeneratedAt); err != nil {
		t.Errorf("generated_at is not RFC3339: %q", doc.GeneratedAt)
	}
	if doc.Panel == nil || doc.Panel.Name != "ForgePanel" {
		t.Errorf("panel block = %+v", doc.Panel)
	}
	u := doc.Users[0]
	if u.SubToken != "tok-alice" {
		t.Errorf("sub_token = %q", u.SubToken)
	}
	if u.ID != "1" {
		t.Errorf("id = %q, want the DB id as a string", u.ID)
	}
	if u.Email != "alice" {
		t.Errorf("email = %q", u.Email)
	}
	if !u.Enabled {
		t.Error("an active user must be enabled")
	}
	if u.UsedTraffic != 1234567 || u.DataLimit != 10<<30 {
		t.Errorf("quota fields = %d/%d", u.UsedTraffic, u.DataLimit)
	}
	if u.ExpiresAt != "2026-12-31T00:00:00Z" {
		t.Errorf("expires_at = %q", u.ExpiresAt)
	}
	// Multi-tenancy: without these every subscriber shares one edge identity.
	if u.VLESSUUID != "11111111-2222-4333-8444-555555555555" {
		t.Errorf("vless_uuid = %q", u.VLESSUUID)
	}
	if u.TrojanPassword != "alice-secret" {
		t.Errorf("trojan_password = %q", u.TrojanPassword)
	}
}

// TestEdgeFeed_ParsesAsTheWorkerExpects checks the JSON against the shape
// sanitizeFeed() in src/edge/feed.ts accepts: every node needs a string
// protocol, a string address and a numeric port, or the edge drops it.
func TestEdgeFeed_ParsesAsTheWorkerExpects(t *testing.T) {
	f := newEdgeFixture(t)
	doc, _ := f.s.EdgeFeed()
	raw, _ := json.Marshal(doc)

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("feed is not an object: %v", err)
	}
	users, ok := generic["users"].([]any)
	if !ok || len(users) == 0 {
		t.Fatalf("users is missing or empty: %T", generic["users"])
	}
	for _, raw := range users {
		u := raw.(map[string]any)
		if _, ok := u["sub_token"].(string); !ok {
			t.Fatal("a user without a string sub_token is dropped by the edge")
		}
		nodes, ok := u["nodes"].([]any)
		if !ok {
			t.Fatal("nodes must always be an array, even when empty")
		}
		for _, nraw := range nodes {
			n := nraw.(map[string]any)
			if _, ok := n["protocol"].(string); !ok {
				t.Error("node.protocol must be a string")
			}
			if _, ok := n["address"].(string); !ok {
				t.Error("node.address must be a string")
			}
			if _, ok := n["port"].(float64); !ok {
				t.Error("node.port must be a number")
			}
		}
	}
}

func TestEdgeFeed_DisabledAndRevokedUsers(t *testing.T) {
	f := newEdgeFixture(t)
	mk := func(name, token string, status store.UserStatus, revoked bool) {
		u := &store.User{Username: name, Status: status, SubToken: token, UUID: "u"}
		if revoked {
			now := time.Now()
			u.SubRevoked = &now
		}
		if err := f.s.db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
	}
	mk("bob", "tok-bob", store.StatusDisabled, false)
	mk("carol", "tok-carol", store.StatusExpired, false)
	mk("dave", "tok-dave", store.StatusActive, true)
	mk("erin", "tok-erin", store.StatusLimited, false)

	doc, err := f.s.EdgeFeed()
	if err != nil {
		t.Fatal(err)
	}
	// erin is over her data limit (StatusLimited): the edge must report her
	// disabled so it stops carrying traffic the VPS has already cut off.
	want := map[string]bool{"alice": true, "bob": false, "carol": false, "dave": false, "erin": false}
	got := map[string]bool{}
	for _, u := range doc.Users {
		got[u.Email] = u.Enabled
	}
	for name, expect := range want {
		if got[name] != expect {
			t.Errorf("%s: enabled = %v, want %v", name, got[name], expect)
		}
	}
}

func TestEdgeFeed_SkipsUsersWithNoSubToken(t *testing.T) {
	f := newEdgeFixture(t)
	if err := f.s.db.CreateUser(&store.User{Username: "tokenless", Status: store.StatusActive}); err != nil {
		t.Fatal(err)
	}
	doc, err := f.s.EdgeFeed()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range doc.Users {
		if u.Email == "tokenless" {
			t.Fatal("a user with no subscription token has no URL to resolve and must not be in the feed")
		}
	}
}

func TestEdgeFeed_SharedNodesFromForgeDNSZones(t *testing.T) {
	f := newEdgeFixture(t)
	if err := f.s.db.CreateZone(&store.ForgeDNSZone{
		Zone: "t.example.com", Adapter: "cottendns", Enabled: true,
		NSHost: "ns1.example.com", Key: "client-key", EncryptKey: "SERVER-ONLY-ENCRYPT-KEY",
	}); err != nil {
		t.Fatal(err)
	}
	// A disabled zone has to be written and then turned off: the column carries
	// `default:true`, so GORM substitutes the default for a zero-valued Enabled
	// on insert. Toggling afterwards is exactly what the panel's own handler does.
	off := &store.ForgeDNSZone{Zone: "off.example.com", Adapter: "cottendns", NSHost: "ns2.example.com"}
	if err := f.s.db.CreateZone(off); err != nil {
		t.Fatal(err)
	}
	off.Enabled = false
	if err := f.s.db.SaveZone(off); err != nil {
		t.Fatal(err)
	}
	doc, err := f.s.EdgeFeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.SharedNodes) != 1 {
		t.Fatalf("want only the enabled zone, got %d shared node(s)", len(doc.SharedNodes))
	}
	n := doc.SharedNodes[0]
	if n.Protocol != model.ProtoForgeDNS || n.Address != "ns1.example.com" || n.Port != 53 {
		t.Errorf("shared node = %+v", n)
	}
	raw, _ := json.Marshal(doc)
	if bytes.Contains(raw, []byte("SERVER-ONLY-ENCRYPT-KEY")) {
		t.Fatal("the zone's server-side encrypt key reached the feed")
	}
}

func TestEdgeFeed_NoDatabase(t *testing.T) {
	s := &Server{}
	if _, err := s.EdgeFeed(); err == nil {
		t.Fatal("a panel with no database cannot build a feed; that must be an error, not an empty document")
	}
}

// --- the pull endpoint ------------------------------------------------------

func edgeRouter(s *Server) *gin.Engine {
	r := gin.New()
	r.GET("/api/edge/feed", s.handleEdgeFeed)
	admin := r.Group("/api/admin")
	s.registerEdgeRoutes(admin)
	return r
}

func TestHandleEdgeFeed_TokenGate(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)

	// No token minted yet: the endpoint must not serve anything.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/edge/feed", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("with no token configured want 404, got %d: %s", w.Code, w.Body)
	}

	// Mint one through the admin route.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/feed-token", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("feed-token: %d %s", w.Code, w.Body)
	}
	var minted struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil || minted.Token == "" {
		t.Fatalf("feed-token body: %v %s", err, w.Body)
	}

	// Wrong bearer.
	w = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/edge/feed", nil)
	req.Header.Set("Authorization", "Bearer nope")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token want 401, got %d", w.Code)
	}

	// No bearer at all.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/edge/feed", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing token want 401, got %d", w.Code)
	}

	// Right bearer: the RAW document, not an envelope — the Worker feeds the
	// response straight into sanitizeFeed().
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/edge/feed", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid token want 200, got %d: %s", w.Code, w.Body)
	}
	var doc EdgeFeedDoc
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not a feed document: %v", err)
	}
	if doc.Version != EdgeFeedVersion || len(doc.Users) != 1 {
		t.Fatalf("unexpected document: version %d, %d user(s)", doc.Version, len(doc.Users))
	}
	if w.Header().Get("Cache-Control") == "" {
		t.Error("the feed carries subscriber credentials and must never be cached")
	}
	if bytes.Contains(w.Body.Bytes(), []byte(realityPrivate)) {
		t.Fatal("the pull endpoint served an unredacted node")
	}

	// Rotation invalidates the old token.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/feed-token?rotate=1", nil))
	var rotated struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.Token == minted.Token {
		t.Fatal("rotate=1 must mint a different token")
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/edge/feed", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("the pre-rotation token must stop working, got %d", w.Code)
	}
}

// --- deployments + push -----------------------------------------------------

// mockEdge replays the Worker's /feed endpoint, envelope and all.
type mockEdge struct {
	mu       sync.Mutex
	token    string
	path     string
	received []byte
	warnings []string
	reject   bool
	srv      *httptest.Server
}

func newMockEdge(t *testing.T, token, path string) *mockEdge {
	t.Helper()
	m := &mockEdge{token: token, path: path}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockEdge) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Machine-authenticated panel API: WARP register + .conf download. Both are
	// authorised by the push token in the Authorization header, exactly as the
	// real Worker accepts it (src/panel/handler.ts machine auth).
	if r.URL.Path == "/"+m.path+"/api/warp/accounts" || r.URL.Path == "/"+m.path+"/api/warp/conf" {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != m.token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/accounts") {
			_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Registered 2 WARP accounts.",` +
				`"body":[{"publicKey":"pk1","warpIPv6":"2606:4700::1/128"},{"publicKey":"pk2","warpIPv6":"2606:4700::2/128"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"status":200,"message":null,` +
			`"body":{"plain":"[Interface]\nPrivateKey = k\n","pro":"[Interface]\nPrivateKey = k\nJc = 5\nS1 = 0\nS2 = 0\n"}}`))
		return
	}

	if r.URL.Path != "/"+m.path+"/feed" {
		// Everything off the secure path is the decoy handler: HTML, not JSON.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>nothing to see</html>"))
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer != m.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Invalid feed push token.","body":null}`))
		return
	}
	body := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(body)
	m.mu.Lock()
	m.received = body
	reject := m.reject
	warnings := m.warnings
	m.mu.Unlock()
	if reject {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"status":400,"message":"feed.users is missing","body":null}`))
		return
	}
	var doc EdgeFeedDoc
	_ = json.Unmarshal(body, &doc)
	if warnings == nil {
		warnings = []string{}
	}
	out, _ := json.Marshal(map[string]any{
		"success": true, "status": 200, "message": "Feed accepted.",
		"body": map[string]any{"users": len(doc.Users), "sharedNodes": len(doc.SharedNodes), "warnings": warnings},
	})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (m *mockEdge) body(t *testing.T) EdgeFeedDoc {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	var doc EdgeFeedDoc
	if err := json.Unmarshal(m.received, &doc); err != nil {
		t.Fatalf("the edge received something that is not a feed: %v (%s)", err, m.received)
	}
	return doc
}

func registerEdge(t *testing.T, r *gin.Engine, body string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deployments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestEdgeDeployments_CRUDAndPush(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	const path = "qrs7tuvwxy23456789abcdef"
	m := newMockEdge(t, "push-token-123", path)

	created := registerEdge(t, r, fmt.Sprintf(
		`{"name":"forgeedge-a1","origin":%q,"secure_path":%q,"push_token":"push-token-123"}`,
		m.srv.URL, path))
	id := int(created["id"].(float64))

	// List: the push token must never come back out.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/deployments", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "push-token-123") {
		t.Fatal("the deployment list leaked the push token")
	}
	var list []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["has_push_token"] != true {
		t.Fatalf("list body = %s", w.Body)
	}

	// Push to everything.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/edge/push", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("push: %d %s", w.Code, w.Body)
	}
	var push struct {
		Users   int              `json:"users"`
		Pushed  int              `json:"pushed"`
		Failed  int              `json:"failed"`
		Results []EdgePushResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &push); err != nil {
		t.Fatal(err)
	}
	if push.Failed != 0 || push.Pushed != 1 || push.Users != 1 {
		t.Fatalf("push summary = %+v", push)
	}
	if !push.Results[0].OK || push.Results[0].Users != 1 {
		t.Fatalf("push result = %+v", push.Results[0])
	}

	// What the edge actually received is the redacted feed.
	got := m.body(t)
	if len(got.Users) != 1 || got.Users[0].SubToken != "tok-alice" {
		t.Fatalf("edge received %+v", got.Users)
	}
	m.mu.Lock()
	rawReceived := append([]byte(nil), m.received...)
	m.mu.Unlock()
	if bytes.Contains(rawReceived, []byte(realityPrivate)) {
		t.Fatal("an unredacted node reached the edge over the push path")
	}

	// The outcome is recorded against the row.
	d, err := f.s.db.EdgeDeploymentByID(uint(id))
	if err != nil {
		t.Fatal(err)
	}
	if d.LastPushAt == nil || !strings.HasPrefix(d.LastStatus, "ok:") {
		t.Fatalf("last push not recorded: %v %q", d.LastPushAt, d.LastStatus)
	}

	// Per-deployment push.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/api/admin/edge/deployments/%d/push", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("targeted push: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/edge/deployments/9999/push", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("push to an unknown id want 404, got %d", w.Code)
	}

	// Delete forgets the row without touching the Worker.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", fmt.Sprintf("/api/admin/edge/deployments/%d", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if _, err := f.s.db.EdgeDeploymentByID(uint(id)); err == nil {
		t.Fatal("row should be gone")
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", fmt.Sprintf("/api/admin/edge/deployments/%d", id), nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("second delete want 404, got %d", w.Code)
	}
}

func TestEdgePush_SurfacesWarnings(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	const path = "warnpath23456789abcdefgh"
	m := newMockEdge(t, "tok", path)
	m.warnings = []string{"dropped user 7: no sub_token"}
	registerEdge(t, r, fmt.Sprintf(`{"name":"w","origin":%q,"secure_path":%q,"push_token":"tok"}`, m.srv.URL, path))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/edge/push", nil))
	var push struct {
		Results []EdgePushResult `json:"results"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &push)
	if len(push.Results) != 1 || len(push.Results[0].Warnings) != 1 {
		t.Fatalf("a warning means subscribers silently lost nodes; it must be surfaced: %s", w.Body)
	}
	d, _ := f.s.db.EdgeDeploymentByName("w")
	if !strings.Contains(d.LastStatus, "warnings:") {
		t.Errorf("the warning must be recorded on the row too, got %q", d.LastStatus)
	}
}

func TestEdgePush_Failures(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	const path = "failpath23456789abcdefgh"
	m := newMockEdge(t, "right-token", path)

	// Wrong push token.
	registerEdge(t, r, fmt.Sprintf(`{"name":"bad-token","origin":%q,"secure_path":%q,"push_token":"wrong"}`, m.srv.URL, path))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/edge/push", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("every edge failing must not read as success: got %d %s", w.Code, w.Body)
	}
	var push struct {
		Failed  int              `json:"failed"`
		Results []EdgePushResult `json:"results"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &push)
	if push.Failed != 1 || push.Results[0].OK {
		t.Fatalf("expected a recorded failure: %s", w.Body)
	}
	if !strings.Contains(push.Results[0].Error, "push token") {
		t.Errorf("the failure should name the push token, got %q", push.Results[0].Error)
	}

	// Registered with no push token at all.
	registerEdge(t, r, fmt.Sprintf(`{"name":"no-token","origin":%q,"secure_path":%q}`, m.srv.URL, path))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/admin/edge/push", nil))
	_ = json.Unmarshal(w.Body.Bytes(), &push)
	found := false
	for _, res := range push.Results {
		if res.Name == "no-token" {
			found = true
			if res.OK || !strings.Contains(res.Error, "no push token") {
				t.Errorf("want a clear 'no push token' failure, got %+v", res)
			}
		}
	}
	if !found {
		t.Fatal("the tokenless edge was skipped silently")
	}
}

func TestEdgeRegister_RejectsBadBody(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	for _, body := range []string{`not json`, `{"name":"x"}`, `{"origin":"https://x.dev"}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/admin/edge/deployments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: want 400, got %d %s", body, w.Code, w.Body)
		}
	}
}

func TestEdgePreviewFeed(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/feed", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", w.Code, w.Body)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(realityPrivate)) {
		t.Fatal("the preview served an unredacted node")
	}
}

// --- the honest failures ----------------------------------------------------

func TestEdgeDeploy_WithoutCredentialsFailsClearly(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("a deploy with no Cloudflare credential must fail, not fake success: got %d %s", w.Code, w.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["kind"] != string(edge.KindNoCredentials) {
		t.Errorf("kind = %v", body["kind"])
	}
	if !strings.Contains(fmt.Sprint(body["remediation"]), "forgectl edge deploy") {
		t.Errorf("the error must say how to authorise, got %v", body["remediation"])
	}
}

// A deploy that omits the bundle now defaults to the worker compiled into the
// panel binary (internal/edge embed), so a one-click deploy needs no external
// build. It must succeed and upload the script, not fail with "missing bundle".
func TestEdgeDeploy_WithoutBundleUsesEmbedded(t *testing.T) {
	if !edge.HasBundle() {
		t.Skip("no embedded ForgeEdge bundle in this build (run `make edge-bundle`)")
	}
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	scripts := map[string]bool{}
	cf := cfAPIMock(t, scripts, nil)
	body := fmt.Sprintf(`{"name":"forgeedge-emb","api_token":"t","account_id":"acct-1","skip_verify": true, "api_base":%q}`, cf.URL+"/client/v4")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("a deploy with no bundle must default to the embedded bundle and succeed, got %d %s", w.Code, w.Body)
	}
	if !scripts["forgeedge-emb"] {
		t.Fatalf("the worker script was not uploaded: %s", w.Body)
	}
}

func TestEdgeDeleteWorker_WithoutTokenFailsClearly(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/api/admin/edge/deploy/some-worker", nil))
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("want 428 with no credential, got %d %s", w.Code, w.Body)
	}
}

func TestEdgeStatus_ProxiesTheWorker(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)

	const path = "statuspath23456789abcdef"
	var loggedIn bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/" + path + "/api/login":
			loggedIn = true
			w.Header().Set("Set-Cookie", "fe_session=abc; HttpOnly; Path=/")
			_, _ = w.Write([]byte(`{"success":true,"status":200,"message":"Signed in.","body":{"firstRun":false}}`))
		case "/" + path + "/api/status":
			if !loggedIn {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"success":false,"status":401,"message":"Unauthorized.","body":null}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"status":200,"message":null,"body":{"version":"0.1.0","users":14,"backendMode":"off","cleanIPs":{"count":37,"updatedAt":"2026-08-07T06:17:00Z"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	created := registerEdge(t, r, fmt.Sprintf(`{"name":"st","origin":%q,"secure_path":%q,"push_token":"t"}`, srv.URL, path))
	id := int(created["id"].(float64))

	// Without a password the Worker's own 401 comes back, unvarnished.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/api/admin/edge/deployments/%d/status", id), nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status want 401, got %d %s", w.Code, w.Body)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET",
		fmt.Sprintf("/api/admin/edge/deployments/%d/status?password=hunter2hunter2", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	var st edge.WorkerStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != "0.1.0" || st.Users != 14 || st.CleanIPs.Count != 37 {
		t.Fatalf("status body = %+v", st)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/deployments/9999/status", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown deployment want 404, got %d", w.Code)
	}
}

func TestEdgeUpdateCheck(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/repos/forgepanel/forgepanel/releases/latest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v0.2.0","html_url":"https://example.invalid/rel"}`))
	}))
	defer gh.Close()
	old := edge.GitHubAPIBase
	edge.GitHubAPIBase = gh.URL
	defer func() { edge.GitHubAPIBase = old }()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/update-check?current=0.1.0", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("update-check: %d %s", w.Code, w.Body)
	}
	var info edge.UpdateInfo
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Latest != "0.2.0" || !info.UpdateAvailable || info.Current != "0.1.0" {
		t.Fatalf("update info = %+v", info)
	}
}

func TestEdgePushSoon_Debounces(t *testing.T) {
	f := newEdgeFixture(t)
	const path = "debouncepath3456789abcde"
	m := newMockEdge(t, "tok", path)
	if err := f.s.db.CreateEdgeDeployment(&store.EdgeDeployment{
		Name: "d", Origin: m.srv.URL, SecurePath: path, PushToken: "tok",
	}); err != nil {
		t.Fatal(err)
	}
	// Fifty calls in a row — a bulk import — must not fire fifty pushes. The
	// timer is still pending when this returns, so nothing has been sent yet.
	for i := 0; i < 50; i++ {
		f.s.EdgePushSoon()
	}
	f.s.edgePush.mu.Lock()
	pending := f.s.edgePush.timer != nil
	f.s.edgePush.mu.Unlock()
	if !pending {
		t.Fatal("expected a single pending push timer")
	}
	m.mu.Lock()
	sent := m.received != nil
	m.mu.Unlock()
	if sent {
		t.Fatal("the debounce window had not elapsed, yet a push was sent")
	}

	// Fire it early and confirm the coalesced push actually lands.
	f.s.edgePush.mu.Lock()
	timer := f.s.edgePush.timer
	f.s.edgePush.mu.Unlock()
	timer.Reset(time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := m.received != nil
		m.mu.Unlock()
		if got {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the debounced push never landed")
}

func TestEdgeWarpRegisterAndConf(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	const path = "warproutepath23456789abcd"
	m := newMockEdge(t, "push-tok", path)

	// Mock Cloudflare's WARP registration API so the panel registers against a
	// fake instead of the live endpoint. Two accounts are minted (WoW pair).
	warp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{"config":{"client_id":"AAAA","interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}},"peers":[{"public_key":"PEERPUBKEY="}]}}`))
	}))
	defer warp.Close()
	oldWarp := warppkg.RegBase
	warppkg.RegBase = warp.URL
	oldPause := warppkg.RegPause
	warppkg.RegPause = 0
	defer func() { warppkg.RegBase = oldWarp; warppkg.RegPause = oldPause }()
	created := registerEdge(t, r, fmt.Sprintf(
		`{"name":"wd","origin":%q,"secure_path":%q,"push_token":"push-tok"}`, m.srv.URL, path))
	id := int(created["id"].(float64))

	// Register WARP → the panel calls the Worker with the push token, gets the
	// accounts back, and re-pushes the feed so the sub reflects them.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/api/admin/edge/deployments/%d/warp", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("warp register: %d %s", w.Code, w.Body)
	}
	var reg struct {
		Count  int  `json:"count"`
		Pushed bool `json:"pushed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	if reg.Count != 2 {
		t.Fatalf("expected 2 WARP accounts, got %d (%s)", reg.Count, w.Body)
	}
	if !reg.Pushed {
		t.Fatal("registering WARP should have re-pushed the feed so the sub serves the new nodes")
	}
	// The re-push must actually have reached the Worker.
	m.mu.Lock()
	got := m.received != nil
	m.mu.Unlock()
	if !got {
		t.Fatal("the feed was not pushed to the edge after WARP registration")
	}

	// Download the Amnezia .conf (?pro=1) — a text attachment carrying the junk
	// params, not JSON.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/api/admin/edge/deployments/%d/warp.conf?pro=1", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("warp.conf: %d %s", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "warp-amnezia.conf") {
		t.Fatalf("expected an amnezia .conf attachment, got Content-Disposition %q", cd)
	}
	body := w.Body.String()
	if !strings.Contains(body, "[Interface]") || !strings.Contains(body, "Jc = 5") || !strings.Contains(body, "S1 = 0") {
		t.Fatalf("the amnezia .conf is missing its junk params: %q", body)
	}

	// A deployment with no push token cannot be driven — the panel says so
	// plainly rather than pretending.
	nt := registerEdge(t, r, fmt.Sprintf(
		`{"name":"notoken","origin":%q,"secure_path":%q}`, m.srv.URL, path))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/api/admin/edge/deployments/%d/warp", int(nt["id"].(float64))), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a tokenless deployment, got %d %s", w.Code, w.Body)
	}
}

func TestEdgePushSoon_NoopWithoutDB(t *testing.T) {
	s := &Server{}
	s.EdgePushSoon() // must not panic or block
}

func TestConstantTimeEqualString(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "a", false},
	}
	for _, tc := range cases {
		if got := constantTimeEqualString(tc.a, tc.b); got != tc.want {
			t.Errorf("constantTimeEqualString(%q,%q) = %v", tc.a, tc.b, got)
		}
	}
}

// --- the live Cloudflare paths, against a mock API --------------------------

// cfAPIMock replays the Workers control-plane calls a deploy and a delete make.
// The panel handlers accept an api_base override for exactly this reason (and
// for an operator behind an egress proxy).
//
// uploads, when non-nil, collects the bindings array of every script upload. The
// PUT body used to be thrown away, which made every binding the handler sends —
// or fails to send — invisible from here.
func cfAPIMock(t *testing.T, scripts map[string]bool, uploads *[][]map[string]any) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	ok := func(w http.ResponseWriter, result string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":` + result + `}`))
	}
	fail := func(w http.ResponseWriter, status, code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"success":false,"result":null,"errors":[{"code":%d,"message":%q}]}`, code, msg)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/client/v4")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case p == "/accounts/acct-1/workers/subdomain":
			ok(w, `{"subdomain":"acme"}`)
		case strings.HasPrefix(p, "/accounts/acct-1/storage/kv/namespaces"):
			switch r.Method {
			case http.MethodGet:
				ok(w, `[]`)
			case http.MethodPost:
				ok(w, `{"id":"kv-1","title":"t"}`)
			default:
				ok(w, `null`)
			}
		case strings.HasPrefix(p, "/accounts/acct-1/workers/scripts/"):
			name, sub, _ := strings.Cut(strings.TrimPrefix(p, "/accounts/acct-1/workers/scripts/"), "/")
			if sub == "subdomain" {
				ok(w, `{"enabled":true}`)
				return
			}
			switch r.Method {
			case http.MethodGet:
				if !scripts[name] {
					fail(w, http.StatusNotFound, 10007, "workers.api.error.script_not_found")
					return
				}
				ok(w, `{"id":"`+name+`"}`)
			case http.MethodPut:
				// sub == "" is the script upload itself; the deploy also PUTs
				// .../schedules, which carries no bindings.
				if uploads != nil && sub == "" {
					*uploads = append(*uploads, cfUploadBindings(t, r))
				}
				scripts[name] = true
				ok(w, `{"id":"`+name+`"}`)
			case http.MethodDelete:
				if !scripts[name] {
					fail(w, http.StatusNotFound, 10007, "workers.api.error.script_not_found")
					return
				}
				delete(scripts, name)
				ok(w, `{"id":"`+name+`"}`)
			}
		default:
			fail(w, http.StatusNotFound, 7003, "Could not route to "+p)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// cfUploadBindings pulls the bindings array out of a script upload's multipart
// `metadata` part.
func cfUploadBindings(t *testing.T, r *http.Request) []map[string]any {
	t.Helper()
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Errorf("upload content type: %v", err)
		return nil
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err != nil {
			t.Error("the upload carried no metadata part")
			return nil
		}
		if part.FormName() != "metadata" {
			continue
		}
		var meta struct {
			Bindings []map[string]any `json:"bindings"`
		}
		if err := json.NewDecoder(part).Decode(&meta); err != nil {
			t.Errorf("decode upload metadata: %v", err)
			return nil
		}
		return meta.Bindings
	}
}

func TestEdgeDeploy_LiveAgainstMockCloudflare(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	scripts := map[string]bool{}
	cf := cfAPIMock(t, scripts, nil)

	body := fmt.Sprintf(`{"name":"forgeedge-live","api_token":"t","account_id":"acct-1",
		"secure_path":"livepath23456789abcdefg","bundle":"export default {}","skip_verify": true, "api_base":%q}`, cf.URL+"/client/v4")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deploy: %d %s", w.Code, w.Body)
	}
	var out struct {
		Registered bool `json:"registered"`
		Deployment struct {
			Origin     string `json:"origin"`
			PanelURL   string `json:"panel_url"`
			SecurePath string `json:"secure_path"`
		} `json:"deployment"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Registered {
		t.Error("a successful deploy must be recorded in the panel")
	}
	if out.Deployment.Origin != "https://forgeedge-live.acme.workers.dev" {
		t.Errorf("origin = %q", out.Deployment.Origin)
	}
	if !strings.HasSuffix(out.Deployment.PanelURL, "/livepath23456789abcdefg/panel") {
		t.Errorf("panel URL = %q", out.Deployment.PanelURL)
	}
	if !scripts["forgeedge-live"] {
		t.Error("no Worker was uploaded")
	}
	if _, err := f.s.db.EdgeDeploymentByName("forgeedge-live"); err != nil {
		t.Errorf("the deployment row is missing: %v", err)
	}

	// A second deploy under the same name must be refused, not silently
	// overwrite someone's Worker.
	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("re-deploy want 409, got %d %s", w.Code, w.Body)
	}
}

func TestEdgeDeploy_GeneratesNameAndPath(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	cf := cfAPIMock(t, map[string]bool{}, nil)
	body := fmt.Sprintf(`{"api_token":"t","account_id":"acct-1","bundle":"x","skip_verify": true, "api_base":%q}`, cf.URL+"/client/v4")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deploy: %d %s", w.Code, w.Body)
	}
	var out struct {
		Deployment struct {
			Name       string `json:"name"`
			SecurePath string `json:"secure_path"`
		} `json:"deployment"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.HasPrefix(out.Deployment.Name, "forgeedge-") {
		t.Errorf("generated name = %q", out.Deployment.Name)
	}
	if len(out.Deployment.SecurePath) != 24 {
		t.Errorf("generated secure path = %q", out.Deployment.SecurePath)
	}
}

// TestEdgeDeploy_SelfManageReachesTheUploadAndTheRow is wiring point A: the
// panel's own deploy handler.
//
// Two separate things get forgotten here, and the second is the quieter one. If
// the flag never reaches edge.DeploySpec the Worker is deployed without the
// credential; if it never reaches the stored row, the Worker HAS the credential
// and the next `forgectl edge update` strips it, because the update loop reads
// the flag back from that row.
func TestEdgeDeploy_SelfManageReachesTheUploadAndTheRow(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	var uploads [][]map[string]any
	cf := cfAPIMock(t, map[string]bool{}, &uploads)

	body := fmt.Sprintf(`{"name":"forgeedge-self","api_token":"cf-token","account_id":"acct-1",
		"secure_path":"selfpath23456789abcdefg","bundle":"export default {}","self_manage":true,
		"skip_verify":true,"api_base":%q}`, cf.URL+"/client/v4")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/edge/deploy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("deploy: %d %s", w.Code, w.Body)
	}
	if len(uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(uploads))
	}
	var sawToken, sawAccount bool
	for _, b := range uploads[0] {
		if b["name"] == "CF_API_TOKEN" && b["type"] == "secret_text" && b["text"] == "cf-token" {
			sawToken = true
		}
		if b["name"] == "CF_ACCOUNT_ID" && b["type"] == "plain_text" && b["text"] == "acct-1" {
			sawAccount = true
		}
	}
	if !sawToken || !sawAccount {
		t.Fatalf("self_manage:true did not reach the upload; bindings were %+v", uploads[0])
	}

	d, err := f.s.db.EdgeDeploymentByName("forgeedge-self")
	if err != nil {
		t.Fatalf("the deployment row is missing: %v", err)
	}
	if !d.SelfManage {
		t.Error("the row says this Worker is not self-managed, so the next update will strip its credential")
	}
	// Only the boolean is persisted. The panel deliberately holds no long-lived
	// Cloudflare secret; every deploy and update supplies its own api_token.
	if strings.Contains(fmt.Sprintf("%+v", *d), "cf-token") {
		t.Errorf("the API token was persisted in the panel row: %+v", *d)
	}
}

func TestEdgeDeleteWorker_LiveAgainstMockCloudflare(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	scripts := map[string]bool{"doomed": true}
	cf := cfAPIMock(t, scripts, nil)
	if err := f.s.db.CreateEdgeDeployment(&store.EdgeDeployment{
		Name: "doomed", Origin: "https://doomed.acme.workers.dev", SecurePath: "p23456789abcdefghijklmno",
	}); err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("/api/admin/edge/deploy/doomed?api_token=t&account_id=acct-1&api_base=%s",
		cf.URL+"/client/v4")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if scripts["doomed"] {
		t.Error("the Worker survived")
	}
	if _, err := f.s.db.EdgeDeploymentByName("doomed"); err == nil {
		t.Error("the panel row survived")
	}

	// Deleting something that is not there must be a 404, not a fake success.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", url, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("second delete want 404, got %d %s", w.Code, w.Body)
	}
}

func TestEdgeUpdateCheck_GitHubFailureIsReported(t *testing.T) {
	f := newEdgeFixture(t)
	r := edgeRouter(f.s)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer gh.Close()
	old := edge.GitHubAPIBase
	edge.GitHubAPIBase = gh.URL
	defer func() { edge.GitHubAPIBase = old }()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/admin/edge/update-check", nil))
	if w.Code == http.StatusOK {
		t.Fatalf("a failed check must not read as 'up to date': %d %s", w.Code, w.Body)
	}
}

func TestEdgeFail_UntypedError(t *testing.T) {
	r := gin.New()
	r.GET("/x", func(c *gin.Context) { edgeFail(c, fmt.Errorf("plain")) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "plain") {
		t.Fatalf("untyped error = %d %s", w.Code, w.Body)
	}
}

func TestEdgeFail_StatusPerKind(t *testing.T) {
	cases := map[edge.Kind]int{
		edge.KindValidation:    http.StatusBadRequest,
		edge.KindAuth:          http.StatusUnauthorized,
		edge.KindPermission:    http.StatusForbidden,
		edge.KindNotFound:      http.StatusNotFound,
		edge.KindConflict:      http.StatusConflict,
		edge.KindRateLimit:     http.StatusTooManyRequests,
		edge.KindNetwork:       http.StatusBadGateway,
		edge.KindNoCredentials: http.StatusPreconditionRequired,
		edge.KindServer:        http.StatusInternalServerError,
	}
	for kind, want := range cases {
		r := gin.New()
		k := kind
		r.GET("/x", func(c *gin.Context) { edgeFail(c, &edge.Error{Kind: k, Message: "m"}) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
		if w.Code != want {
			t.Errorf("kind %q → %d, want %d", kind, w.Code, want)
		}
	}
}

func TestPanelBaseURL_WithRealSettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FORGEPANEL_DATA", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataDir = dir
	p := cfg.Panel()
	p.Domain, p.Port, p.HTTPSEnabled = "panel.example.com", 443, true
	p.AdminPath = "/secret-admin"

	s := &Server{cfg: cfg}
	if got := s.panelBaseURL(); got != "https://panel.example.com" {
		t.Fatalf("panelBaseURL = %q; the randomised admin path must not be advertised to the edge", got)
	}
	if got := s.panelHost(); got != "panel.example.com" {
		t.Fatalf("panelHost = %q", got)
	}

	// A panel with no persisted settings advertises nothing rather than a guess.
	if got := (&Server{}).panelBaseURL(); got != "" {
		t.Errorf("a settings-less panel should report no base URL, got %q", got)
	}
	if got := (&Server{}).panelHost(); got != "" {
		t.Errorf("panelHost = %q", got)
	}
}
