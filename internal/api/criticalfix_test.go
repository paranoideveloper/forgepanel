package api

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/config"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/protocol/routing"
	"github.com/forgepanel/forgepanel/internal/store"
)

func dbServerT(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Server{cfg: &config.Config{}, db: db, router: gin.New(),
		signer: auth.NewSigner([]byte("test")), login: newLoginLimiter(), subs: newLoginLimiter()}
}

// #1: engine-dependent routes must not panic when s.engine is nil.
func TestEngineNilNoPanic(t *testing.T) {
	s := dbServerT(t) // engine is nil
	r := gin.New()
	r.POST("/reload", func(c *gin.Context) {
		if s.engine == nil {
			s.engineUnavailable(c)
			return
		}
		c.JSON(200, s.engine.Status())
	})
	r.POST("/hb", s.handleNodeHeartbeat)

	// A node so the heartbeat authenticates, then succeeds with no engine.
	_ = s.db.CreateNode(&store.Node{Name: "n1", EnrollToken: "tok123"})
	code, _ := post(t, r, "/hb", `{"token":"tok123","cpu":1,"mem_mb":10}`)
	if code != 200 {
		t.Fatalf("heartbeat must succeed in light mode, got %d", code)
	}
	code, out := post(t, r, "/reload", "")
	if code != 503 || out["code"] != "engine_unavailable" {
		t.Fatalf("reload with nil engine want 503/engine_unavailable, got %d %v", code, out)
	}
}

// #3: a stored recovery code works for login exactly once.
func TestRecoveryCodeLogin(t *testing.T) {
	s := dbServerT(t)
	secret := "JBSWY3DPEHPK3PXP"
	hash, _ := auth.HashPassword("Sup3rSecret!")
	admin := &store.Admin{Username: "owner", PasswordHash: hash, Role: store.RoleOwner, TOTPSecret: secret}
	if err := s.db.CreateAdmin(admin); err != nil {
		t.Fatal(err)
	}
	codes, err := s.generateRecoveryCodes(admin.ID, 8)
	if err != nil || len(codes) != 8 {
		t.Fatalf("gen codes: %v", err)
	}
	r := gin.New()
	r.POST("/login", s.handleLogin)

	// Login with a recovery code (no TOTP) succeeds and returns a token.
	body := `{"username":"owner","password":"Sup3rSecret!","recovery_code":"` + codes[0] + `"}`
	code, out := post(t, r, "/login", body)
	if code != 200 || out["access_token"] == nil {
		t.Fatalf("recovery login failed: %d %v", code, out)
	}
	// Same code cannot be reused (single-use).
	code, _ = post(t, r, "/login", body)
	if code == 200 {
		t.Fatal("recovery code must be single-use")
	}
	// Remaining count dropped to 7.
	got, _ := s.db.AdminByUsername("owner")
	if recoveryRemaining(got.RecoveryCodes) != 7 {
		t.Fatalf("remaining should be 7, got %d", recoveryRemaining(got.RecoveryCodes))
	}
}

// #6: sing-box subscription is valid sing-box JSON, not base64 V2Ray.
func TestSingboxSubscription(t *testing.T) {
	nodes := []*model.Node{
		{Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			Transport: model.Transport{Network: model.NetWS, Path: "/w"}, Security: model.Security{Type: model.SecTLS, ServerName: "x.com"}, Remark: "a"},
	}
	raw := singboxSubscription(nodes, routing.Options{}, routing.Fragment{})
	var doc map[string]any
	if err := jsonUnmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, raw)
	}
	outs, ok := doc["outbounds"].([]any)
	if !ok || len(outs) < 2 {
		t.Fatalf("expected outbounds array, got %v", doc["outbounds"])
	}
}

// #7: reseller quota is enforced transactionally at the repository layer.
func TestResellerQuotaEnforced(t *testing.T) {
	s := dbServerT(t)
	reseller := &store.Admin{Username: "r", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 2, TrafficCredit: 0}
	_ = s.db.CreateAdmin(reseller)
	mk := func(name string) error {
		return s.db.CreateUserEnforcingQuota(&store.User{Username: name, Status: store.StatusActive, OwnerAdminID: reseller.ID, SubToken: name}, reseller)
	}
	if err := mk("u1"); err != nil {
		t.Fatalf("u1: %v", err)
	}
	if err := mk("u2"); err != nil {
		t.Fatalf("u2: %v", err)
	}
	if err := mk("u3"); err == nil {
		t.Fatal("u3 must be rejected over quota")
	}
	// Owner (unlimited) bypasses.
	owner := &store.Admin{Username: "o", PasswordHash: "x", Role: store.RoleOwner, UserQuota: 1}
	_ = s.db.CreateAdmin(owner)
	for i := 0; i < 5; i++ {
		if err := s.db.CreateUserEnforcingQuota(&store.User{Username: "o" + string(rune('a'+i)), OwnerAdminID: owner.ID, SubToken: "o" + string(rune('a'+i))}, owner); err != nil {
			t.Fatalf("owner bypass failed: %v", err)
		}
	}
	// Traffic credit: cannot allocate an unlimited-traffic user.
	tr := &store.Admin{Username: "tr", PasswordHash: "x", Role: store.RoleReseller, TrafficCredit: 1000}
	_ = s.db.CreateAdmin(tr)
	if err := s.db.CreateUserEnforcingQuota(&store.User{Username: "big", OwnerAdminID: tr.ID, DataLimit: 0, SubToken: "big"}, tr); err == nil {
		t.Fatal("unlimited-traffic user under a finite credit must be rejected")
	}
	if err := s.db.CreateUserEnforcingQuota(&store.User{Username: "ok", OwnerAdminID: tr.ID, DataLimit: 600, SubToken: "ok"}, tr); err != nil {
		t.Fatalf("600 within 1000 credit should pass: %v", err)
	}
	if err := s.db.CreateUserEnforcingQuota(&store.User{Username: "over", OwnerAdminID: tr.ID, DataLimit: 600, SubToken: "over"}, tr); err == nil {
		t.Fatal("600+600 over 1000 credit must be rejected")
	}
}

// #7 concurrency: the cap holds under concurrent creates (never exceeds quota).
func TestResellerQuotaConcurrent(t *testing.T) {
	s := dbServerT(t)
	reseller := &store.Admin{Username: "rc", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 5}
	_ = s.db.CreateAdmin(reseller)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "c" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			if err := s.db.CreateUserEnforcingQuota(&store.User{Username: name, OwnerAdminID: reseller.ID, SubToken: name}, reseller); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok > 5 {
		t.Fatalf("quota breached under concurrency: %d created, cap 5", ok)
	}
}

func TestRedactNodesForClient(t *testing.T) {
	n := &model.Node{
		Protocol: model.ProtoVLESS, Address: "1.2.3.4", Port: 443, UUID: "u",
		Security: model.Security{Type: model.SecReality, KeyFile: "/etc/forgepanel/key.pem",
			Reality: &model.Reality{PrivateKey: "SERVER-PRIV", PublicKey: "PUB", ShortID: "ab"}},
		WireGuard: &model.WireGuardOptions{PrivateKey: "WG-SERVER-PRIV", PeerPrivateKey: "CLIENT-PRIV", PublicKey: "WG-PUB"},
	}
	out := redactNodesForClient([]*model.Node{n})
	r := out[0]
	if r.Security.Reality.PrivateKey != "" {
		t.Fatal("REALITY server private key leaked to client")
	}
	if r.Security.KeyFile != "" {
		t.Fatal("TLS key file path leaked to client")
	}
	if r.WireGuard.PrivateKey != "" {
		t.Fatal("WireGuard server private key leaked to client")
	}
	// Client-side fields must survive so configs still work.
	if r.Security.Reality.PublicKey != "PUB" || r.WireGuard.PeerPrivateKey != "CLIENT-PRIV" {
		t.Fatal("client fields must be preserved")
	}
	// The stored node must NOT be mutated by redaction.
	if n.Security.Reality.PrivateKey != "SERVER-PRIV" || n.WireGuard.PrivateKey != "WG-SERVER-PRIV" {
		t.Fatal("original node was mutated by redaction")
	}
}
