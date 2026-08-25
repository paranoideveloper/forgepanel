package edgebot

import (
	"context"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/edge"
)

// fakeOps is an in-memory Ops so the router can be tested with no network.
type fakeOps struct {
	deployed  map[string]Deployment
	config    map[string]map[string]any // per worker name
	deployErr error
	verifyErr error
	warpCount int
}

func newFakeOps() *fakeOps {
	return &fakeOps{deployed: map[string]Deployment{}, config: map[string]map[string]any{}}
}

func (f *fakeOps) VerifyCreds(_ context.Context, _, account string) (string, error) {
	if f.verifyErr != nil {
		return "", f.verifyErr
	}
	if account == "" {
		account = "acct-auto"
	}
	return account, nil
}

func (f *fakeOps) Deploy(_ context.Context, _, account, name, domain string) (Deployment, error) {
	if f.deployErr != nil {
		return Deployment{}, f.deployErr
	}
	if name == "" {
		name = "forgeedge-abc123"
	}
	d := Deployment{
		Name: name, Origin: "https://" + name + ".workers.dev", SecurePath: "securepath23456789abcd",
		FeedPushToken: "push-" + name, AccountID: account, Domain: domain,
	}
	f.deployed[name] = d
	f.config[name] = map[string]any{
		"version": float64(1), "protocols": []any{"vless"}, "ports": []any{float64(443)},
		"cleanIPs": []any{}, "customCdnSni": "", "customCdnAddrs": []any{},
		"fragment": map[string]any{"enabled": false, "lengthMin": float64(1), "lengthMax": float64(2), "delayMin": float64(1), "delayMax": float64(2)},
		"backend":  map[string]any{"enabled": false, "url": ""},
	}
	return d, nil
}

func (f *fakeOps) Update(_ context.Context, _, _ string, _ Deployment) error { return nil }
func (f *fakeOps) Destroy(_ context.Context, _, _ string, d Deployment, _ bool) error {
	delete(f.deployed, d.Name)
	return nil
}
func (f *fakeOps) AttachDomain(_ context.Context, _, _ string, _ Deployment, _ string) error {
	return nil
}
func (f *fakeOps) Status(_ context.Context, d Deployment) (*edge.WorkerStatus, error) {
	st := &edge.WorkerStatus{Version: "1.19.1", Users: 3, BackendMode: "off"}
	st.CleanIPs.Count = 5
	return st, nil
}
func (f *fakeOps) GetConfig(_ context.Context, d Deployment) (map[string]any, error) {
	c := f.config[d.Name]
	// return a shallow copy so the router's edits don't mutate our master
	out := map[string]any{}
	for k, v := range c {
		out[k] = v
	}
	return out, nil
}
func (f *fakeOps) PutConfig(_ context.Context, d Deployment, cfg map[string]any) (map[string]any, error) {
	// mimic the worker's validation: reject an SNI that isn't a plausible host.
	if sni, _ := cfg["customCdnSni"].(string); strings.Contains(sni, " ") || sni == "bad" {
		return nil, &edge.Error{Op: "edge-config-put", Kind: edge.KindValidation, Message: "customCdnSni is not a hostname"}
	}
	f.config[d.Name] = cfg
	return cfg, nil
}
func (f *fakeOps) RefreshCleanIPs(_ context.Context, _ Deployment) (*edge.CleanIPStore, error) {
	return &edge.CleanIPStore{Entries: []string{"1.1.1.1", "104.16.0.1"}}, nil
}
func (f *fakeOps) ProbeCleanIP(_ context.Context, _ Deployment, target string) (*edge.CleanIPProbe, error) {
	ms := 42
	return &edge.CleanIPProbe{Target: target, SuccessRate: "3/3", AvgLatencyMs: &ms}, nil
}
func (f *fakeOps) RefreshExternal(_ context.Context, _ Deployment) (int, error) { return 7, nil }
func (f *fakeOps) RotatePath(_ context.Context, _ Deployment) (string, error) {
	return "freshpath23456789abcd", nil
}
func (f *fakeOps) Warp(_ context.Context, _ Deployment) (int, error) { return f.warpCount, nil }
func (f *fakeOps) WarpConf(_ context.Context, _ Deployment) (string, string, error) {
	return "[Interface]\nplain", "[Interface]\npro", nil
}

// harness builds a router with a fresh store and fake ops.
func harness(t *testing.T, owner int64) (*Router, *Store, *fakeOps) {
	t.Helper()
	store, err := Open(t.TempDir(), owner)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ops := newFakeOps()
	return NewRouter(store, ops), store, ops
}

// send routes one text message from a user and returns the result.
func send(r *Router, userID int64, text string) Result {
	return r.Handle(context.Background(), Incoming{
		UserID: userID, ChatID: userID, Username: "u", Text: text, MessageID: 100,
	})
}

// firstText returns the text of the first outbound message.
func firstText(res Result) string {
	if len(res.Outs) == 0 {
		return ""
	}
	return res.Outs[0].Text
}

func hasOutTo(res Result, chatID int64) *Out {
	for i := range res.Outs {
		if res.Outs[i].ChatID == chatID {
			return &res.Outs[i]
		}
	}
	return nil
}

func TestRouter_AccessRequestAndApproval(t *testing.T) {
	const owner, stranger = int64(1), int64(2)
	r, store, _ := harness(t, owner)

	// A stranger's first message becomes a request; the owner is notified with buttons.
	res := send(r, stranger, "/start")
	if hasOutTo(res, stranger) == nil {
		t.Fatal("stranger should get a 'request sent' reply")
	}
	ownerMsg := hasOutTo(res, owner)
	if ownerMsg == nil || len(ownerMsg.Buttons) == 0 {
		t.Fatal("owner should get a notification with approve/deny buttons")
	}
	if store.IsApproved(stranger) {
		t.Fatal("stranger must not be approved yet")
	}

	// Stranger still can't run commands.
	if !strings.Contains(firstText(send(r, stranger, "/deploy")), "waiting") {
		t.Fatal("pending user should be told they're waiting")
	}

	// Owner taps Approve.
	cb := r.Handle(context.Background(), Incoming{
		UserID: owner, ChatID: owner, IsCallback: true, CallbackID: "c1",
		CallbackData: "approve:2",
	})
	if !store.IsApproved(stranger) {
		t.Fatalf("approve callback did not approve: %+v", cb)
	}
	if hasOutTo(cb, stranger) == nil {
		t.Fatal("approved user should be notified")
	}

	// A non-owner cannot approve anyone.
	deny := r.Handle(context.Background(), Incoming{
		UserID: stranger, ChatID: stranger, IsCallback: true, CallbackID: "c2",
		CallbackData: "approve:999",
	})
	if !strings.Contains(deny.CallbackAnswer, "Owner") {
		t.Fatalf("non-owner approve should be refused, got %q", deny.CallbackAnswer)
	}
}

func tapButton(r *Router, userID int64, data string) Result {
	return r.Handle(context.Background(), Incoming{
		UserID: userID, ChatID: userID, IsCallback: true, CallbackID: "cb", CallbackData: data,
	})
}

func TestRouter_MenuNavigation(t *testing.T) {
	r, store, _ := harness(t, 1)
	_ = store.Decide(2, StatusApproved)

	// /start shows a home screen WITH buttons.
	res := send(r, 2, "/start")
	if len(res.Outs) == 0 || len(res.Outs[0].Buttons) == 0 {
		t.Fatalf("/start should render buttons: %+v", res)
	}

	// Tapping "Connect Cloudflare" explains how to get a token.
	if !strings.Contains(firstText(tapButton(r, 2, "m:cf")), "API Tokens") {
		t.Fatal("m:cf should show the token how-to")
	}

	// Tapping Deploy without creds nudges to connect first (no crash).
	dep := tapButton(r, 2, "m:deploy")
	if !strings.Contains(firstText(dep), "connect your Cloudflare") {
		t.Fatalf("m:deploy without creds: %q", firstText(dep))
	}

	// A non-approved user's taps are refused.
	if ans := tapButton(r, 999, "m:list").CallbackAnswer; !strings.Contains(ans, "Not authorized") {
		t.Fatalf("unapproved tap should be refused, got %q", ans)
	}
}

func TestRouter_CredentialsScrubbed(t *testing.T) {
	r, store, _ := harness(t, 1)
	_ = store.Decide(2, StatusApproved)

	res := send(r, 2, "/cf my-secret-token acct-9")
	if !res.DeleteIncoming {
		t.Fatal("/cf must delete the incoming credential message")
	}
	tok, acct, ok := store.Creds(2)
	if !ok || tok != "my-secret-token" || acct != "acct-9" {
		t.Fatalf("creds not stored: %q %q %v", tok, acct, ok)
	}
}

func TestRouter_DeployAndConfigEditor(t *testing.T) {
	r, store, ops := harness(t, 1)
	_ = store.Decide(2, StatusApproved)
	_ = store.SetCreds(2, "tok", "acct")

	// Deploy with an explicit name.
	res := send(r, 2, "/deploy myedge")
	if !strings.Contains(firstText(res), "is live") || !strings.Contains(firstText(res), "myedge") {
		t.Fatalf("deploy reply: %q", firstText(res))
	}
	if _, ok := store.Deployment(2, "myedge"); !ok {
		t.Fatal("deployment not recorded")
	}

	// Add a clean IP (name omitted → the single worker is assumed).
	res = send(r, 2, "/addip 188.114.96.3")
	if !strings.Contains(firstText(res), "clean IPs 0 → 1") {
		t.Fatalf("addip reply: %q", firstText(res))
	}
	if got := asStringSlice(ops.config["myedge"]["cleanIPs"]); len(got) != 1 || got[0] != "188.114.96.3" {
		t.Fatalf("cleanIPs after add: %v", ops.config["myedge"]["cleanIPs"])
	}

	// A bad SNI is rejected by the (fake) worker and relayed verbatim.
	res = send(r, 2, "/sni bad")
	if !strings.Contains(firstText(res), "customCdnSni") {
		t.Fatalf("expected relayed validation error, got %q", firstText(res))
	}

	// A good SNI sticks.
	res = send(r, 2, "/sni www.digikala.com")
	if !strings.Contains(firstText(res), "www.digikala.com") {
		t.Fatalf("sni set reply: %q", firstText(res))
	}

	// A non-Cloudflare port is rejected before it ever reaches the worker.
	res = send(r, 2, "/ports 12345")
	if !strings.Contains(firstText(res), "not a Cloudflare-reachable port") {
		t.Fatalf("ports validation: %q", firstText(res))
	}

	// Fragment on with ranges.
	res = send(r, 2, "/fragment on 10-100 5-15")
	if !strings.Contains(firstText(res), "fragmentation on") {
		t.Fatalf("fragment reply: %q", firstText(res))
	}
	frag, _ := ops.config["myedge"]["fragment"].(map[string]any)
	if frag["enabled"] != true || frag["lengthMax"] != 100 {
		t.Fatalf("fragment not applied: %v", frag)
	}
}

func TestRouter_PerUserIsolationInRouter(t *testing.T) {
	r, store, _ := harness(t, 1)
	for _, id := range []int64{2, 3} {
		_ = store.Decide(id, StatusApproved)
		_ = store.SetCreds(id, "tok", "acct")
	}
	_ = send(r, 2, "/deploy alpha")
	_ = send(r, 3, "/deploy beta")

	// User 3 cannot target user 2's worker by name.
	res := send(r, 3, "/status alpha")
	// mustDeployment falls back to user 3's single worker "beta" since "alpha"
	// isn't theirs — the status is for beta, never alpha.
	if strings.Contains(firstText(res), "alpha") {
		t.Fatalf("user 3 must not see alpha: %q", firstText(res))
	}
}

func TestRouter_RequiresCredsBeforeDeploy(t *testing.T) {
	r, store, _ := harness(t, 1)
	_ = store.Decide(2, StatusApproved)
	res := send(r, 2, "/deploy")
	if !strings.Contains(firstText(res), "Cloudflare credentials first") {
		t.Fatalf("expected a creds prompt, got %q", firstText(res))
	}
}

func TestRouter_DestroyConfirmFlow(t *testing.T) {
	r, store, ops := harness(t, 1)
	_ = store.Decide(2, StatusApproved)
	_ = store.SetCreds(2, "tok", "acct")
	_ = send(r, 2, "/deploy gamma")

	ask := send(r, 2, "/destroy gamma")
	btn := hasOutTo(ask, 2)
	if btn == nil || len(btn.Buttons) == 0 || btn.Buttons[0][0].Data != "destroy:gamma" {
		t.Fatalf("destroy should ask for confirmation with a button: %+v", ask)
	}

	// Tap confirm.
	res := r.Handle(context.Background(), Incoming{
		UserID: 2, ChatID: 2, IsCallback: true, CallbackID: "c", CallbackData: "destroy:gamma",
	})
	if _, ok := ops.deployed["gamma"]; ok {
		t.Fatal("confirm did not destroy the worker")
	}
	if _, ok := store.Deployment(2, "gamma"); ok {
		t.Fatal("deployment not removed from store")
	}
	if !strings.Contains(res.CallbackAnswer, "Deleted") {
		t.Fatalf("callback answer: %q", res.CallbackAnswer)
	}
}
