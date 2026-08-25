package api

import (
	"encoding/json"
	"testing"

	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/core/online"
	"github.com/forgepanel/forgepanel/internal/job"
	"github.com/forgepanel/forgepanel/internal/store"
)

// Presence over HTTP: the engine-side identity has to come back as a person, and
// a reseller must not learn the connection addresses of users who are not theirs.

type onlineResponse struct {
	Users []struct {
		UserID    uint   `json:"user_id"`
		Username  string `json:"username"`
		Addresses int    `json:"addresses"`
		Sessions  []struct {
			IP      string `json:"ip"`
			Inbound string `json:"inbound"`
			Node    string `json:"node"`
		} `json:"sessions"`
	} `json:"users"`
	TTLSeconds int `json:"ttl_seconds"`
}

func TestOnlineNamesUsersRatherThanCounterKeys(t *testing.T) {
	s, token := adminAPI(t)
	u := &store.User{Username: "present", SubToken: "pt"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	// Feed the tracker the way a real core would: through the log-line hook,
	// with a line captured from a live Xray rather than one written by hand.
	s.engine.ObservePresenceLine(core.LocalNodeName,
		`2026/08/25 17:58:56.880563 from 203.0.113.7:64792 accepted tcp:example.com:443 [in-1 >> direct] email: `+
			job.UserEmail(u.ID))

	code, body := doGET(t, s, "/api/admin/online", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res onlineResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 1 {
		t.Fatalf("online users = %d, want 1: %s", len(res.Users), body)
	}
	got := res.Users[0]
	// The whole point of this layer: an operator reads names, not "u.7".
	if got.Username != "present" {
		t.Errorf("username = %q, want present", got.Username)
	}
	if got.UserID != u.ID {
		t.Errorf("user id = %d, want %d", got.UserID, u.ID)
	}
	if got.Addresses != 1 || len(got.Sessions) != 1 {
		t.Fatalf("sessions = %+v, want one", got.Sessions)
	}
	if got.Sessions[0].IP != "203.0.113.7" {
		t.Errorf("source IP = %q, want 203.0.113.7", got.Sessions[0].IP)
	}
	if got.Sessions[0].Inbound != "in-1" {
		t.Errorf("inbound = %q, want in-1", got.Sessions[0].Inbound)
	}
	if got.Sessions[0].Node != core.LocalNodeName {
		t.Errorf("node = %q, want %q", got.Sessions[0].Node, core.LocalNodeName)
	}
	// Without the window, a reader cannot tell whether an absent user
	// disconnected or merely went quiet.
	if res.TTLSeconds != int(online.DefaultTTL.Seconds()) {
		t.Errorf("ttl_seconds = %d, want %d", res.TTLSeconds, int(online.DefaultTTL.Seconds()))
	}
}

func TestOnlineIsScopedToAResellersOwnUsers(t *testing.T) {
	s, _ := adminAPI(t)

	reseller := &store.Admin{Username: "rs", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 10}
	if err := s.db.CreateAdmin(reseller); err != nil {
		t.Fatal(err)
	}
	mine := &store.User{Username: "mine", SubToken: "m1", OwnerAdminID: reseller.ID}
	theirs := &store.User{Username: "theirs", SubToken: "t1"}
	if err := s.db.CreateUser(mine); err != nil {
		t.Fatal(err)
	}
	if err := s.db.CreateUser(theirs); err != nil {
		t.Fatal(err)
	}

	for _, u := range []*store.User{mine, theirs} {
		s.engine.ObservePresenceLine(core.LocalNodeName,
			`x from 198.51.100.4:1 accepted tcp:a.b:443 [in >> direct] email: `+job.UserEmail(u.ID))
	}

	rtoken, _, err := s.signer.Issue(reseller.ID, reseller.Username, string(store.RoleReseller))
	if err != nil {
		t.Fatal(err)
	}
	code, body := doGET(t, s, "/api/admin/online", rtoken)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res onlineResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	// Source addresses are the most sensitive thing in the panel. A reseller
	// seeing another tenant's is a privacy breach, not a cosmetic leak.
	for _, row := range res.Users {
		if row.Username == "theirs" || row.UserID == theirs.ID {
			t.Fatalf("a reseller was shown another tenant's connections: %s", body)
		}
	}
	if len(res.Users) != 1 || res.Users[0].Username != "mine" {
		t.Fatalf("reseller should see exactly their own user, got %s", body)
	}
}

func TestOnlineHidesUnattributedSessionsFromResellers(t *testing.T) {
	s, token := adminAPI(t)
	reseller := &store.Admin{Username: "rs2", PasswordHash: "x", Role: store.RoleReseller, UserQuota: 10}
	if err := s.db.CreateAdmin(reseller); err != nil {
		t.Fatal(err)
	}

	// An identity the panel never issued: a hand-configured inbound, or an
	// import. It belongs to no user, so it cannot be scoped to a tenant.
	s.engine.ObservePresenceLine(core.LocalNodeName,
		`x from 198.51.100.9:1 accepted tcp:a.b:443 [in >> direct] email: handmade@example`)

	rtoken, _, err := s.signer.Issue(reseller.ID, reseller.Username, string(store.RoleReseller))
	if err != nil {
		t.Fatal(err)
	}
	_, body := doGET(t, s, "/api/admin/online", rtoken)
	var res onlineResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 0 {
		t.Fatalf("a reseller was shown an unattributable session: %s", body)
	}

	// The owner still sees it — it is real traffic, and hiding it from everyone
	// would make a hand-configured inbound invisible.
	_, obody := doGET(t, s, "/api/admin/online", token)
	var ores onlineResponse
	if err := json.Unmarshal([]byte(obody), &ores); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range ores.Users {
		if row.Username == "handmade@example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the owner should see an unattributed session, showing its raw tag: %s", obody)
	}
}

func TestOnlineRequiresAuth(t *testing.T) {
	s, _ := adminAPI(t)
	if code, _ := doGET(t, s, "/api/admin/online", ""); code != 401 {
		t.Fatalf("unauthenticated presence request returned %d, want 401 — source addresses are not public", code)
	}
}
