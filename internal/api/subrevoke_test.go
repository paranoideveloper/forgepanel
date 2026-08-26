package api

import (
	"strconv"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func TestRevokingASubscriptionEmptiesItWithoutTouchingCredentials(t *testing.T) {
	// sub_revoked_at was enforced end to end — a non-nil value makes
	// subscriptionNodes return an empty list and drops the user from the edge
	// feed — and NOTHING anywhere wrote it. The whole mechanism was unreachable.
	//
	// It is the one action that stops a leaked subscription URL WITHOUT
	// invalidating the credentials already imported into every client, which is
	// what rotating does.
	s, token := adminAPI(t)
	in, err := s.db.CreateInbound(&model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.30", Port: 443, Remark: "rv",
		UUID:      "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS},
		Security:  model.Security{Type: model.SecTLS},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "revokee", SubToken: "revoke-tok", Status: store.StatusActive,
		UUID: "11111111-2222-3333-4444-555555555555"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil); err != nil {
		t.Fatal(err)
	}
	beforeUUID := u.UUID

	if n := s.subscriptionNodes("revoke-tok", ""); len(n) == 0 {
		t.Fatal("precondition: the subscription is already empty")
	}

	rec := doJSON(t, s, "POST", "/api/admin/users/"+itoa(int(u.ID))+"/sub-revoked", token, `{"revoked":true}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if n := s.subscriptionNodes("revoke-tok", ""); len(n) != 0 {
		t.Fatalf("a revoked subscription still served %d config(s)", len(n))
	}

	after, _ := s.db.UserByID(u.ID)
	if after.UUID != beforeUUID {
		t.Fatal("revoking rotated the credentials; that is what rotate is for")
	}
	if after.SubToken != "revoke-tok" {
		t.Fatal("revoking changed the sub token")
	}

	// And it must be reversible: a revocation that cannot be undone is a
	// deletion with extra steps.
	rec = doJSON(t, s, "POST", "/api/admin/users/"+itoa(int(u.ID))+"/sub-revoked", token, `{"revoked":false}`)
	if rec.Code != 200 {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if n := s.subscriptionNodes("revoke-tok", ""); len(n) == 0 {
		t.Fatal("a restored subscription is still empty")
	}
}

func TestCreateUserAcceptsASubGigabyteLimit(t *testing.T) {
	// data_limit_gb is an int64 of whole gigabytes, so a 500 MB trial arrived as
	// 0 — and 0 means UNLIMITED, the exact opposite of the intent. Discovered
	// only once the account has moved a hundred gigabytes.
	s, token := adminAPI(t)
	half := int64(512 * 1024 * 1024)
	rec := doJSON(t, s, "POST", "/api/admin/users", token,
		`{"username":"trial","data_limit":`+strconv.FormatInt(half, 10)+`}`)
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	u := findUserByName(t, s, "trial")
	if u.DataLimit != half {
		t.Fatalf("data limit = %d, want %d — 0 here would mean unlimited", u.DataLimit, half)
	}
	// The old whole-gigabyte field must keep working for existing callers.
	rec = doJSON(t, s, "POST", "/api/admin/users", token, `{"username":"legacy","data_limit_gb":5}`)
	if rec.Code != 200 && rec.Code != 201 {
		t.Fatalf("legacy field: %d %s", rec.Code, rec.Body.String())
	}
	l := findUserByName(t, s, "legacy")
	if l.DataLimit != 5*1024*1024*1024 {
		t.Fatalf("legacy data limit = %d", l.DataLimit)
	}
	_ = strings.TrimSpace("")
}

// findUserByName looks a user up through the store's list, which is the only
// public path the API package has.
func findUserByName(t *testing.T, s *Server, name string) *store.User {
	t.Helper()
	users, err := s.db.ListUsers(0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range users {
		if users[i].Username == name {
			return &users[i]
		}
	}
	t.Fatalf("no user named %q", name)
	return nil
}
