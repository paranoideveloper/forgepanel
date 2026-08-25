package store

import (
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// An import runs once, against a panel the operator has not used before, with
// data they cannot easily reconstruct. A half-finished one is the worst outcome:
// some users exist and some do not, nobody knows which, and running it again
// duplicates the half that landed.

func node(t *testing.T, remark string, port int) *model.Node {
	t.Helper()
	n := &model.Node{Protocol: model.ProtoVLESS, Address: "0.0.0.0", Port: port,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: remark}
	n.Normalize()
	return n
}

func TestAFailedImportLeavesNothingBehind(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// The second inbound's second user duplicates the first user's name, which
	// the unique index refuses — a realistic mid-import failure.
	items := []ImportInbound{
		{Node: node(t, "first", 1001), Users: []ImportUser{
			{Username: "alice", UUID: "u1", SubToken: "t1"},
		}},
		{Node: node(t, "second", 1002), Users: []ImportUser{
			{Username: "bob", UUID: "u2", SubToken: "t2"},
			{Username: "alice", UUID: "u3", SubToken: "t3"}, // collides
		}},
	}
	if _, err := db.ApplyImport(items); err == nil {
		t.Fatal("a colliding username was accepted")
	}

	// EVERYTHING must be gone — including the first inbound and the first user,
	// which succeeded before the failure. Anything left behind is state the
	// operator does not know about and will duplicate on the retry.
	ins, _ := db.ListInbounds()
	if len(ins) != 0 {
		t.Fatalf("%d inbound(s) survived a rolled-back import", len(ins))
	}
	users, _ := db.ListUsers(0)
	if len(users) != 0 {
		t.Fatalf("%d user(s) survived a rolled-back import", len(users))
	}
}

func TestASuccessfulImportReportsWhatLanded(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	out, err := db.ApplyImport([]ImportInbound{
		{Node: node(t, "a", 2001), Users: []ImportUser{
			{Username: "x", UUID: "u1", SubToken: "t1"},
			{Username: "y", UUID: "u2", SubToken: "t2"},
		}},
		{Node: node(t, "b", 2002), Users: []ImportUser{
			{Username: "z", UUID: "u3", SubToken: "t3"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Inbounds != 2 || out.Users != 3 {
		t.Fatalf("outcome = %+v, want 2 inbounds and 3 users", out)
	}
	// The ids let a caller reload exactly what changed rather than everything.
	if len(out.InboundIDs) != 2 {
		t.Fatalf("inbound ids = %v", out.InboundIDs)
	}
	// Every user is attached to its inbound. An account with no inbound exists,
	// looks correct, and serves nobody.
	for _, u := range mustUsers(t, db) {
		a, err := db.UserAssignments(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Direct) == 0 {
			t.Fatalf("%s has no inbound assignment", u.Username)
		}
	}
}

func mustUsers(t *testing.T, db *Store) []User {
	t.Helper()
	u, err := db.ListUsers(0)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
