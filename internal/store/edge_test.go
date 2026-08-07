package store

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func edgeStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEdgeDeployment_RoundTrip(t *testing.T) {
	s := edgeStore(t)

	d := &EdgeDeployment{
		Name:       "forgeedge-a1b2c3",
		Origin:     "https://forgeedge-a1b2c3.acme.workers.dev/",
		SecurePath: "/qrs7tuvwxy23456789abcdef/",
		PushToken:  "push-token-123",
		AccountID:  "acct-1",
	}
	if err := s.CreateEdgeDeployment(d); err != nil {
		t.Fatalf("CreateEdgeDeployment: %v", err)
	}
	if d.ID == 0 {
		t.Fatal("expected an assigned id")
	}
	if d.Target != "workers" {
		t.Errorf("target should default to workers, got %q", d.Target)
	}
	if d.Origin != "https://forgeedge-a1b2c3.acme.workers.dev" {
		t.Errorf("trailing slash not trimmed: %q", d.Origin)
	}
	if d.SecurePath != "qrs7tuvwxy23456789abcdef" {
		t.Errorf("secure path not trimmed: %q", d.SecurePath)
	}

	got, err := s.EdgeDeploymentByID(d.ID)
	if err != nil {
		t.Fatalf("EdgeDeploymentByID: %v", err)
	}
	if got.PushToken != "push-token-123" {
		t.Errorf("push token did not survive the round trip: %q", got.PushToken)
	}
	byName, err := s.EdgeDeploymentByName("forgeedge-a1b2c3")
	if err != nil || byName.ID != d.ID {
		t.Fatalf("EdgeDeploymentByName: %v (id %v)", err, byName)
	}

	wantFeed := "https://forgeedge-a1b2c3.acme.workers.dev/qrs7tuvwxy23456789abcdef/feed"
	if got.FeedURL() != wantFeed {
		t.Errorf("FeedURL = %q, want %q", got.FeedURL(), wantFeed)
	}
	wantStatus := "https://forgeedge-a1b2c3.acme.workers.dev/qrs7tuvwxy23456789abcdef/api/status"
	if got.StatusURL() != wantStatus {
		t.Errorf("StatusURL = %q, want %q", got.StatusURL(), wantStatus)
	}

	list, err := s.ListEdgeDeployments()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListEdgeDeployments: %v (%d rows)", err, len(list))
	}

	at := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	if err := s.UpdateEdgePushStatus(d.ID, at, "ok: 14 user(s)"); err != nil {
		t.Fatalf("UpdateEdgePushStatus: %v", err)
	}
	got, _ = s.EdgeDeploymentByID(d.ID)
	if got.LastStatus != "ok: 14 user(s)" {
		t.Errorf("LastStatus = %q", got.LastStatus)
	}
	if got.LastPushAt == nil || !got.LastPushAt.UTC().Equal(at) {
		t.Errorf("LastPushAt = %v, want %v", got.LastPushAt, at)
	}

	got.SecurePath = "rotatedpath23456789abcde"
	if err := s.SaveEdgeDeployment(got); err != nil {
		t.Fatalf("SaveEdgeDeployment: %v", err)
	}
	again, _ := s.EdgeDeploymentByID(d.ID)
	if again.SecurePath != "rotatedpath23456789abcde" {
		t.Errorf("rotated path not persisted: %q", again.SecurePath)
	}

	if err := s.DeleteEdgeDeployment(d.ID); err != nil {
		t.Fatalf("DeleteEdgeDeployment: %v", err)
	}
	if _, err := s.EdgeDeploymentByID(d.ID); err == nil {
		t.Error("expected the row to be gone")
	}
}

func TestEdgeDeployment_DeleteMissingIsNotFound(t *testing.T) {
	s := edgeStore(t)
	err := s.DeleteEdgeDeployment(4242)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestEdgeDeployment_RejectsBadInput(t *testing.T) {
	s := edgeStore(t)
	cases := []struct {
		name string
		in   EdgeDeployment
	}{
		{"no name", EdgeDeployment{Origin: "https://x.workers.dev"}},
		{"no origin", EdgeDeployment{Name: "x"}},
		{"relative origin", EdgeDeployment{Name: "x", Origin: "x.workers.dev"}},
		{"wrong scheme", EdgeDeployment{Name: "x", Origin: "ftp://x.workers.dev"}},
		{"scheme only", EdgeDeployment{Name: "x", Origin: "https://"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.in
			if err := s.CreateEdgeDeployment(&d); err == nil {
				t.Fatalf("expected a rejection for %+v", tc.in)
			}
		})
	}
}

func TestEdgeDeployment_NameIsUnique(t *testing.T) {
	s := edgeStore(t)
	first := &EdgeDeployment{Name: "dup", Origin: "https://a.workers.dev"}
	if err := s.CreateEdgeDeployment(first); err != nil {
		t.Fatalf("first create: %v", err)
	}
	second := &EdgeDeployment{Name: "dup", Origin: "https://b.workers.dev"}
	if err := s.CreateEdgeDeployment(second); err == nil {
		t.Fatal("a duplicate name must be refused; two rows for one Worker means one of them is fed a stale path")
	}
}

func TestEdgeDeployment_IsMigrated(t *testing.T) {
	s := edgeStore(t)
	if !s.DB().Migrator().HasTable(&EdgeDeployment{}) {
		t.Fatal("edge_deployments is missing from the migration set")
	}
}
