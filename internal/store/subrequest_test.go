package store

import (
	"testing"
	"time"
)

// TestRecordSubRequestStampsUserAndSelfBounds covers the two things about this
// write that are easy to get wrong and impossible to see from the outside: it
// must not disturb users.updated_at, and it must bound its own table.
func TestRecordSubRequestStampsUserAndSelfBounds(t *testing.T) {
	s := testStore(t)
	u := &User{Username: "tele", SubToken: "teletok123456",
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Status: StatusActive}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	before, err := s.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}

	when := time.Now().UTC().Truncate(time.Second)
	if err := s.RecordSubRequest(&SubRequest{
		UserID: u.ID, CreatedAt: when, Format: "sing-box",
		UserAgent: "sing-box 1.9.0", IP: "203.0.113.9",
	}); err != nil {
		t.Fatalf("RecordSubRequest: %v", err)
	}

	after, err := s.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SubUpdatedAt == nil || !after.SubUpdatedAt.UTC().Equal(when) {
		t.Fatalf("sub_updated_at = %v, want %v", after.SubUpdatedAt, when)
	}
	if after.SubLastUA != "sing-box 1.9.0" {
		t.Fatalf("sub_last_ua = %q, want %q", after.SubLastUA, "sing-box 1.9.0")
	}
	// users.updated_at is the optimistic-concurrency token the edit form sends
	// back as ifUnchanged. If a subscription fetch bumped it, an operator with
	// the form open would be told someone else edited the user when nobody did.
	if !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("updated_at moved from %v to %v: use UpdateColumns, not Updates",
			before.UpdatedAt, after.UpdatedAt)
	}

	// /sub/:token is unauthenticated, so the history must bound itself from the
	// write side rather than trusting a scheduled prune to keep up.
	base := when.Add(time.Minute)
	for i := 0; i < 120; i++ {
		if err := s.RecordSubRequest(&SubRequest{
			UserID: u.ID, CreatedAt: base.Add(time.Duration(i) * time.Second),
			Format: "v2ray", UserAgent: "v2rayNG/1.8.1", IP: "203.0.113.9",
		}); err != nil {
			t.Fatalf("RecordSubRequest %d: %v", i, err)
		}
	}
	items, total, err := s.ListSubRequests(u.ID, 500, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 || len(items) != 100 {
		t.Fatalf("kept %d rows (total %d), want 100", len(items), total)
	}
	// Newest first, and the oldest survivor is row 20 of the 120 — the trim drops
	// the OLDEST, not whatever the driver happened to return first.
	wantNewest := base.Add(119 * time.Second)
	wantOldest := base.Add(20 * time.Second)
	if !items[0].CreatedAt.UTC().Equal(wantNewest) {
		t.Fatalf("newest kept row is %v, want %v", items[0].CreatedAt.UTC(), wantNewest)
	}
	if !items[99].CreatedAt.UTC().Equal(wantOldest) {
		t.Fatalf("oldest kept row is %v, want %v", items[99].CreatedAt.UTC(), wantOldest)
	}
}
