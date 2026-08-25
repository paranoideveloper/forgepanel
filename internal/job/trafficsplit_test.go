package job

import (
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// The engine reports uplink and downlink SEPARATELY and the API layer summed
// them before anything could see the two halves. The panel then held one number,
// so every subscription reported "upload=0" and put the whole total under
// download — a figure every client displays verbatim.

func TestUplinkAndDownlinkAreRecordedSeparately(t *testing.T) {
	db := ipTestStore(t)
	u := &store.User{Username: "split", SubToken: "split", Status: store.StatusActive}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	email := UserEmail(u.ID)

	obs := map[string]store.TrafficSplit{email: {Up: 300, Down: 700}}
	s := New(Config{DB: db, PollTraffic: func(bool) (map[string]store.TrafficSplit, error) {
		return obs, nil
	}})
	s.pollAndAccount()

	got, err := db.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The billed total is unchanged: still the combined counter.
	if got.UsedTraffic != 1000 {
		t.Fatalf("used = %d, want 1000 — the billed total must not change", got.UsedTraffic)
	}
	if got.UploadTraffic != 300 || got.DownloadTraffic != 700 {
		t.Fatalf("split = %d up / %d down, want 300/700", got.UploadTraffic, got.DownloadTraffic)
	}

	// A second cumulative observation must bill and attribute only the DELTA.
	// Half-baselines that do not advance would count the same bytes again.
	obs[email] = store.TrafficSplit{Up: 500, Down: 1100}
	s.pollAndAccount()
	got, _ = db.UserByID(u.ID)
	if got.UsedTraffic != 1600 {
		t.Fatalf("used = %d, want 1600", got.UsedTraffic)
	}
	if got.UploadTraffic != 500 || got.DownloadTraffic != 1100 {
		t.Fatalf("split = %d/%d after the second poll, want 500/1100 — the half baselines did not advance",
			got.UploadTraffic, got.DownloadTraffic)
	}
}

func TestASourceWithNoSplitStillBills(t *testing.T) {
	db := ipTestStore(t)
	u := &store.User{Username: "nosplit", SubToken: "nosplit", Status: store.StatusActive}
	if err := db.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	// A remote node reports one combined counter and no split at all.
	if _, _, err := db.ApplyTrafficDeltaAt(store.NodeScope(4), "u", u.ID, 900, 900,
		store.TrafficSplit{}, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	got, _ := db.UserByID(u.ID)
	// Billed in full...
	if got.UsedTraffic != 900 {
		t.Fatalf("used = %d, want 900 — unattributable traffic must still be billed", got.UsedTraffic)
	}
	// ...and attributed to NEITHER half. Inventing a split would make a guessed
	// number indistinguishable from a measured one.
	if got.UploadTraffic != 0 || got.DownloadTraffic != 0 {
		t.Fatalf("split = %d/%d, want 0/0 for a source that reported none",
			got.UploadTraffic, got.DownloadTraffic)
	}
}
