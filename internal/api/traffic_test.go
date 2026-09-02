package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/store"
)

// Usage history over HTTP, and the scoping that keeps it from becoming a way to
// read another tenant's usage one key at a time.

func TestTrafficSeriesIsServed(t *testing.T) {
	s, token := adminAPI(t)
	u := &store.User{Username: "charted", SubToken: "ct"}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-2 * time.Hour)
	if _, _, err := s.db.ApplyTrafficDeltaAt(store.ScopeLocalEngine, "k", u.ID, 4096, 4096, store.TrafficSplit{}, at, nil); err != nil {
		t.Fatal(err)
	}

	code, body := doGET(t, s, "/api/admin/traffic/series?scope=user&key="+store.UserRollupKey(u.ID), token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res struct {
		Points []store.SeriesPoint `json:"points"`
		Total  int64               `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Total != 4096 {
		t.Fatalf("total is %d, want 4096", res.Total)
	}
	if len(res.Points) != 1 {
		t.Fatalf("got %d points, want 1", len(res.Points))
	}
}

// The question an operator asks first.
func TestTopConsumersIsServed(t *testing.T) {
	s, token := adminAPI(t)
	at := time.Now().Add(-time.Hour)
	for i, bytes := range []int64{50, 5000} {
		u := &store.User{Username: "top" + itoa(i), SubToken: "tk" + itoa(i)}
		if err := s.db.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.db.ApplyTrafficDeltaAt(store.ScopeLocalEngine, "k", u.ID, bytes, bytes, store.TrafficSplit{}, at, nil); err != nil {
			t.Fatal(err)
		}
	}
	code, body := doGET(t, s, "/api/admin/traffic/top?scope=user&limit=5", token)
	if code != 200 {
		t.Fatalf("%d: %s", code, body)
	}
	var res struct {
		Items []struct {
			Key   string `json:"key"`
			Bytes int64  `json:"bytes"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Items) < 2 || res.Items[0].Bytes != 5000 {
		t.Fatalf("not ranked by usage: %+v", res.Items)
	}
}

// A missing key must be refused rather than silently charted as an empty series
// that reads like "this user transferred nothing".
func TestSeriesRequiresAKey(t *testing.T) {
	s, token := adminAPI(t)
	code, _ := doGET(t, s, "/api/admin/traffic/series?scope=user", token)
	if code != 400 {
		t.Fatalf("a missing key returned %d, want 400", code)
	}
}

func TestSeriesRefusesAMalformedWindow(t *testing.T) {
	s, token := adminAPI(t)
	code, body := doGET(t, s, "/api/admin/traffic/series?scope=user&key=1&since=lastweek", token)
	if code != 400 {
		t.Fatalf("a malformed since returned %d, want 400: %s", code, body)
	}
}
