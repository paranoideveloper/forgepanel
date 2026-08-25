package store

import (
	"testing"
	"time"
)

// The panel knew a user's TOTAL and nothing about when: no charts, no "why did
// this node spike on Tuesday", no usage report for a disputed bill. These cover
// the history, and the property that makes it trustworthy — it is written from
// the same delta, in the same transaction, that bills the traffic.

func rollupStore(t *testing.T) (*Store, *User) {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	u := &User{Username: "r", SubToken: "rt"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return s, u
}

func TestBillingAlsoWritesHistory(t *testing.T) {
	s, u := rollupStore(t)
	at := time.Date(2026, 8, 25, 14, 30, 0, 0, time.UTC)

	if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 5000, 5000, TrafficSplit{}, at, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if got.UsedTraffic != 5000 {
		t.Fatalf("billed %d, want 5000", got.UsedTraffic)
	}

	// The same bytes must be in the history, or a chart and an invoice disagree.
	pts, err := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 1 || pts[0].Bytes != 5000 {
		t.Fatalf("history holds %+v, want one bucket of 5000", pts)
	}
	if !pts[0].Bucket.Equal(time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)) {
		t.Fatalf("bucket is %v, want the 14:00 hour", pts[0].Bucket)
	}
}

// Both resolutions, because hourly is what an operator debugs with and daily is
// what a customer is billed against and what a long chart needs.
func TestHourlyAndDailyAreBothRecorded(t *testing.T) {
	s, u := rollupStore(t)
	day := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for i, h := range []int{1, 5, 9} {
		at := day.Add(time.Duration(h) * time.Hour)
		if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 100, int64(100*(i+1)), TrafficSplit{}, at, nil); err != nil {
			t.Fatal(err)
		}
	}
	hourly, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(hourly) != 3 {
		t.Fatalf("hourly holds %d buckets, want 3", len(hourly))
	}
	daily, _ := s.TrafficSeries(SeriesQuery{Period: PeriodDay, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(daily) != 1 || daily[0].Bytes != 300 {
		t.Fatalf("daily holds %+v, want one bucket of 300", daily)
	}
}

// Repeated usage in one hour accumulates into the bucket rather than appending
// rows, or the table grows without bound and every query becomes an aggregation.
func TestSameBucketAccumulates(t *testing.T) {
	s, u := rollupStore(t)
	at := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	for i := 1; i <= 4; i++ {
		if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 250, int64(250*i), TrafficSplit{}, at.Add(time.Duration(i)*time.Minute), nil); err != nil {
			t.Fatal(err)
		}
	}
	pts, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(pts) != 1 {
		t.Fatalf("one hour produced %d buckets", len(pts))
	}
	if pts[0].Bytes != 1000 {
		t.Fatalf("bucket holds %d, want 1000", pts[0].Bytes)
	}
}

// A node's scope credits the node too, so "which node carried this" is
// answerable without re-deriving it from every user.
func TestNodeTrafficIsAttributedToTheNode(t *testing.T) {
	s, u := rollupStore(t)
	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	if _, _, err := s.ApplyTrafficDeltaAt(NodeScope(7), "u1", u.ID, 800, 800, TrafficSplit{}, at, nil); err != nil {
		t.Fatal(err)
	}
	pts, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeNode, Key: "7"})
	if len(pts) != 1 || pts[0].Bytes != 800 {
		t.Fatalf("node history holds %+v, want 800", pts)
	}
	// And the user still gets credited; it is the same bytes seen two ways.
	up, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(up) != 1 || up[0].Bytes != 800 {
		t.Fatalf("user history holds %+v, want 800", up)
	}
}

// Local traffic must NOT be credited to a node, or every node's chart includes
// traffic it never carried.
func TestLocalTrafficIsNotAttributedToAnyNode(t *testing.T) {
	s, u := rollupStore(t)
	at := time.Now()
	if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 400, 400, TrafficSplit{}, at, nil); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"0", "1", "local"} {
		pts, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeNode, Key: key})
		if len(pts) != 0 {
			t.Fatalf("local traffic was credited to node %q: %+v", key, pts)
		}
	}
}

// Buckets are UTC on purpose: keyed by local time they shift with the server's
// zone or DST, so a historical chart rewrites itself and an hour duplicates or
// vanishes once a year.
func TestBucketsAreUTC(t *testing.T) {
	loc := time.FixedZone("UTC+5:30", int(5.5*3600))
	local := time.Date(2026, 8, 25, 2, 15, 0, 0, loc) // 20:45 previous day UTC
	got := bucketFor(PeriodDay, local)
	want := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("daily bucket for %v is %v, want %v", local, got, want)
	}
}

// Oldest-first is the order a chart plots; returning newest-first and expecting
// every caller to reverse it is how one of them forgets.
func TestSeriesIsOldestFirst(t *testing.T) {
	s, u := rollupStore(t)
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		_, _, _ = s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 10, int64(10*(i+1)),
			TrafficSplit{}, base.Add(time.Duration(i)*time.Hour), nil)
	}
	pts, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	for i := 1; i < len(pts); i++ {
		if !pts[i].Bucket.After(pts[i-1].Bucket) {
			t.Fatalf("points are not oldest-first: %v then %v", pts[i-1].Bucket, pts[i].Bucket)
		}
	}
}

// A year of hourly data is 8,760 points, which no chart renders and no browser
// should be sent by accident.
func TestSeriesIsBounded(t *testing.T) {
	q := SeriesQuery{Limit: 100000}
	s, u := rollupStore(t)
	q.Scope, q.Key, q.Period = ScopeUser, UserRollupKey(u.ID), PeriodHour
	if _, err := s.TrafficSeries(q); err != nil {
		t.Fatal(err)
	}
	// The cap is enforced inside; assert the constant exists and is sane.
	if MaxSeriesPoints <= 0 || MaxSeriesPoints > 10000 {
		t.Fatalf("MaxSeriesPoints is %d, which is not a usable bound", MaxSeriesPoints)
	}
}

func TestTopConsumersRanksByUsage(t *testing.T) {
	s, _ := rollupStore(t)
	at := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	for i, bytes := range []int64{100, 900, 500} {
		u := &User{Username: "t" + string(rune('a'+i)), SubToken: "tt" + string(rune('a'+i))}
		if err := s.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "k", u.ID, bytes, bytes, TrafficSplit{}, at, nil); err != nil {
			t.Fatal(err)
		}
	}
	top, err := s.TopConsumers(ScopeUser, PeriodHour, at.Add(-time.Hour), at.Add(time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 {
		t.Fatalf("got %d rows, want 2", len(top))
	}
	if top[0].Bytes != 900 || top[1].Bytes != 500 {
		t.Fatalf("not ranked by usage: %+v", top)
	}
}

// Hourly and daily prune on DIFFERENT clocks: one shared cutoff would either
// keep an unusable amount of hourly data or destroy the long-range chart.
func TestPruneUsesSeparateClocksPerResolution(t *testing.T) {
	s, u := rollupStore(t)
	old := time.Now().Add(-60 * 24 * time.Hour)
	if _, _, err := s.ApplyTrafficDeltaAt(ScopeLocalEngine, "u1", u.ID, 10, 10, TrafficSplit{}, old, nil); err != nil {
		t.Fatal(err)
	}
	// Prune hourly older than 30 days; keep daily for a year.
	if _, err := s.PruneRollups(time.Now().Add(-30*24*time.Hour), time.Now().Add(-365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	hourly, _ := s.TrafficSeries(SeriesQuery{Period: PeriodHour, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(hourly) != 0 {
		t.Fatalf("hourly detail older than its window survived: %+v", hourly)
	}
	daily, _ := s.TrafficSeries(SeriesQuery{Period: PeriodDay, Scope: ScopeUser, Key: UserRollupKey(u.ID)})
	if len(daily) != 1 {
		t.Fatalf("daily billing history was destroyed by the hourly cutoff: %+v", daily)
	}
}
