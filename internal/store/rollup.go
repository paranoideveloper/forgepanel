package store

// Usage history.
//
// The panel knew how much traffic a user had used in total and nothing about
// WHEN. No history means no charts, no "why did this node spike on Tuesday", no
// usage report for a customer disputing a bill, and no way to see a quota being
// consumed before it runs out. A single cumulative number answers none of it.
//
// WHERE THE NUMBERS COME FROM. Rollups are written in the SAME transaction that
// bills the traffic, from the same delta. They are not re-derived from anything
// afterwards, so the chart and the invoice cannot disagree — and a crash cannot
// bill traffic that never lands in the history, or chart traffic that was never
// billed.
//
// TWO RESOLUTIONS. Hourly is what an operator debugs with; daily is what a
// customer is billed against and what a year-long chart needs. Keeping only
// hourly and summing it would work until retention deleted the hours, at which
// point the long-range chart would silently lose its past.

import (
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// Rollup periods.
const (
	PeriodHour = "hour"
	PeriodDay  = "day"
)

// Rollup scopes. A user's traffic is also a node's traffic and an inbound's
// traffic, so the same delta lands in several rows under different scopes.
const (
	ScopeUser    = "user"
	ScopeNode    = "node"
	ScopeInbound = "inbound"
)

// TrafficRollup is bytes used within one time bucket, for one thing.
//
// The composite key is (period, scope, key, bucket): one row per bucket per
// subject, incremented in place. Appending a row per observation instead would
// grow without bound and make every query an aggregation.
type TrafficRollup struct {
	Period string    `gorm:"primaryKey;size:8" json:"period"`
	Scope  string    `gorm:"primaryKey;size:16" json:"scope"`
	Key    string    `gorm:"primaryKey;size:128" json:"key"`
	Bucket time.Time `gorm:"primaryKey;index" json:"bucket"`
	Bytes  int64     `json:"bytes"`
}

func (TrafficRollup) TableName() string { return "traffic_rollups" }

// bucketFor truncates a time to the start of its period, in UTC.
//
// UTC deliberately: buckets keyed by local time shift when the server's zone or
// DST changes, which makes a historical chart rewrite itself and an hour
// duplicate or vanish once a year.
func bucketFor(period string, t time.Time) time.Time {
	t = t.UTC()
	if period == PeriodDay {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	return t.Truncate(time.Hour)
}

// addRollup increments one bucket inside an existing transaction.
func addRollup(tx *gorm.DB, period, scope, key string, at time.Time, delta int64) error {
	if delta <= 0 || key == "" {
		return nil
	}
	row := TrafficRollup{Period: period, Scope: scope, Key: key, Bucket: bucketFor(period, at)}
	// An atomic increment, so two pollers crediting the same bucket cannot lose
	// one another's bytes to a read-modify-write race.
	res := tx.Model(&TrafficRollup{}).
		Where("period = ? AND scope = ? AND key = ? AND bucket = ?", row.Period, row.Scope, row.Key, row.Bucket).
		UpdateColumn("bytes", gorm.Expr("bytes + ?", delta))
	if res.Error != nil {
		return fmt.Errorf("increment rollup %s/%s/%s: %w", period, scope, key, res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	row.Bytes = delta
	if err := tx.Create(&row).Error; err != nil {
		// A concurrent creator won the race; fold into their row instead of
		// failing the whole accounting transaction over a duplicate key.
		res := tx.Model(&TrafficRollup{}).
			Where("period = ? AND scope = ? AND key = ? AND bucket = ?", row.Period, row.Scope, row.Key, row.Bucket).
			UpdateColumn("bytes", gorm.Expr("bytes + ?", delta))
		if res.Error != nil || res.RowsAffected == 0 {
			return fmt.Errorf("create rollup %s/%s/%s: %w", period, scope, key, err)
		}
	}
	return nil
}

// RecordUsage writes both resolutions for one subject, inside a transaction.
func recordUsage(tx *gorm.DB, scope, key string, at time.Time, delta int64) error {
	if err := addRollup(tx, PeriodHour, scope, key, at, delta); err != nil {
		return err
	}
	return addRollup(tx, PeriodDay, scope, key, at, delta)
}

// SeriesPoint is one bucket in a returned series.
type SeriesPoint struct {
	Bucket time.Time `json:"bucket"`
	Bytes  int64     `json:"bytes"`
}

// SeriesQuery selects a slice of history.
type SeriesQuery struct {
	Period string
	Scope  string
	Key    string
	Since  time.Time
	Until  time.Time
	// Limit caps the returned points. A year of hourly data is 8,760 points,
	// which no chart can render and no browser should be sent by accident.
	Limit int
}

// MaxSeriesPoints bounds one series response.
const MaxSeriesPoints = 2000

// TrafficSeries returns usage over time for one subject, oldest first.
//
// Oldest-first because that is the order a chart plots; returning newest-first
// and expecting every caller to reverse it is how one of them forgets.
func (s *Store) TrafficSeries(q SeriesQuery) ([]SeriesPoint, error) {
	if q.Period != PeriodDay {
		q.Period = PeriodHour
	}
	if q.Limit <= 0 || q.Limit > MaxSeriesPoints {
		q.Limit = MaxSeriesPoints
	}
	db := s.db.Model(&TrafficRollup{}).
		Where("period = ? AND scope = ? AND key = ?", q.Period, q.Scope, q.Key)
	if !q.Since.IsZero() {
		db = db.Where("bucket >= ?", bucketFor(q.Period, q.Since))
	}
	if !q.Until.IsZero() {
		db = db.Where("bucket < ?", q.Until.UTC())
	}
	var out []SeriesPoint
	if err := db.Order("bucket asc").Limit(q.Limit).
		Select("bucket", "bytes").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("read traffic series: %w", err)
	}
	return out, nil
}

// TopConsumers returns the heaviest subjects in a window.
//
// This is the question an operator actually asks first — "who is using it all" —
// and answering it by fetching every series and sorting client-side would send
// the whole table to the browser.
func (s *Store) TopConsumers(scope, period string, since, until time.Time, limit int) ([]struct {
	Key   string `json:"key"`
	Bytes int64  `json:"bytes"`
}, error) {
	if period != PeriodDay {
		period = PeriodHour
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	var out []struct {
		Key   string `json:"key"`
		Bytes int64  `json:"bytes"`
	}
	db := s.db.Model(&TrafficRollup{}).
		Select("key, SUM(bytes) as bytes").
		Where("period = ? AND scope = ?", period, scope)
	if !since.IsZero() {
		db = db.Where("bucket >= ?", bucketFor(period, since))
	}
	if !until.IsZero() {
		db = db.Where("bucket < ?", until.UTC())
	}
	if err := db.Group("key").Order("bytes desc").Limit(limit).Find(&out).Error; err != nil {
		return nil, fmt.Errorf("read top consumers: %w", err)
	}
	return out, nil
}

// PruneRollups drops buckets older than the cutoffs.
//
// Hourly and daily are pruned on DIFFERENT clocks on purpose: hourly is debug
// detail worth weeks, daily is billing history worth years. One shared cutoff
// would either keep an unusable amount of hourly data or destroy the long-range
// chart.
func (s *Store) PruneRollups(hourlyBefore, dailyBefore time.Time) (int64, error) {
	var total int64
	if !hourlyBefore.IsZero() {
		res := s.db.Where("period = ? AND bucket < ?", PeriodHour, hourlyBefore.UTC()).Delete(&TrafficRollup{})
		if res.Error != nil {
			return total, fmt.Errorf("prune hourly rollups: %w", res.Error)
		}
		total += res.RowsAffected
	}
	if !dailyBefore.IsZero() {
		res := s.db.Where("period = ? AND bucket < ?", PeriodDay, dailyBefore.UTC()).Delete(&TrafficRollup{})
		if res.Error != nil {
			return total, fmt.Errorf("prune daily rollups: %w", res.Error)
		}
		total += res.RowsAffected
	}
	return total, nil
}

// UserRollupKey is the rollup key for a user id, kept beside the counter-key
// encoding so the two cannot drift apart.
func UserRollupKey(userID uint) string { return strconv.FormatUint(uint64(userID), 10) }
