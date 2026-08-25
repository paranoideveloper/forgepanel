package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/forgepanel/forgepanel/internal/migrate"
)

// This file is ForgePanel's schema-migration registry. Before it, store.Open ran
// gorm's AutoMigrate on every boot: no ordering, no record of what had run, no
// way to express a backfill or a drop, and — worst on SQLite — AutoMigrate is
// free to rebuild a table to reconcile a column, which is the one operation on a
// live panel database that can lose an operator's users.
//
// Adding a column to a model here is therefore NOT enough on its own: a fresh
// install picks it up from the baseline, but a database already at the current
// version will never see it. Every model change needs a migration, and
// TestModelSchemaFingerprintPinned fails until one exists.

// Migration versions. They are constants rather than literals in the registry so
// a new step cannot silently reuse a number that has already shipped, and so a
// migration can be referenced by name from a test.
const (
	migVBaseline      uint64 = 1
	migVAlignLegacy   uint64 = 2
	migVRepairOrphans uint64 = 3
	migVTrafficSnaps  uint64 = 4
	migVNodeMetrics   uint64 = 5
	migVRollups       uint64 = 6
)

// migrations is the ordered registry. Entries are append-only: a shipped version
// is never renumbered, reordered or rewritten, because a database in the field
// records only the number and the runner refuses a name that no longer matches.
func migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version:  migVBaseline,
			Name:     "baseline_schema",
			Baseline: true,
			Rollback: "none. This step is the whole schema; undoing it means dropping the database, " +
				"so the only rollback is restoring a backup.",
			Up: func(tx *gorm.DB) error { return createSchema(tx, AllModels()) },
		},
		{
			Version: migVAlignLegacy,
			Name:    "align_pre_registry_schema",
			Rollback: "none needed. The step only ever adds a missing table, column or index; " +
				"it never drops or rewrites one, so there is nothing to undo.",
			Up: func(tx *gorm.DB) error { _, err := alignSchema(tx, AllModels()); return err },
		},
		{
			Version: migVRepairOrphans,
			Name:    "repair_orphaned_references",
			Rollback: "irreversible. The rows it removes point at objects that no longer exist, " +
				"so restoring them would restore the corruption; recover from a backup instead.",
			Up: func(tx *gorm.DB) error { _, err := repairOrphans(tx); return err },
		},
		{
			Version: migVTrafficSnaps,
			Name:    "traffic_snapshots",
			Rollback: "safe to drop. The table holds only the last cumulative counter value seen " +
				"per user; losing it makes the next poll treat each counter's current total as one " +
				"delta, which over-counts once and then settles.",
			// Adds the table behind downtime-safe accounting. Without it the
			// poller has no baseline, so it would fall back to reading the
			// engine's counters destructively — the pattern that loses a whole
			// cycle's traffic whenever the panel is killed mid-cycle.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&TrafficSnapshot{}})
				return err
			},
		},
		{
			Version: migVNodeMetrics,
			Name:    "node_disk_conns_uptime",
			Rollback: "safe to drop. The columns hold the newest reported metrics only; " +
				"losing them costs one heartbeat of history, which the next heartbeat replaces.",
			// Adds disk, TCP connection count and core uptime to the node row.
			// Without the migration an existing database keeps the old columns
			// and every node reports these as zero forever, which reads as
			// "healthy with an empty disk" rather than "not collected".
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Node{}})
				return err
			},
		},
		{
			Version: migVRollups,
			Name:    "traffic_rollups",
			Rollback: "safe to drop. The table holds usage HISTORY only; losing it costs the charts " +
				"their past, not any user's current balance, which lives on the user row.",
			// Usage history per hour and per day. Without the table the panel
			// knows totals and nothing about when, so there are no charts, no
			// usage reports and no way to watch a quota being consumed.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&TrafficRollup{}})
				return err
			},
		},
	}
}

// Migrate brings db up to the current schema version and reports what it did.
func Migrate(db *gorm.DB) (*migrate.MigrationReport, error) {
	return migrate.RunMigrations(db, migrations(), migrate.MigrationOptions{SchemaExists: hasPreRegistrySchema})
}

// hasPreRegistrySchema reports whether this database was created by a build that
// predates the registry. The probe is the three tables that have existed since
// the first ForgePanel release: if any of them is there while the ledger is not,
// the database holds real operator data and must be adopted, never rebuilt.
func hasPreRegistrySchema(db *gorm.DB) (bool, error) {
	m := db.Migrator()
	for _, model := range []any{&Admin{}, &User{}, &Inbound{}} {
		if m.HasTable(model) {
			return true, nil
		}
	}
	return false, nil
}

// createSchema builds every table from nothing. It is the fresh-install path and
// runs only when the database has no ForgePanel tables at all.
func createSchema(tx *gorm.DB, models []any) error {
	if err := tx.Migrator().CreateTable(models...); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// SchemaDelta counts what alignSchema had to add.
type SchemaDelta struct {
	Tables  []string
	Columns []string
	Indexes []string
}

// Empty reports whether the database already matched the model set.
func (d SchemaDelta) Empty() bool {
	return len(d.Tables) == 0 && len(d.Columns) == 0 && len(d.Indexes) == 0
}

// alignSchema brings a database created before the registry up to the shape the
// baseline would have produced. It is deliberately NOT AutoMigrate: it only
// creates a missing table, adds a missing column and creates a missing index,
// and it never alters or rebuilds an existing one. That restriction is the whole
// point — a pre-registry database can be any historical shape, and the one thing
// that must not happen while adopting it is a table rebuild that drops rows or
// truncates a column whose declared type has drifted.
func alignSchema(tx *gorm.DB, models []any) (SchemaDelta, error) {
	var delta SchemaDelta
	m := tx.Migrator()
	for _, model := range models {
		stmt := &gorm.Statement{DB: tx}
		if err := stmt.Parse(model); err != nil {
			return delta, fmt.Errorf("parse model: %w", err)
		}
		table := stmt.Schema.Table

		if !m.HasTable(model) {
			if err := m.CreateTable(model); err != nil {
				return delta, fmt.Errorf("create table %s: %w", table, err)
			}
			delta.Tables = append(delta.Tables, table)
			continue
		}
		for _, f := range stmt.Schema.Fields {
			if f.DBName == "" || f.IgnoreMigration || !f.Creatable {
				continue
			}
			if m.HasColumn(model, f.DBName) {
				continue
			}
			if err := m.AddColumn(model, f.DBName); err != nil {
				return delta, fmt.Errorf("add column %s.%s: %w", table, f.DBName, err)
			}
			delta.Columns = append(delta.Columns, table+"."+f.DBName)
		}
		for _, idx := range stmt.Schema.ParseIndexes() {
			if idx.Name == "" || m.HasIndex(model, idx.Name) {
				continue
			}
			if err := m.CreateIndex(model, idx.Name); err != nil {
				return delta, fmt.Errorf("create index %s on %s: %w", idx.Name, table, err)
			}
			delta.Indexes = append(delta.Indexes, idx.Name)
		}
	}
	return delta, nil
}

// modelSchemaFingerprint is a dialect-independent digest of the declared model
// set: every table, its columns with their abstract types and null/primary-key
// flags, and every index name. TestModelSchemaFingerprintPinned compares it
// against modelSchemaFingerprintPinned so that changing a model without adding
// the migration that carries the change to existing databases fails in CI rather
// than at an operator's next boot.
func modelSchemaFingerprint(db *gorm.DB, models []any) (string, error) {
	lines := make([]string, 0, 256)
	for _, model := range models {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(model); err != nil {
			return "", fmt.Errorf("parse model: %w", err)
		}
		table := stmt.Schema.Table
		for _, f := range stmt.Schema.Fields {
			if f.DBName == "" || f.IgnoreMigration || !f.Creatable {
				continue
			}
			lines = append(lines, "col "+table+"."+f.DBName+" "+string(f.DataType)+
				" notnull="+strconv.FormatBool(f.NotNull)+" pk="+strconv.FormatBool(f.PrimaryKey))
		}
		for _, idx := range stmt.Schema.ParseIndexes() {
			lines = append(lines, "idx "+table+"."+idx.Name+" class="+idx.Class)
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}
