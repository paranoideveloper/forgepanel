package migrate

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/m.db"),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// noop is a migration body that does nothing but is not nil, for registry
// validation cases where the body is irrelevant.
func noop(*gorm.DB) error { return nil }

// TestValidateRegistryRejectsAmbiguousRegistries: every one of these mistakes
// ends with a database that either replays a step or skips one, and both are
// silent. They have to fail before any statement runs.
func TestValidateRegistryRejectsAmbiguousRegistries(t *testing.T) {
	cases := map[string][]Migration{
		"zero version": {{Version: 0, Name: "a", Up: noop}},
		"no name":      {{Version: 1, Up: noop}},
		"nil up":       {{Version: 1, Name: "a"}},
		"duplicate version": {
			{Version: 1, Name: "a", Up: noop},
			{Version: 1, Name: "b", Up: noop},
		},
		"out of order": {
			{Version: 2, Name: "a", Up: noop},
			{Version: 1, Name: "b", Up: noop},
		},
		"duplicate name": {
			{Version: 1, Name: "a", Up: noop},
			{Version: 2, Name: "a", Up: noop},
		},
	}
	for name, reg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRegistry(reg); !errors.Is(err, ErrRegistryInvalid) {
				t.Fatalf("registry with %s was accepted: %v", name, err)
			}
			if _, err := RunMigrations(testDB(t), reg, MigrationOptions{}); !errors.Is(err, ErrRegistryInvalid) {
				t.Fatalf("RunMigrations ran an invalid registry: %v", err)
			}
		})
	}
	valid := []Migration{{Version: 1, Name: "a", Up: noop}, {Version: 2, Name: "b", Up: noop}}
	if err := ValidateRegistry(valid); err != nil {
		t.Fatalf("a well-formed registry was rejected: %v", err)
	}
}

// TestRunMigrationsAppliesInOrderOnceOnly: the registry must run in version
// order, and a second boot must apply nothing at all — a migration that runs
// twice is how a backfill doubles the numbers it was meant to set.
func TestRunMigrationsAppliesInOrderOnceOnly(t *testing.T) {
	db := testDB(t)
	var order []string
	reg := []Migration{
		{Version: 1, Name: "first", Up: func(*gorm.DB) error { order = append(order, "first"); return nil }},
		{Version: 5, Name: "second", Up: func(*gorm.DB) error { order = append(order, "second"); return nil }},
		{Version: 9, Name: "third", Up: func(*gorm.DB) error { order = append(order, "third"); return nil }},
	}

	rep, err := RunMigrations(db, reg, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Applied) != 3 || rep.Version != 9 || rep.AlreadyApplied != 0 {
		t.Fatalf("first run: %+v", rep)
	}
	if len(order) != 3 || order[0] != "first" || order[1] != "second" || order[2] != "third" {
		t.Fatalf("migrations ran out of order: %v", order)
	}

	rep2, err := RunMigrations(db, reg, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Applied) != 0 || rep2.AlreadyApplied != 3 {
		t.Fatalf("a second run was not a no-op: %+v", rep2)
	}
	if len(order) != 3 {
		t.Fatalf("a migration ran twice: %v", order)
	}

	rows, err := MigrationStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("ledger has %d rows, want 3", len(rows))
	}
	for _, r := range rows {
		if r.AppliedAt.IsZero() {
			t.Fatalf("version %d was recorded without an applied-at timestamp", r.Version)
		}
		if r.Adopted {
			t.Fatalf("version %d was marked adopted on a fresh database", r.Version)
		}
	}
	if rows[0].Version != 1 || rows[2].Version != 9 {
		t.Fatalf("ledger is not ordered: %+v", rows)
	}
}

type stepMarker struct {
	ID int `gorm:"primaryKey"`
}

func (stepMarker) TableName() string { return "step_marker" }

// TestRunMigrationsRollsBackAFailedStep: the schema change and the ledger row
// share one transaction, so a step that dies halfway must leave neither. Without
// that, the next boot either replays a partly-applied step or skips it entirely.
func TestRunMigrationsRollsBackAFailedStep(t *testing.T) {
	db := testDB(t)
	boom := errors.New("engine exploded")
	reg := []Migration{
		{Version: 1, Name: "ok", Up: noop},
		{Version: 2, Name: "doomed", Up: func(tx *gorm.DB) error {
			if err := tx.Migrator().CreateTable(&stepMarker{}); err != nil {
				return err
			}
			return boom
		}},
		{Version: 3, Name: "never", Up: func(*gorm.DB) error {
			t.Fatal("a step after a failure was allowed to run")
			return nil
		}},
	}
	if _, err := RunMigrations(db, reg, MigrationOptions{}); !errors.Is(err, boom) {
		t.Fatalf("the failure was not surfaced: %v", err)
	}
	if db.Migrator().HasTable(&stepMarker{}) {
		t.Fatal("the failed step's table survived; the migration was not transactional")
	}
	rows, err := MigrationStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Version != 1 {
		t.Fatalf("ledger recorded a step that did not complete: %+v", rows)
	}
}

// TestRunMigrationsAdoptsAnExistingSchema: a database built before the registry
// existed must have its baseline stamped rather than rebuilt, while every later
// repair still runs against it.
func TestRunMigrationsAdoptsAnExistingSchema(t *testing.T) {
	db := testDB(t)
	if err := db.Migrator().CreateTable(&stepMarker{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&stepMarker{ID: 7}).Error; err != nil {
		t.Fatal(err)
	}

	baselineRan, repairRan := false, false
	reg := []Migration{
		{Version: 1, Name: "baseline", Baseline: true, Up: func(*gorm.DB) error {
			baselineRan = true
			return nil
		}},
		{Version: 2, Name: "repair", Up: func(*gorm.DB) error { repairRan = true; return nil }},
	}
	rep, err := RunMigrations(db, reg, MigrationOptions{
		SchemaExists: func(d *gorm.DB) (bool, error) { return d.Migrator().HasTable(&stepMarker{}), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Adopted {
		t.Fatal("an existing schema was not adopted")
	}
	if baselineRan {
		t.Fatal("the baseline was replayed against a database that already had a schema")
	}
	if !repairRan {
		t.Fatal("adoption skipped a non-baseline step; the database never gets its repairs")
	}
	rows, _ := MigrationStatus(db)
	if len(rows) != 2 || !rows[0].Adopted || rows[1].Adopted {
		t.Fatalf("ledger does not record which step was adopted: %+v", rows)
	}

	var marker stepMarker
	if err := db.First(&marker, 7).Error; err != nil {
		t.Fatalf("adoption lost existing data: %v", err)
	}

	// An empty database with the same options must build the schema normally.
	fresh := testDB(t)
	baselineRan = false
	rep2, err := RunMigrations(fresh, reg, MigrationOptions{
		SchemaExists: func(d *gorm.DB) (bool, error) { return d.Migrator().HasTable(&stepMarker{}), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Adopted || !baselineRan {
		t.Fatalf("an empty database was adopted instead of built: %+v", rep2)
	}
}

// TestRunMigrationsRefusesLedgerDrift: renumbering a shipped migration would make
// the runner treat a step that never ran as applied. Refusing to boot is the only
// safe answer.
func TestRunMigrationsRefusesLedgerDrift(t *testing.T) {
	db := testDB(t)
	if _, err := RunMigrations(db, []Migration{{Version: 1, Name: "original", Up: noop}}, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := RunMigrations(db, []Migration{{Version: 1, Name: "renamed", Up: noop}}, MigrationOptions{})
	if !errors.Is(err, ErrLedgerDrift) {
		t.Fatalf("a renumbered registry was accepted: %v", err)
	}
}
