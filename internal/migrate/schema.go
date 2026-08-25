package migrate

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// This file is ForgePanel's own schema-migration runner: an ordered,
// uniquely-versioned registry of steps, every one of which is recorded in the
// database with the time it was applied.
//
// It exists because gorm's AutoMigrate cannot express the three things a live
// panel actually needs. AutoMigrate has no ordering, so a data backfill cannot
// be sequenced after the column it fills. It is additive only, so a rename or a
// drop is impossible and a breaking change has no safe path. And it leaves no
// record, so an operator looking at a database that is behaving strangely has no
// way to tell which schema it is really on, or whether a step half-ran.
//
// Nothing here is model-aware: the caller supplies the migrations, so the runner
// never has to import the package whose tables it migrates.

// Migration is one ordered schema change.
//
// Up runs inside a transaction together with the ledger insert that records it,
// so a step that fails halfway leaves neither a half-applied schema nor a row
// claiming it succeeded. A step whose statements a driver refuses inside a
// transaction sets NoTx and accepts that it must be internally idempotent.
type Migration struct {
	// Version orders the registry and is the ledger's primary key. Versions are
	// permanent: once a number has shipped it is never reused or renumbered,
	// because a database in the field records only the number.
	Version uint64
	// Name is the human handle shown in the ledger. It is compared against the
	// recorded name on every run so a renumbered or reordered registry is caught
	// instead of silently re-running the wrong step.
	Name string
	// Up applies the change.
	Up func(tx *gorm.DB) error
	// Rollback documents what undoing this step would take. It is prose, not
	// code: an automatic down-migration on a live panel is a data-loss weapon,
	// and the honest answer for most steps is "restore the backup". Writing the
	// consideration down forces the author to have had one.
	Rollback string
	// Baseline marks a step that only ever builds schema from nothing. Those are
	// the steps skipped (recorded, not executed) when the runner finds a database
	// that already carries a schema built before this registry existed — see
	// RunMigrations.
	Baseline bool
	// NoTx runs Up outside a transaction.
	NoTx bool
}

// MigrationRecord is one row of the schema_migrations ledger: the audit trail of
// what ran against this database and when.
type MigrationRecord struct {
	Version    uint64    `gorm:"primaryKey"`
	Name       string    `gorm:"not null"`
	AppliedAt  time.Time `gorm:"not null"`
	DurationMS int64
	// Adopted marks a baseline step that was recorded without being executed
	// because the database already had the schema it would have created. It is
	// what tells an operator that this database predates versioned migrations.
	Adopted bool
}

// TableName pins the ledger's table so a future rename of this type cannot make
// an existing database look unmigrated and replay every step against it.
func (MigrationRecord) TableName() string { return "schema_migrations" }

// ErrRegistryInvalid reports a registry that is not a strictly ascending,
// uniquely numbered, fully populated list. It is a programming error, caught
// before a single statement runs.
var ErrRegistryInvalid = errors.New("migrate: migration registry is invalid")

// ErrLedgerDrift reports that a version recorded in the database was applied
// under a different name than the registry now gives it. Continuing would mean
// treating a step that never ran as applied, so the runner refuses.
var ErrLedgerDrift = errors.New("migrate: applied migration does not match the registry")

// MigrationOptions tunes a run.
type MigrationOptions struct {
	// SchemaExists reports whether the database already carries tables that the
	// registry's baseline steps would otherwise create. It is consulted exactly
	// once, and only when the ledger table itself is absent, which is the single
	// moment a database can be adopted into the registry. Leaving it nil means
	// "every database is either empty or already registered".
	SchemaExists func(*gorm.DB) (bool, error)
}

// AppliedMigration describes one step a run put into the ledger.
type AppliedMigration struct {
	Version  uint64
	Name     string
	Adopted  bool
	Duration time.Duration
}

// MigrationReport is the outcome of a run.
type MigrationReport struct {
	// Applied lists the steps recorded by this run, in order.
	Applied []AppliedMigration
	// AlreadyApplied counts steps the ledger already had, which is what makes a
	// second run a no-op.
	AlreadyApplied int
	// Adopted is true when this run took over a database whose schema predates
	// the registry.
	Adopted bool
	// Version is the highest version recorded once the run finished.
	Version uint64
}

// ValidateRegistry checks a registry before any of it runs. Ordering is checked
// as written rather than sorted first, so the file itself is the source of order
// and a pasted duplicate or an out-of-place insertion fails loudly.
func ValidateRegistry(migs []Migration) error {
	var prev uint64
	seen := make(map[string]uint64, len(migs))
	for i, m := range migs {
		switch {
		case m.Version == 0:
			return fmt.Errorf("%w: entry %d has no version", ErrRegistryInvalid, i)
		case m.Name == "":
			return fmt.Errorf("%w: version %d has no name", ErrRegistryInvalid, m.Version)
		case m.Up == nil:
			return fmt.Errorf("%w: version %d (%s) has no Up", ErrRegistryInvalid, m.Version, m.Name)
		case m.Version <= prev:
			return fmt.Errorf("%w: version %d (%s) does not come after %d", ErrRegistryInvalid, m.Version, m.Name, prev)
		}
		if at, dup := seen[m.Name]; dup {
			return fmt.Errorf("%w: name %q is used by both version %d and %d", ErrRegistryInvalid, m.Name, at, m.Version)
		}
		seen[m.Name] = m.Version
		prev = m.Version
	}
	return nil
}

// RunMigrations applies every registry step the database has not recorded yet,
// in order, and returns what it did.
//
// Adoption: a database that already holds a schema built before this registry
// existed must NOT have its baseline steps replayed against it — those steps
// create tables from nothing and know nothing about the rows already there. When
// the ledger table is missing and SchemaExists says a schema is already present,
// baseline steps are recorded as applied without executing, and every
// non-baseline step still runs. That is the difference that matters: stamping
// only the baseline adopts the database, while stamping the whole registry would
// skip the very repairs and backfills such a database needs.
func RunMigrations(db *gorm.DB, migs []Migration, opts MigrationOptions) (*MigrationReport, error) {
	if db == nil {
		return nil, errors.New("migrate: nil database handle")
	}
	if err := ValidateRegistry(migs); err != nil {
		return nil, err
	}

	ledgerExisted := db.Migrator().HasTable(&MigrationRecord{})
	if !ledgerExisted {
		if err := db.Migrator().CreateTable(&MigrationRecord{}); err != nil {
			return nil, fmt.Errorf("migrate: create ledger: %w", err)
		}
	}

	recorded, err := MigrationStatus(db)
	if err != nil {
		return nil, err
	}
	applied := make(map[uint64]MigrationRecord, len(recorded))
	for _, r := range recorded {
		applied[r.Version] = r
	}
	for _, m := range migs {
		if r, ok := applied[m.Version]; ok && r.Name != m.Name {
			return nil, fmt.Errorf("%w: version %d was applied as %q but the registry now calls it %q",
				ErrLedgerDrift, m.Version, r.Name, m.Name)
		}
	}

	rep := &MigrationReport{}
	if !ledgerExisted && opts.SchemaExists != nil {
		present, err := opts.SchemaExists(db)
		if err != nil {
			return nil, fmt.Errorf("migrate: probe for an existing schema: %w", err)
		}
		rep.Adopted = present
	}

	for _, m := range migs {
		if r, ok := applied[m.Version]; ok {
			rep.AlreadyApplied++
			if r.Version > rep.Version {
				rep.Version = r.Version
			}
			continue
		}
		if rep.Adopted && m.Baseline {
			if err := db.Create(&MigrationRecord{
				Version: m.Version, Name: m.Name, AppliedAt: time.Now().UTC(), Adopted: true,
			}).Error; err != nil {
				return nil, fmt.Errorf("migrate: adopt version %d (%s): %w", m.Version, m.Name, err)
			}
			rep.Applied = append(rep.Applied, AppliedMigration{Version: m.Version, Name: m.Name, Adopted: true})
			rep.Version = m.Version
			continue
		}
		took, err := applyMigration(db, m)
		if err != nil {
			return nil, err
		}
		rep.Applied = append(rep.Applied, AppliedMigration{Version: m.Version, Name: m.Name, Duration: took})
		rep.Version = m.Version
	}
	return rep, nil
}

// applyMigration runs one step and records it. The ledger insert shares the
// step's transaction so a crash between the two is impossible: either the schema
// change and its record both land, or neither does.
func applyMigration(db *gorm.DB, m Migration) (time.Duration, error) {
	start := time.Now()
	run := func(tx *gorm.DB) error {
		if err := m.Up(tx); err != nil {
			return fmt.Errorf("migrate: migration %d (%s): %w", m.Version, m.Name, err)
		}
		return tx.Create(&MigrationRecord{
			Version:    m.Version,
			Name:       m.Name,
			AppliedAt:  time.Now().UTC(),
			DurationMS: time.Since(start).Milliseconds(),
		}).Error
	}
	var err error
	if m.NoTx {
		err = run(db)
	} else {
		err = db.Transaction(run)
	}
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// MigrationStatus returns the ledger oldest-first. An empty result from a
// database that has tables means the schema was never registered, not that the
// database is empty.
func MigrationStatus(db *gorm.DB) ([]MigrationRecord, error) {
	if db == nil {
		return nil, errors.New("migrate: nil database handle")
	}
	if !db.Migrator().HasTable(&MigrationRecord{}) {
		return nil, nil
	}
	var out []MigrationRecord
	if err := db.Order("version").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("migrate: read ledger: %w", err)
	}
	return out, nil
}
