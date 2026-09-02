package store

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/forgepanel/forgepanel/internal/migrate"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

func rawDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/forgepanel.db"),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// TestFreshDatabaseRecordsTheWholeRegistry: an install must end up with an
// auditable ledger, not just tables, or nobody can tell later which schema the
// database is on.
func TestFreshDatabaseRecordsTheWholeRegistry(t *testing.T) {
	db := rawDB(t)
	rep, err := Migrate(db)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Adopted {
		t.Fatal("an empty database was adopted instead of built from the baseline")
	}
	// The expected version is the LAST entry in the registry, not a constant
	// repeated here: hardcoding it means every new migration fails this test
	// with a message about the wrong thing.
	all := migrations()
	want := all[len(all)-1].Version
	if rep.Version != want || len(rep.Applied) != len(all) {
		t.Fatalf("registry did not fully apply: reached version %d of %d, applied %d of %d\n%+v",
			rep.Version, want, len(rep.Applied), len(all), rep)
	}
	rows, err := migrate.MigrationStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(migrations()) {
		t.Fatalf("ledger has %d rows, want %d", len(rows), len(migrations()))
	}
	for _, r := range rows {
		if r.AppliedAt.IsZero() {
			t.Fatalf("version %d recorded without a timestamp", r.Version)
		}
	}
	for _, m := range AllModels() {
		if !db.Migrator().HasTable(m) {
			t.Fatalf("baseline did not create the table for %T", m)
		}
	}

	// A second boot must change nothing.
	rep2, err := Migrate(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Applied) != 0 || rep2.AlreadyApplied != len(migrations()) {
		t.Fatalf("a second migration run was not a no-op: %+v", rep2)
	}
}

// TestEveryMigrationDocumentsItsRollback: an operator staring at a broken
// upgrade needs to know what undoing a step would take. An empty Rollback means
// the author never considered it.
func TestEveryMigrationDocumentsItsRollback(t *testing.T) {
	if err := migrate.ValidateRegistry(migrations()); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations() {
		if m.Rollback == "" {
			t.Fatalf("migration %d (%s) documents no rollback consideration", m.Version, m.Name)
		}
	}
}

// --- the pre-registry ("legacy") schema fixture ---------------------------
//
// These are ForgePanel's models as an older build wrote them: fewer columns, and
// three tables that did not exist yet. They are the shape a real operator's
// forgepanel.db is in right now, and adopting one of those without losing a
// single row is the whole point of the registry.

type legacyAdmin struct {
	ID           uint `gorm:"primaryKey"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	Role         string `gorm:"default:owner"`
	TOTPSecret   string
	Disabled     bool
}

func (legacyAdmin) TableName() string { return "admins" }

type legacyGroup struct {
	ID         uint `gorm:"primaryKey"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Name       string   `gorm:"uniqueIndex;not null"`
	InboundIDs IntSlice `gorm:"type:text"`
}

func (legacyGroup) TableName() string { return "groups" }

type legacyUser struct {
	ID             uint `gorm:"primaryKey"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Username       string `gorm:"uniqueIndex;not null"`
	Status         string `gorm:"default:active"`
	GroupID        uint
	OwnerAdminID   uint `gorm:"index"`
	UUID           string
	Password       string
	SubToken       string `gorm:"uniqueIndex"`
	DataLimit      int64
	UsedTraffic    int64
	ResetStrategy  string `gorm:"default:no_reset"`
	ExpireAt       *time.Time
	OnHoldDuration int64
	FirstConnectAt *time.Time
	IPLimit        int
	TelegramID     int64
	Note           string
}

func (legacyUser) TableName() string { return "users" }

type legacyInbound struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	NodeID    uint   `gorm:"index"`
	Remark    string `gorm:"index"`
	Protocol  string
	Port      int
	Enabled   bool   `gorm:"default:true"`
	NodeJSON  string `gorm:"type:text"`
}

func (legacyInbound) TableName() string { return "inbounds" }

// legacyNodeClientTraffic is the per-(node,user) baseline table shipped before
// traffic_snapshots replaced it. Real databases in the field still carry it, so
// the fixture keeps it: migrating must step over a table the panel no longer
// models rather than tripping on it.
type legacyNodeClientTraffic struct {
	NodeID       uint   `gorm:"primaryKey"`
	Username     string `gorm:"primaryKey"`
	LastRecorded int64
}

func (legacyNodeClientTraffic) TableName() string { return "node_client_traffic" }

type legacyNode struct {
	ID          uint `gorm:"primaryKey"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Name        string `gorm:"uniqueIndex;not null"`
	Address     string
	EnrollToken string `gorm:"uniqueIndex"`
	Enrolled    bool
	LastSeen    *time.Time
	CoreVersion string
	CPU         float64
	MemMB       int
	Healthy     bool
}

func (legacyNode) TableName() string { return "nodes" }

type legacyZone struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Zone      string `gorm:"uniqueIndex;not null"`
	Adapter   string `gorm:"default:cottendns"`
	Enabled   bool   `gorm:"default:true"`
	NSHost    string
	Key       string
}

func (legacyZone) TableName() string { return "forge_dns_zones" }

// seedLegacyDatabase builds a pre-registry database holding real operator data:
// one admin, two users (one bound to a group, one with a direct subscription
// token), two inbounds, a node with a traffic baseline, and settings.
func seedLegacyDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	db := rawDB(t)
	// Note the missing tables: user_inbounds, domains and edge_deployments did
	// not exist in this build, so adoption has to create them.
	if err := db.Migrator().CreateTable(&legacyAdmin{}, &legacyGroup{}, &legacyUser{},
		&legacyInbound{}, &Setting{}, &AuditLog{}, &legacyNode{}, &legacyNodeClientTraffic{},
		&legacyZone{}); err != nil {
		t.Fatal(err)
	}
	node := &model.Node{Protocol: model.ProtoVLESS, Address: "203.0.113.9", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Remark: "legacy-in",
		Transport: model.Transport{Network: model.NetTCP}}
	nodeJSON, err := marshalNode(node)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	seed := []any{
		&legacyAdmin{ID: 1, Username: "owner", PasswordHash: "$argon2id$fake", Role: "owner"},
		&legacyNode{ID: 1, Name: "s7", Address: "203.0.113.9", EnrollToken: "enroll-legacy", Enrolled: true},
		&legacyInbound{ID: 1, NodeID: 1, Remark: "legacy-in", Protocol: "vless", Port: 443,
			Enabled: true, NodeJSON: nodeJSON},
		&legacyInbound{ID: 2, Remark: "legacy-in-2", Protocol: "vless", Port: 8443,
			Enabled: true, NodeJSON: nodeJSON},
		&legacyGroup{ID: 1, Name: "legacy-group", InboundIDs: IntSlice{1, 2}},
		&legacyUser{ID: 1, Username: "alice", Status: "active", GroupID: 1, SubToken: "tok-alice",
			UUID: "u-alice", DataLimit: 1 << 30, UsedTraffic: 512, ResetStrategy: "month", ExpireAt: &exp},
		&legacyUser{ID: 2, Username: "bob", Status: "limited", SubToken: "tok-bob", UUID: "u-bob",
			DataLimit: 1 << 20, UsedTraffic: 1 << 21},
		&legacyZone{ID: 1, Zone: "tunnel.example", Adapter: "cottendns", Enabled: true},
		&legacyNodeClientTraffic{NodeID: 1, Username: "alice", LastRecorded: 512},
		&Setting{Key: "panel.title", Value: "legacy panel"},
	}
	for _, row := range seed {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	return db
}

// TestLegacyDatabaseIsAdoptedWithoutLosingData is the guard that matters most:
// an operator's existing forgepanel.db must come through the switch to versioned
// migrations with every admin, user, inbound, node, subscription token and
// setting exactly as it was — and with the columns and tables newer builds
// added.
func TestLegacyDatabaseIsAdoptedWithoutLosingData(t *testing.T) {
	db := seedLegacyDatabase(t)

	rep, err := Migrate(db)
	if err != nil {
		t.Fatalf("adopting a pre-registry database failed: %v", err)
	}
	if !rep.Adopted {
		t.Fatal("a database with existing ForgePanel tables was not adopted")
	}
	rows, err := migrate.MigrationStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(migrations()) {
		t.Fatalf("ledger has %d rows, want %d", len(rows), len(migrations()))
	}
	if !rows[0].Adopted {
		t.Fatal("the baseline was replayed against an existing schema instead of being stamped")
	}
	for _, r := range rows[1:] {
		if r.Adopted {
			t.Fatalf("version %d (%s) was stamped instead of run; the database never got it",
				r.Version, r.Name)
		}
	}

	// Columns and tables newer builds introduced must now exist.
	for _, want := range []struct {
		model  any
		column string
	}{
		{&Admin{}, "session_epoch"},
		{&Admin{}, "last_totp_step"},
		{&Admin{}, "recovery_codes"},
		{&Admin{}, "user_quota"},
		{&User{}, "lifetime_traffic"},
		{&User{}, "last_reset_at"},
		{&User{}, "last_seen_at"},
		{&User{}, "sub_revoked"},
		{&User{}, "sub_updated_at"},
		{&User{}, "sub_last_ua"},
		{&Inbound{}, "prev_node_json"},
		{&Node{}, "config_dirty"},
		{&Group{}, "is_default"},
		{&ForgeDNSZone{}, "override_toml"},
	} {
		if !db.Migrator().HasColumn(want.model, want.column) {
			t.Fatalf("adoption did not add %T.%s", want.model, want.column)
		}
	}
	for _, m := range []any{&UserInbound{}, &Domain{}, &EdgeDeployment{}, &SubRequest{}} {
		if !db.Migrator().HasTable(m) {
			t.Fatalf("adoption did not create the missing table for %T", m)
		}
	}

	// Every row must have survived, readable through the real repositories.
	s := &Store{db: db}
	if n, err := s.CountAdmins(); err != nil || n != 1 {
		t.Fatalf("admins lost: n=%d err=%v", n, err)
	}
	admin, err := s.AdminByUsername("owner")
	if err != nil || admin.PasswordHash != "$argon2id$fake" || admin.Role != RoleOwner {
		t.Fatalf("admin did not survive intact: %+v %v", admin, err)
	}
	users, err := s.ListUsers(0)
	if err != nil || len(users) != 2 {
		t.Fatalf("users lost: %d %v", len(users), err)
	}
	alice, err := s.UserBySubToken("tok-alice")
	if err != nil {
		t.Fatalf("subscription token no longer resolves: %v", err)
	}
	if alice.DataLimit != 1<<30 || alice.UsedTraffic != 512 || alice.GroupID != 1 ||
		alice.Status != StatusActive || alice.ResetStrategy != ResetMonth || alice.ExpireAt == nil {
		t.Fatalf("user fields were altered by the migration: %+v", alice)
	}
	if alice.LifetimeTraffic != 0 || alice.LastResetAt != nil {
		t.Fatalf("newly added columns were not zero-valued: %+v", alice)
	}
	if _, err := s.UserBySubToken("tok-bob"); err != nil {
		t.Fatalf("second subscription token lost: %v", err)
	}
	ins, err := s.ListInbounds()
	if err != nil || len(ins) != 2 {
		t.Fatalf("inbounds lost: %d %v", len(ins), err)
	}
	rehydrated, err := ins[0].Node()
	if err != nil || rehydrated.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("inbound config did not survive: %+v %v", rehydrated, err)
	}
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 1 || nodes[0].EnrollToken != "enroll-legacy" {
		t.Fatalf("nodes lost: %+v %v", nodes, err)
	}
	groups, err := s.ListGroups()
	if err != nil || len(groups) != 1 || len(groups[0].InboundIDs) != 2 {
		t.Fatalf("group binding lost: %+v %v", groups, err)
	}
	zones, err := s.ListZones()
	if err != nil || len(zones) != 1 || zones[0].Zone != "tunnel.example" {
		t.Fatalf("forgedns zones lost: %+v %v", zones, err)
	}
	if v := s.GetSetting("panel.title"); v != "legacy panel" {
		t.Fatalf("settings lost: %q", v)
	}
	// node_client_traffic is no longer modelled — traffic_snapshots replaced it,
	// atomically and scoped. The rows are left in place rather than dropped
	// (a destructive migration for data nothing reads), so all that matters here
	// is that migrating a database containing it succeeds and creates the new
	// table alongside.
	if _, err := s.TrafficSnapshots(ScopeLocalEngine); err != nil {
		t.Fatalf("traffic_snapshots not usable after migrating a legacy database: %v", err)
	}
	// The subscription still resolves to the same inbounds it did before.
	eff, err := s.InboundsForUser(alice.ID)
	if err != nil || len(eff) != 2 {
		t.Fatalf("subscription resolves to %v (%v), want both inbounds", eff, err)
	}

	// Re-running must not touch anything.
	rep2, err := Migrate(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Applied) != 0 || rep2.AlreadyApplied != len(migrations()) {
		t.Fatalf("adopting again was not a no-op: %+v", rep2)
	}
}

// TestAlignSchemaOnlyAddsWhatIsMissing: the adoption step must never rewrite an
// existing table. On SQLite a rebuild is the one operation that can silently lose
// rows, so a database that already matches the models must come out untouched.
func TestAlignSchemaOnlyAddsWhatIsMissing(t *testing.T) {
	db := rawDB(t)
	if _, err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	delta, err := alignSchema(db, AllModels())
	if err != nil {
		t.Fatal(err)
	}
	if !delta.Empty() {
		t.Fatalf("alignSchema wanted to change a database that already matched the models: %+v", delta)
	}

	legacy := seedLegacyDatabase(t)
	delta2, err := alignSchema(legacy, AllModels())
	if err != nil {
		t.Fatal(err)
	}
	if len(delta2.Tables) == 0 || len(delta2.Columns) == 0 {
		t.Fatalf("alignSchema found nothing to add to a pre-registry database: %+v", delta2)
	}
	// Idempotent: a second pass has nothing left to do.
	delta3, err := alignSchema(legacy, AllModels())
	if err != nil {
		t.Fatal(err)
	}
	if !delta3.Empty() {
		t.Fatalf("alignSchema is not idempotent: %+v", delta3)
	}
}

// modelSchemaFingerprintPinned is the digest of the model set the current
// registry is known to produce. It is pinned so that adding or changing a column
// fails here rather than at an operator's next boot: a fresh install would pick
// the change up from the baseline, but a database already at the current version
// only ever gets it from a migration. When this test fails, add the migration
// that carries the change to existing databases, then update this constant.
//
// REMOVING a model is the one case that needs no migration: alignSchema only
// ever adds tables, columns and indexes, so a model that goes away simply leaves
// its table behind, unread. That is deliberate — dropping a table is destructive
// and irreversible, and the rows cost nothing where they sit. Update the pin,
// and say here what was removed and why.
//
// node_client_traffic was removed when traffic_snapshots replaced it: the old
// table's writer (internal/service) was never linked into any binary, so the
// baselines it modelled were never written, and the replacement is scoped and
// updates atomically with the usage it accounts for.
//
// outbound_groups was added with migVOutboundGroups: named failover groups,
// several outbounds behind one tag. A database already at the previous version
// has no such table, and the rules that target a group would name a balancer the
// generated config cannot define — which the core refuses whole, taking every
// inbound down. The migration carries the table; this pin follows it.
//
// webhook_endpoints came next, in the same batch: lifecycle alerts had exactly
// one sink and it was a chat app, so anything wanting them programmatically had
// to poll. Two models landing together is why this digest moved twice.
//
// nodes gained a status column in the same batch, with a backfill: adding it
// stamps every existing row with one default, so an established fleet would come
// out of the migration claiming every node — including ones long dead — is in
// the same state.
//
// sub_requests, plus users.sub_updated_at and users.sub_last_ua, came with
// migVSubTelemetry: /sub/:token recorded nothing, so no panel could say whether
// a subscriber's client had ever pulled its configuration. A table and two
// columns move the digest together.
//
// user_templates arrived with migVUserTemplates: saved plans, so "the 5 GB
// monthly trial" is a row rather than something an operator retypes from memory
// on every new account. It adds a table and touches no existing one, but a
// database already at the previous version has no such table, and the create-user
// handler now reads it — so an unmigrated panel would answer every template-backed
// create with a missing-table error.
//
// edge_deployments gained self_manage: the Worker's own Deployment panel reads
// CF_API_TOKEN/CF_ACCOUNT_ID bindings, and an update re-sends a closed bindings
// list. Without a record of which Workers were deployed with that credential,
// the next `forgectl edge update` strips it back out and nothing reports it.
//
// Three models landed in the same batch, so no single branch's digest is the
// merged one; this is recomputed at the merge.

// core_pins came with migVCorePins: the operator's own (engine, version, asset)
// checksums, which is what lets a panel move off the core version it was
// compiled against. It has to be a table because a version needs one digest per
// platform asset, and it has to carry the digest at all because binmgr refuses
// to install an artifact it cannot verify — a version with no checksum is not a
// smaller feature, it is an unverified proxy core.
const modelSchemaFingerprintPinned = "c0f25b830e74df4159fb1fbaa3d9d3c8286b024f2346e78a75f4811ebf168077"

// TestModelSchemaFingerprintPinned guards the registry against a model change
// that ships without a migration.
func TestModelSchemaFingerprintPinned(t *testing.T) {
	db := rawDB(t)
	got, err := modelSchemaFingerprint(db, AllModels())
	if err != nil {
		t.Fatal(err)
	}
	if got != modelSchemaFingerprintPinned {
		t.Fatalf("the model set changed (fingerprint %s, pinned %s).\n"+
			"A database already at the current schema version will NEVER see this change: "+
			"add a migration to internal/store/migrations.go that applies it, then update "+
			"modelSchemaFingerprintPinned to the new value.", got, modelSchemaFingerprintPinned)
	}
}

// TestMigrateRefusesARenumberedRegistry: the ledger stores only version numbers,
// so silently accepting a renamed version would mark a step applied that never
// ran. Boot must fail instead.
func TestMigrateRefusesARenumberedRegistry(t *testing.T) {
	db := rawDB(t)
	if _, err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	renamed := migrations()
	renamed[0].Name = "baseline_schema_v2"
	_, err := migrate.RunMigrations(db, renamed, migrate.MigrationOptions{SchemaExists: hasPreRegistrySchema})
	if !errors.Is(err, migrate.ErrLedgerDrift) {
		t.Fatalf("a renumbered registry was accepted: %v", err)
	}
}
