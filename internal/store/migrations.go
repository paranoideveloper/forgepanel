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
	migVBaseline       uint64 = 1
	migVAlignLegacy    uint64 = 2
	migVRepairOrphans  uint64 = 3
	migVTrafficSnaps   uint64 = 4
	migVNodeMetrics    uint64 = 5
	migVRollups        uint64 = 6
	migVIPLimit        uint64 = 7
	migVRouting        uint64 = 8
	migVNotServing     uint64 = 9
	migVTrafficSplit   uint64 = 10
	migVAPITokens      uint64 = 11
	migVProfiles       uint64 = 12
	migVImportSource   uint64 = 13
	migVNodeSbStats    uint64 = 14
	migVNodeMTLS       uint64 = 15
	migVInboundHosts   uint64 = 16
	migVWGPeers        uint64 = 17
	migVBridges        uint64 = 18
	migVGroupInbounds  uint64 = 19
	migVOutboundGroups uint64 = 20
	// 21, not 20: outbound_groups took 20 in the same batch. A shipped version is
	// never renumbered, and two migrations sharing a number would leave one of
	// them recorded as already applied on every database that ran the other.
	migVWebhooks uint64 = 21
	// 22: 20 went to outbound_groups and 21 to webhooks in the same batch.
	migVNodeStatus uint64 = 22
	// 23: 22 went to node_status.
	migVSubTelemetry uint64 = 23
	// 24, not 23: 23 was assigned to another row landing in the same batch.
	// Versions only have to increase, never be contiguous (ValidateRegistry,
	// internal/migrate/schema.go:129), and leaving the gap is cheaper than
	// renumbering a step somebody else has already written.
	migVUserTemplates uint64 = 24
	// 26: 23-25 are assigned to other rows landing in the same batch. Numbers
	// are handed out, not computed from "the next free one" — two migrations
	// sharing a number would leave one of them recorded as already applied on
	// every database that ran the other. 25 belongs to the core-pin row, which
	// has not landed yet; the gap is deliberate.
	migVEdgeSelfManage uint64 = 26
	// 25, not 23: 23 and 24 were assigned to other steps in the same batch. A
	// shipped version is never renumbered, so the gap stays.
	migVCorePins uint64 = 25
)

// LatestSchemaVersion is the highest migration this build knows how to apply.
// A backup whose database is beyond it cannot be migrated by this binary, which
// is what makes restoring one destructive rather than merely awkward.
func LatestSchemaVersion() uint64 {
	var max uint64
	for _, m := range migrations() {
		if m.Version > max {
			max = m.Version
		}
	}
	return max
}

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
		{
			Version: migVIPLimit,
			Name:    "user_ip_limit_cooldown",
			Rollback: "safe to drop. The column holds a transient cooldown that expires on its own; " +
				"losing it releases any user currently held by an IP limit, which the next sweep " +
				"re-applies if they are still over it.",
			// Adds users.ip_limited_until. Without the migration an existing
			// database has no column to write, so enforcement would fail on
			// every sweep — leaving IPLimit exactly as non-functional as it was
			// before, but now with errors in the log.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&User{}})
				return err
			},
		},
		{
			Version: migVRouting,
			Name:    "outbounds_and_routing_rules",
			Rollback: "safe to drop, but READ THIS FIRST: dropping the tables removes every routing " +
				"decision an operator configured, so traffic that was being blocked or sent through a " +
				"particular exit falls through to the default direct outbound. Take a backup first.",
			// Named outbounds and the ordered rules that select between them.
			// Without the tables the panel can only send an inbound's entire
			// traffic through one relay chain: no blocking, no geo-split, no
			// per-user exit.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Outbound{}, &RoutingRule{}})
				return err
			},
		},
		{
			Version: migVNotServing,
			Name:    "inbound_not_serving_reason",
			Rollback: "safe to drop. The columns hold a diagnostic recomputed on every reload; " +
				"losing them costs the current explanation, which the next reload rewrites.",
			// Records WHY an inbound is absent from the running configuration.
			// Without the migration the columns do not exist, the write fails on
			// every reload, and the panel goes back to accepting an inbound that
			// silently never serves.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Inbound{}})
				return err
			},
		},
		{
			Version: migVTrafficSplit,
			Name:    "user_upload_download_split",
			Rollback: "safe to drop. The columns hold the ATTRIBUTED halves of usage; UsedTraffic " +
				"remains authoritative and is what quotas are enforced on, so losing them costs " +
				"the breakdown and never a byte of billing.",
			// Adds users.upload_traffic / download_traffic. Without the migration
			// the columns do not exist, every accounting transaction fails, and
			// traffic stops being billed at all — which is why this is a
			// migration and not an opportunistic write.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&User{}})
				return err
			},
		},
		{
			Version: migVAPITokens,
			Name:    "scoped_api_tokens",
			Rollback: "safe to drop, but it REVOKES EVERY ISSUED TOKEN: the secrets are not stored " +
				"anywhere else and cannot be recovered, so every integration using one has to be " +
				"issued a new token by hand.",
			// Machine credentials narrower than a full-privilege admin JWT.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&APIToken{}})
				return err
			},
		},
		{
			Version: migVProfiles,
			Name:    "config_profiles",
			Rollback: "safe to drop, but the inbound rows the bindings own are LEFT BEHIND: they " +
				"keep serving under a definition the panel can no longer edit as a group. Delete " +
				"the profiles through the API first if you intend to remove them.",
			// One protocol definition deployed to many nodes.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Profile{}, &ProfileBinding{}})
				return err
			},
		},
		{
			Version: migVImportSource,
			Name:    "inbound_import_provenance",
			Rollback: "safe to drop. The column only records where a row was imported from; losing " +
				"it makes a future re-import fall back to matching on the remark, which duplicates " +
				"anything that has been renamed since.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Inbound{}})
				return err
			},
		},
		{
			Version: migVNodeSbStats,
			Name:    "node_singbox_stats_capability",
			Rollback: "safe to drop. The column caches what the node reports on every heartbeat; " +
				"losing it makes the panel omit the sing-box stats section for one cycle, after " +
				"which the next heartbeat restores it.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Node{}})
				return err
			},
		},
		{
			Version: migVNodeMTLS,
			Name:    "node_mtls_control_plane",
			Rollback: "safe to drop, but every node then falls back to its legacy enrol token — " +
				"which is exactly the permanent bearer credential this replaced. Re-enrol the " +
				"fleet rather than staying there.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Node{}})
				return err
			},
		},
		{
			Version: migVInboundHosts,
			Name:    "inbound_public_hosts",
			Rollback: "safe to drop. Subscriptions fall back to one entry per inbound plus the " +
				"clean-IP and SNI fan-outs, which is what they did before; any extra endpoints " +
				"an operator defined simply stop being published.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&InboundHost{}})
				return err
			},
		},
		{
			Version: migVWGPeers,
			Name:    "wireguard_per_client_peers",
			Rollback: "NOT safe to drop while WireGuard inbounds have several users: every user " +
				"falls back to the inbound's single shared keypair, and WireGuard keys a session " +
				"by public key, so they take the tunnel from each other in turn.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&WGPeer{}})
				return err
			},
		},
		{
			Version: migVBridges,
			Name:    "reverse_tunnel_bridges",
			Rollback: "safe to drop, but every configured bridge is forgotten: the exit stops " +
				"supervising its half and any inbound reached through it becomes unreachable " +
				"until the bridge is recreated.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&Bridge{}})
				return err
			},
		},
		{
			Version: migVGroupInbounds,
			Name:    "group_inbound_join_table",
			Rollback: "safe to drop: Group.InboundIDs remains the source of truth, so membership " +
				"survives. Only the indexed reverse lookup and the delete cascade are lost.",
			Up: func(tx *gorm.DB) error {
				if _, err := alignSchema(tx, []any{&GroupInbound{}}); err != nil {
					return err
				}
				// BACKFILL. Without it an already-installed panel gets an empty
				// table forever: it exists, the reverse query returns nothing,
				// and nothing looks broken until a delete cascade quietly misses
				// every group that predates this migration.
				var groups []Group
				if err := tx.Find(&groups).Error; err != nil {
					return err
				}
				for i := range groups {
					if err := setGroupInbounds(tx, groups[i].ID, groups[i].InboundIDs); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			Version: migVOutboundGroups,
			Name:    "outbound_failover_groups",
			Rollback: "safe to drop, but READ THIS FIRST: dropping the table removes every failover " +
				"group, so each rule that targeted one names a balancer nothing defines. The core " +
				"accepts that config and silently drops every connection those rules match — the " +
				"traffic stops with one line in the engine log and nothing in the panel. Delete the " +
				"rules that point at groups first, or take a backup.",
			// Named failover groups: several outbounds behind one tag, health
			// probed. Without the table a rule can only name ONE exit, so an
			// operator with two relays loses their users' traffic the moment
			// the one a rule names stops answering.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&OutboundGroup{}})
				return err
			},
		},
		{
			Version: migVWebhooks,
			Name:    "outbound_webhook_endpoints",
			Rollback: "safe to drop: no other table references it. Every configured receiver is " +
				"forgotten and the panel goes back to having Telegram as its only sink.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&WebhookEndpoint{}})
				return err
			},
		},
		{
			Version: migVNodeStatus,
			Name:    "node_status_machine",
			Rollback: "safe to drop. The panel falls back to the single healthy bit, which cannot " +
				"tell an install in progress from a dead node — and every node stops being " +
				"refusable: a node an operator disabled starts receiving config bundles again.",
			Up: func(tx *gorm.DB) error {
				if _, err := alignSchema(tx, []any{&Node{}}); err != nil {
					return err
				}
				// BACKFILL. Adding the column stamps every existing row with
				// the same default, so an established fleet would come out of
				// the migration with every node — including ones that have been
				// serving for months — recorded as mid-install. The API derives
				// the state on every read and would hide that, but the column is
				// also what a backup carries and what anything querying the
				// store directly sees, and a stored value that contradicts the
				// served one is the seed of the next "the panel says two
				// different things" bug.
				//
				// LastSeen is the only evidence available here: a node that has
				// reported was connected as of that moment. If it has since gone
				// quiet the read path calls it an error on the next list, so
				// this only has to be right about the past.
				//
				// Scoped to rows this migration could itself have produced, so a
				// re-run cannot overwrite a state the panel has since decided.
				if err := tx.Model(&Node{}).
					Where("status IS NULL OR status = ? OR status = ?", "", string(NodeConnecting)).
					Where("last_seen IS NOT NULL").
					Update("status", string(NodeConnected)).Error; err != nil {
					return err
				}
				// A dialect that adds the column without applying the default
				// leaves NULLs behind, which is not one of the four states.
				return tx.Model(&Node{}).
					Where("status IS NULL OR status = ?", "").
					Update("status", string(NodeConnecting)).Error
			},
		},
		{
			Version: migVSubTelemetry,
			Name:    "subscription_fetch_telemetry",
			Rollback: "safe to drop: nothing references sub_requests, and the two user columns are " +
				"read-only reporting. The panel goes back to being unable to say whether a " +
				"subscription URL has ever been fetched.",
			Up: func(tx *gorm.DB) error {
				// No backfill: there is no historical data to recover, and a NULL
				// sub_updated_at correctly reads as "never fetched".
				_, err := alignSchema(tx, []any{&User{}, &SubRequest{}})
				return err
			},
		},
		{
			Version: migVUserTemplates,
			Name:    "user_templates",
			Rollback: "safe to drop: nothing references it and no user row points at a template — a " +
				"plan is a stamp applied at creation, not a live binding. Dropping it forgets every " +
				"saved plan; the accounts created from one keep their limits and are unaffected.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&UserTemplate{}})
				return err
			},
		},
		{
			Version: migVCorePins,
			Name:    "core_pins",
			Rollback: "safe to drop: no other table references it. Every operator-selected core " +
				"version is forgotten and the panel falls back to the versions this build shipped " +
				"with, which is what it did before this migration.",
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&CorePin{}})
				return err
			},
		},
		{
			Version: migVEdgeSelfManage,
			Name:    "edge_self_manage",
			Rollback: "safe to drop. `forgectl edge update` then stops re-sending the " +
				"CF_API_TOKEN/CF_ACCOUNT_ID bindings, and the Worker's own Deployment panel " +
				"goes back to \"no Cloudflare credential bound\" on the next update.",
			// No backfill: false is right for every existing row, because until
			// this column existed nothing had ever bound the credential.
			Up: func(tx *gorm.DB) error {
				_, err := alignSchema(tx, []any{&EdgeDeployment{}})
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

// SchemaVersion is the highest migration recorded against THIS database.
//
// It is what a backup records about itself: migration versions are append-only
// and strictly ascending, so they compare meaningfully across builds in a way a
// version string does not. A database with no ledger returns 0, which reads as
// "older than anything", and that is the safe direction for a restore.
func (s *Store) SchemaVersion() (uint64, error) {
	recs, err := migrate.MigrationStatus(s.db)
	if err != nil {
		return 0, err
	}
	var max uint64
	for _, r := range recs {
		if r.Version > max {
			max = r.Version
		}
	}
	return max, nil
}
