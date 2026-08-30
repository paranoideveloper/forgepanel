package store

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Store wraps the GORM DB and exposes typed repositories.
type Store struct {
	db        *gorm.DB
	closeOnce sync.Once
	closeErr  error
}

// Open opens (pure-Go) SQLite at path and brings it up to the current schema
// version through the ordered migration registry in migrations.go. A dsn of
// ":memory:" yields an ephemeral DB, used by tests.
func Open(path string) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := Migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// DB exposes the underlying handle for advanced queries.
func (s *Store) DB() *gorm.DB { return s.db }

// Close releases the SQLite connection pool. It is safe to call more than once.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		db, err := s.db.DB()
		if err != nil {
			s.closeErr = err
			return
		}
		s.closeErr = db.Close()
	})
	return s.closeErr
}

// --- admins ---------------------------------------------------------------

// CreateAdmin inserts an admin.
func (s *Store) CreateAdmin(a *Admin) error { return s.db.Create(a).Error }

// AdminByUsername looks up an admin by username.
func (s *Store) AdminByUsername(u string) (*Admin, error) {
	var a Admin
	if err := s.db.Where("username = ?", u).First(&a).Error; err != nil {
		return nil, err
	}
	return &a, nil
}

// CountAdmins returns how many admins exist (used to detect first boot).
func (s *Store) CountAdmins() (int64, error) {
	var n int64
	return n, s.db.Model(&Admin{}).Count(&n).Error
}

// --- inbounds -------------------------------------------------------------

// CreateInbound persists a canonical node as an inbound.
func (s *Store) CreateInbound(n *model.Node) (*Inbound, error) {
	var in Inbound
	in.Enabled = true
	if err := in.SetNode(n); err != nil {
		return nil, err
	}
	if err := s.db.Create(&in).Error; err != nil {
		return nil, err
	}
	return &in, nil
}

// ListInbounds returns all inbounds.
func (s *Store) ListInbounds() ([]Inbound, error) {
	var out []Inbound
	return out, s.db.Order("id").Find(&out).Error
}

// InboundByID fetches one inbound.
func (s *Store) InboundByID(id uint) (*Inbound, error) {
	var in Inbound
	return &in, s.db.First(&in, id).Error
}

// SaveInbound updates an inbound.
// SaveInbound creates or updates an inbound.
//
// Creating one with Enabled:false silently stored it as ENABLED, so a caller
// that asked for a disabled inbound got a live listener. Inbound.Enabled carries
// `gorm:"default:true"`, and GORM omits a zero-valued field on INSERT when its
// column declares a default. Select("*") does NOT override that — measured — and
// GORM additionally writes the applied default back into the struct, which is
// why the intent must be captured before the call. The UPDATE path writes every
// field and was never affected.
func (s *Store) SaveInbound(in *Inbound) error {
	if in.ID == 0 {
		// The caller's intent has to be captured BEFORE the insert. GORM omits a
		// zero-valued field on INSERT when its column declares a default, and
		// then writes the applied default BACK into the struct — so by the time
		// Create returns, in.Enabled reads true whatever the caller passed, and
		// the original request is gone.
		wantEnabled := in.Enabled
		if err := s.db.Create(in).Error; err != nil {
			return err
		}
		if !wantEnabled {
			in.Enabled = false
			return s.db.Model(&Inbound{}).Where("id = ?", in.ID).
				UpdateColumn("enabled", false).Error
		}
		return nil
	}
	return s.db.Save(in).Error
}

// UpdateInboundFields writes named columns only.
//
// A targeted update rather than SaveInbound: the caller here runs on every
// engine reload and holds an inbound it read moments ago, and saving the whole
// row would overwrite any concurrent edit an operator made in between with the
// stale copy.
func (s *Store) UpdateInboundFields(id uint, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	return s.db.Model(&Inbound{}).Where("id = ?", id).Updates(fields).Error
}

// --- groups & users -------------------------------------------------------

// CreateGroup persists a group and its inbound bindings.
//
// It was a one-line s.db.Create, which is exactly why it is the likeliest place
// for the join table to be left unwritten: the function reads as already done.
// Both writes are in one transaction, so a group can never exist with the column
// set and no join rows.
func (s *Store) CreateGroup(g *Group) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(g).Error; err != nil {
			return err
		}
		return setGroupInbounds(tx, g.ID, g.InboundIDs)
	})
}

// ListGroups returns all groups.
func (s *Store) ListGroups() ([]Group, error) {
	var out []Group
	return out, s.db.Order("id").Find(&out).Error
}

// GroupByID fetches one group.
func (s *Store) GroupByID(id uint) (*Group, error) {
	var g Group
	return &g, s.db.First(&g, id).Error
}

// CreateUser persists a user. OwnerAdminID scopes reseller visibility.
func (s *Store) CreateUser(u *User) error { return s.db.Create(u).Error }

// QuotaError signals that a reseller limit was hit. Handlers map it to a 409 so
// clients can distinguish an over-quota rejection from a generic failure.
type QuotaError struct {
	Reason string
	Limit  string // "user_quota" | "traffic_credit"
}

func (e *QuotaError) Error() string { return e.Reason }

// CreateUserEnforcingQuota creates u while enforcing the owning admin's reseller
// limits inside ONE transaction, so concurrent create requests cannot race past
// the cap (spec §4). Owners and admins have unlimited privileges and bypass the
// checks; for resellers, a limit of 0 means unlimited. Soft-deleted users no
// longer count, so deleting a user restores both its slot and its traffic
// allocation automatically.
func (s *Store) CreateUserEnforcingQuota(u *User, owner *Admin) error {
	if owner == nil || owner.Role == RoleOwner || owner.Role == RoleAdmin {
		return s.CreateUser(u)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if owner.UserQuota > 0 {
			var n int64
			if e := tx.Model(&User{}).Where("owner_admin_id = ?", owner.ID).Count(&n).Error; e != nil {
				return e
			}
			if n >= int64(owner.UserQuota) {
				return &QuotaError{Reason: fmt.Sprintf("user quota reached (%d/%d)", n, owner.UserQuota), Limit: "user_quota"}
			}
		}
		if owner.TrafficCredit > 0 {
			if u.DataLimit <= 0 {
				return &QuotaError{Reason: "a reseller with a traffic credit cannot allocate unlimited traffic to a user", Limit: "traffic_credit"}
			}
			var sum int64
			if e := tx.Model(&User{}).Where("owner_admin_id = ? AND data_limit > 0", owner.ID).
				Select("COALESCE(SUM(data_limit),0)").Scan(&sum).Error; e != nil {
				return e
			}
			if sum+u.DataLimit > owner.TrafficCredit {
				return &QuotaError{Reason: fmt.Sprintf("traffic credit exceeded: %d bytes requested, %d remaining", u.DataLimit, owner.TrafficCredit-sum), Limit: "traffic_credit"}
			}
		}
		return tx.Create(u).Error
	})
}

// ResetUserUsageCAS resets a user's period usage exactly once per period. It is a
// compare-and-set on LastResetAt: the reset only applies when the user has not
// already been reset for the period beginning at periodStart, so it is
// idempotent, recovers missed schedules after downtime (catching up to the
// current period on the next run), and is safe when multiple panel instances
// sweep concurrently. Lifetime traffic is preserved; a data-limited user that is
// not expired is reactivated. Returns whether a reset was applied.
func (s *Store) ResetUserUsageCAS(userID uint, periodStart, now time.Time) (bool, error) {
	applied := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var u User
		if e := tx.First(&u, userID).Error; e != nil {
			return e
		}
		if u.LastResetAt != nil && !u.LastResetAt.Before(periodStart) {
			return nil
		}
		u.LifetimeTraffic += u.UsedTraffic
		u.UsedTraffic = 0
		u.LastResetAt = &now
		if u.Status == StatusLimited && (u.ExpireAt == nil || now.Before(*u.ExpireAt)) {
			u.Status = StatusActive
		}
		applied = true
		return tx.Save(&u).Error
	})
	return applied, err
}

// ResellerUsage reports a reseller's current quota-counted user count and the
// total finite traffic allocated, for the remaining-quota display.
func (s *Store) ResellerUsage(ownerID uint) (users int64, allocated int64, err error) {
	if e := s.db.Model(&User{}).Where("owner_admin_id = ?", ownerID).Count(&users).Error; e != nil {
		return 0, 0, e
	}
	err = s.db.Model(&User{}).Where("owner_admin_id = ? AND data_limit > 0", ownerID).
		Select("COALESCE(SUM(data_limit),0)").Scan(&allocated).Error
	return users, allocated, err
}

// ListUsers returns users; if ownerID != 0 only that admin's users (reseller
// isolation enforced at the repository layer, spec §4).
func (s *Store) ListUsers(ownerID uint) ([]User, error) {
	var out []User
	q := s.db.Order("id")
	if ownerID != 0 {
		q = q.Where("owner_admin_id = ?", ownerID)
	}
	return out, q.Find(&out).Error
}

// UserBySubToken resolves the subscription token to a user.
func (s *Store) UserBySubToken(token string) (*User, error) {
	var u User
	if err := s.db.Where("sub_token = ?", token).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// UserByUsername fetches one user by name, using the unique index the column
// has always carried.
//
// The index existed; the query did not. Every caller that needed a user by name
// loaded the ENTIRE user table and walked it — the Telegram bot did it on every
// single command, twice for some of them, and its own comment said so ("there is
// no unique-username lookup on the store, so this scans"). On a panel with a few
// thousand users that is a few thousand rows decoded to answer a question SQLite
// can answer from the index without touching the table.
func (s *Store) UserByUsername(name string) (*User, error) {
	var u User
	if err := s.db.Where("username = ?", name).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// Counts returns the row counts the dashboard and the bot report.
//
// COUNT(*) per table, rather than loading three whole tables and taking len()
// of each — which is what the bot's /stats did, decoding every user, every
// inbound and every group to produce three integers.
func (s *Store) Counts() (inbounds, users, groups int64, err error) {
	if err = s.db.Model(&Inbound{}).Count(&inbounds).Error; err != nil {
		return 0, 0, 0, err
	}
	if err = s.db.Model(&User{}).Count(&users).Error; err != nil {
		return 0, 0, 0, err
	}
	if err = s.db.Model(&Group{}).Count(&groups).Error; err != nil {
		return 0, 0, 0, err
	}
	return inbounds, users, groups, nil
}

// UserByID fetches one user.
func (s *Store) UserByID(id uint) (*User, error) {
	var u User
	return &u, s.db.First(&u, id).Error
}

// SaveUser persists changes to a user.
func (s *Store) SaveUser(u *User) error { return s.db.Save(u).Error }

// --- settings & audit -----------------------------------------------------

// SetSetting upserts a key/value setting.
func (s *Store) SetSetting(key, value string) error {
	return s.db.Save(&Setting{Key: key, Value: value}).Error
}

// GetSetting reads a setting (empty string if absent).
func (s *Store) GetSetting(key string) string {
	var st Setting
	if err := s.db.First(&st, "key = ?", key).Error; err != nil {
		return ""
	}
	return st.Value
}

// Audit records a mutating action.
func (s *Store) Audit(a *AuditLog) { _ = s.db.Create(a).Error }

// --- IntSlice: a []uint stored as a comma-separated text column -----------

// IntSlice serialises a []uint into a text column so group→inbound bindings need
// no join table for the core build.
type IntSlice []uint

// Value implements driver.Valuer.
func (s IntSlice) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "", nil
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, ","), nil
}

// Scan implements sql.Scanner.
func (s *IntSlice) Scan(src any) error {
	*s = nil
	var str string
	switch v := src.(type) {
	case string:
		str = v
	case []byte:
		str = string(v)
	case nil:
		return nil
	default:
		return errors.New("IntSlice: unsupported scan type")
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return nil
	}
	for _, p := range strings.Split(str, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
		if err != nil {
			return err
		}
		*s = append(*s, uint(n))
	}
	return nil
}

func marshalNode(n *model.Node) (string, error) {
	b, err := json.Marshal(n)
	return string(b), err
}

func unmarshalNode(s string) (*model.Node, error) {
	var n model.Node
	if err := json.Unmarshal([]byte(s), &n); err != nil {
		return nil, err
	}
	n.Normalize()
	return &n, nil
}

// --- nodes ----------------------------------------------------------------

// CreateNode persists a node with its one-time enroll token.
func (s *Store) CreateNode(n *Node) error { return s.db.Create(n).Error }

// ListNodes returns all nodes.
func (s *Store) ListNodes() ([]Node, error) {
	var out []Node
	return out, s.db.Order("id").Find(&out).Error
}

// NodeByID resolves a node by ID.
func (s *Store) NodeByID(id uint) (*Node, error) {
	var n Node
	if err := s.db.First(&n, id).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// NodeByBootstrapHash resolves a hashed one-time bootstrap token to its node.
//
// The hash is what is stored: the token is spent once to obtain a certificate,
// and a database that has been read should not yield a working credential for
// every node in it.
func (s *Store) NodeByBootstrapHash(hash string) (*Node, error) {
	var n Node
	if hash == "" {
		return nil, gorm.ErrRecordNotFound
	}
	if err := s.db.Where("bootstrap_hash = ?", hash).First(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// NodeByToken resolves an enroll/auth token to a node.
func (s *Store) NodeByToken(token string) (*Node, error) {
	var n Node
	if err := s.db.Where("enroll_token = ?", token).First(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// SaveNode persists node changes.
func (s *Store) SaveNode(n *Node) error { return s.db.Save(n).Error }

// --- forgedns zones -------------------------------------------------------

// CreateZone persists a ForgeDNS zone.
func (s *Store) CreateZone(z *ForgeDNSZone) error { return s.db.Create(z).Error }

// ListZones returns all ForgeDNS zones.
func (s *Store) ListZones() ([]ForgeDNSZone, error) {
	var out []ForgeDNSZone
	return out, s.db.Order("id").Find(&out).Error
}

// ZoneByID fetches one zone.
func (s *Store) ZoneByID(id uint) (*ForgeDNSZone, error) {
	var z ForgeDNSZone
	return &z, s.db.First(&z, id).Error
}

// SaveZone persists zone changes.
func (s *Store) SaveZone(z *ForgeDNSZone) error { return s.db.Save(z).Error }

// DeleteZone removes a zone.
func (s *Store) DeleteZone(id uint) error { return s.db.Delete(&ForgeDNSZone{}, id).Error }

// SaveAdmin persists admin changes.
func (s *Store) SaveAdmin(a *Admin) error { return s.db.Save(a).Error }

// AdminByID looks up an admin by primary key.
func (s *Store) AdminByID(id uint) (*Admin, error) {
	var a Admin
	if err := s.db.First(&a, id).Error; err != nil {
		return nil, err
	}
	return &a, nil
}

// SetAdminRecoveryCodes replaces an admin's stored recovery-code hashes.
func (s *Store) SetAdminRecoveryCodes(adminID uint, hashesJSON string) error {
	return s.db.Model(&Admin{}).Where("id = ?", adminID).Update("recovery_codes", hashesJSON).Error
}

// BumpAdminSessionEpoch invalidates every token already issued to an admin by
// advancing the epoch stamped into them. Used when the account's authentication
// state changes under recovery conditions (recovery-code login, 2FA disabled,
// password changed), so a session an attacker already holds does not survive the
// owner recovering the account.
func (s *Store) BumpAdminSessionEpoch(adminID uint) error {
	return s.db.Model(&Admin{}).Where("id = ?", adminID).
		UpdateColumn("session_epoch", gorm.Expr("session_epoch + 1")).Error
}

// AdminSessionEpoch reads an admin's current session epoch, for token validation.
func (s *Store) AdminSessionEpoch(adminID uint) (uint, error) {
	var a Admin
	if err := s.db.Select("session_epoch").First(&a, adminID).Error; err != nil {
		return 0, err
	}
	return a.SessionEpoch, nil
}

// ClaimTOTPStep records a successfully verified TOTP time step, refusing to
// re-record a step at or below the one already stored. The compare-and-set runs
// as a single conditional UPDATE so two concurrent logins presenting the same
// intercepted code cannot both succeed.
func (s *Store) ClaimTOTPStep(adminID uint, step int64) (bool, error) {
	res := s.db.Model(&Admin{}).
		Where("id = ? AND (last_totp_step IS NULL OR last_totp_step < ?)", adminID, step).
		UpdateColumn("last_totp_step", step)
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}

// ConsumeRecoveryCode atomically removes one matching recovery-code hash from an
// admin and reports whether it was present. The read-check-write runs in a
// transaction so two concurrent logins can never both spend the same code
// (single-use guarantee, spec §12). remaining is the count left after consuming.
func (s *Store) ConsumeRecoveryCode(adminID uint, matches func(hash string) bool) (used bool, remaining int, err error) {
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// The transaction serializes the read-modify-write; on SQLite the write
		// lock is exclusive, so two concurrent consumers can't both spend a code.
		var a Admin
		if e := tx.First(&a, adminID).Error; e != nil {
			return e
		}
		var hashes []string
		if a.RecoveryCodes != "" {
			if e := json.Unmarshal([]byte(a.RecoveryCodes), &hashes); e != nil {
				hashes = nil
			}
		}
		kept := hashes[:0:0]
		for _, h := range hashes {
			if !used && matches(h) {
				used = true
				continue
			}
			kept = append(kept, h)
		}
		remaining = len(kept)
		if !used {
			return nil
		}
		raw, _ := json.Marshal(kept)
		return tx.Model(&Admin{}).Where("id = ?", adminID).Update("recovery_codes", string(raw)).Error
	})
	return used, remaining, err
}
