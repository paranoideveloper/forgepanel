package store

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// Store wraps the GORM DB and exposes typed repositories.
type Store struct {
	db *gorm.DB
}

// Open opens (pure-Go) SQLite at path and auto-migrates. A dsn of ":memory:"
// yields an ephemeral DB, used by tests.
func Open(path string) (*Store, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.AutoMigrate(AllModels()...); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// DB exposes the underlying handle for advanced queries.
func (s *Store) DB() *gorm.DB { return s.db }

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

// DeleteInbound removes an inbound.
func (s *Store) DeleteInbound(id uint) error { return s.db.Delete(&Inbound{}, id).Error }

// --- groups & users -------------------------------------------------------

// CreateGroup persists a group.
func (s *Store) CreateGroup(g *Group) error { return s.db.Create(g).Error }

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

// UserByID fetches one user.
func (s *Store) UserByID(id uint) (*User, error) {
	var u User
	return &u, s.db.First(&u, id).Error
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id uint) error { return s.db.Delete(&User{}, id).Error }

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

// DeleteNode removes a node.
func (s *Store) DeleteNode(id uint) error { return s.db.Delete(&Node{}, id).Error }

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
