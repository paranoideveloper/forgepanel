package store

import (
	"time"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// AdminRepository defines admin persistence operations.
type AdminRepository interface {
	CreateAdmin(a *Admin) error
	AdminByUsername(u string) (*Admin, error)
	CountAdmins() (int64, error)
	SaveAdmin(a *Admin) error
	AdminByID(id uint) (*Admin, error)
	SetAdminRecoveryCodes(adminID uint, hashesJSON string) error
	BumpAdminSessionEpoch(id uint) error
	AdminSessionEpoch(id uint) (uint, error)
	ClaimTOTPStep(adminID uint, step int64) (bool, error)
	ConsumeRecoveryCode(adminID uint, matches func(hash string) bool) (used bool, remaining int, err error)
}

// InboundRepository defines inbound persistence operations.
type InboundRepository interface {
	CreateInbound(n *model.Node) (*Inbound, error)
	ListInbounds() ([]Inbound, error)
	InboundByID(id uint) (*Inbound, error)
	DeleteInbound(id uint) error
	SaveInbound(in *Inbound) error
}

// GroupRepository defines group persistence operations.
type GroupRepository interface {
	CreateGroup(g *Group) error
	ListGroups() ([]Group, error)
	GroupByID(id uint) (*Group, error)
	DeleteGroupSafely(groupID, reassignTo uint, allowOrphan bool) (moved int64, err error)
	SetDefaultGroup(groupID uint) error
	DefaultGroup() *Group
	UpdateGroupFields(groupID uint, fields map[string]any, ifUnchanged time.Time) error
	UsersInGroup(groupID uint) (int64, error)
}

// UserRepository defines user/client persistence operations.
type UserRepository interface {
	CreateUser(u *User) error
	ListUsers(ownerID uint) ([]User, error)
	UserByID(id uint) (*User, error)
	UserBySubToken(tok string) (*User, error)
	SaveUser(u *User) error
	UpdateUserFields(userID uint, fields map[string]any, ifUnchanged time.Time) error
	DeleteUserCascade(userID uint) error
	UserAssignments(userID uint) (*Assignments, error)
	SetUserInbounds(userID uint, ids []uint, allowed map[uint]bool) error
	InboundsForUser(userID uint) ([]uint, error)
	RecordSubRequest(r *SubRequest) error
	ListSubRequests(userID uint, limit, offset int) ([]SubRequest, int64, error)
}

// NodeRepository defines node agent persistence operations.
type NodeRepository interface {
	CreateNode(n *Node) error
	ListNodes() ([]Node, error)
	NodeByID(id uint) (*Node, error)
	NodeByToken(token string) (*Node, error)
	SaveNode(n *Node) error
	DeleteNode(id uint) error
}

// ZoneRepository defines ForgeDNS zone persistence operations.
type ZoneRepository interface {
	CreateZone(z *ForgeDNSZone) error
	ListZones() ([]ForgeDNSZone, error)
	ZoneByID(id uint) (*ForgeDNSZone, error)
	SaveZone(z *ForgeDNSZone) error
	DeleteZone(id uint) error
}

// SettingRepository is the key/value settings table. It is stated as an
// interface so *Store satisfies settings.KV by contract rather than by
// coincidence: the settings registry is built on exactly these two methods, and
// a rename here should break the build, not the panel.
type SettingRepository interface {
	GetSetting(key string) string
	SetSetting(key, value string) error
}

// Interface combines all repository interfaces for complete store operations.
type Interface interface {
	AdminRepository
	InboundRepository
	GroupRepository
	UserRepository
	NodeRepository
	ZoneRepository
	SettingRepository
}

// Ensure *Store implements Interface at compile time.
var _ Interface = (*Store)(nil)

// SchedulerStore is the persistence internal/job needs — exactly the eleven
// methods the scheduler calls, and nothing else.
//
// It is deliberately flat rather than composed from UserRepository: the
// scheduler uses five of that interface's ten user methods, and an interface
// that demands five methods its only consumer never calls is one no alternative
// backend can honestly implement — the fake ends up embedding a nil interface
// and panicking on the first unstubbed call. wgpeer.Repo
// (internal/wgpeer/manager.go) is the model followed here: the methods the
// caller calls, named by the caller's need.
//
// The point of this type is internal/job/scheduler.go, whose Scheduler.db and
// Config.DB are typed as it. Interface above has had a compile assert since the
// day it was written and not one consumer, which is what an interface no
// consumer's field names is worth. If this type ever loses its consumer, delete
// it rather than leave it as decoration.
type SchedulerStore interface {
	// Lifecycle sweep: on-hold activation, expiry, periodic usage reset,
	// IP-limit enforcement.
	ListUsers(ownerID uint) ([]User, error)
	UserByID(id uint) (*User, error)
	SaveUser(u *User) error
	UpdateUserFields(userID uint, fields map[string]any, ifUnchanged time.Time) error
	ResetUserUsageCAS(userID uint, periodStart, now time.Time) (bool, error)

	// Traffic accounting against the stored cumulative snapshot.
	TrafficSnapshots(scope string) (map[string]int64, error)
	SetTrafficSnapshot(scope, key string, value int64) error
	ApplyTrafficDeltaAt(scope, key string, userID uint, delta, cumulative int64, split TrafficSplit, at time.Time, stamp func(*User)) (used int64, limited bool, err error)

	// Housekeeping: the backup manifest's schema stamp and the two retention
	// pruners.
	SchemaVersion() (uint64, error)
	PruneRollups(hourlyBefore, dailyBefore time.Time) (int64, error)
	PruneAuditLogs(before time.Time) (int64, error)
}

// Ensure *Store implements SchedulerStore at compile time. Unlike the assert
// above, this one is backed by a consumer whose field names the type.
var _ SchedulerStore = (*Store)(nil)
