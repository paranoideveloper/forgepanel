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

// Interface combines all repository interfaces for complete store operations.
type Interface interface {
	AdminRepository
	InboundRepository
	GroupRepository
	UserRepository
	NodeRepository
	ZoneRepository
}

// Ensure *Store implements Interface at compile time.
var _ Interface = (*Store)(nil)
