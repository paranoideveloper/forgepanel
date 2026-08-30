package store

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// This file adds DIRECT user→inbound assignment alongside the existing
// group→inbound one, plus the edit and safe-delete operations the panel needs.
//
// Before this, a user's inbounds came only from their group, so correcting one
// user's access meant editing the group (and therefore everybody else in it) or
// recreating the user. A user now has:
//
//	direct    — assigned to this user specifically (UserInbound rows)
//	inherited — from the user's group (Group.InboundIDs)
//	effective — the union, which is what subscriptions render
//
// The distinction is preserved everywhere rather than flattened, because
// "remove this inbound" means something different for each: a direct assignment
// is the user's to drop, an inherited one belongs to the group and removing it
// there affects every member.

// UserInbound is one direct user→inbound assignment. The composite primary key
// makes duplicate assignments impossible at the schema level rather than relying
// on the caller to check first.
type UserInbound struct {
	UserID    uint      `gorm:"primaryKey;index:idx_user_inbound_user" json:"user_id"`
	InboundID uint      `gorm:"primaryKey;index:idx_user_inbound_inbound" json:"inbound_id"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName pins the table name so it reads clearly in migrations.
func (UserInbound) TableName() string { return "user_inbounds" }

// GroupInbound is one group→inbound binding, mirroring Group.InboundIDs.
//
// That column is a comma-separated TEXT list with no foreign key and no index,
// so the reverse question — which groups reference inbound N — could only be
// answered by loading every group and filtering in Go, and nothing stopped the
// list naming an inbound that had been deleted. This table answers it with an
// index and lets a delete cascade reach it.
//
// The text column stays as the source of truth for at least one release: a
// half-deployed panel, or one rolled back, still resolves subscriptions from it.
// This is an indexed mirror plus the reverse query, not a replacement — which is
// why every writer of the column has to write here too, in the same transaction.
type GroupInbound struct {
	GroupID   uint      `gorm:"primaryKey;index:idx_group_inbound_group" json:"group_id"`
	InboundID uint      `gorm:"primaryKey;index:idx_group_inbound_inbound" json:"inbound_id"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName pins the table name so it reads clearly in migrations.
func (GroupInbound) TableName() string { return "group_inbounds" }

// setGroupInbounds replaces a group's join rows inside an existing transaction.
// Callers pass the same slice they write to Group.InboundIDs, so the two cannot
// diverge within one write.
func setGroupInbounds(tx *gorm.DB, groupID uint, ids IntSlice) error {
	if err := tx.Where("group_id = ?", groupID).Delete(&GroupInbound{}).Error; err != nil {
		return err
	}
	seen := map[uint]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		if err := tx.Create(&GroupInbound{GroupID: groupID, InboundID: id}).Error; err != nil {
			return err
		}
	}
	return nil
}

// GroupsForInbound reports which groups reference an inbound, in id order.
//
// This is the query the text column could not serve. cascade.go answered it by
// loading every group and filtering in Go; on a panel with many groups that is a
// full table read for a question asked on every inbound delete.
func (s *Store) GroupsForInbound(inboundID uint) ([]uint, error) {
	var out []uint
	err := s.db.Model(&GroupInbound{}).
		Where("inbound_id = ?", inboundID).
		Order("group_id").
		Pluck("group_id", &out).Error
	return out, err
}

// ErrStaleWrite reports that a record changed between the caller reading it and
// writing it back, so the write was refused rather than silently discarding the
// other edit.
var ErrStaleWrite = errors.New("store: record was modified by someone else; reload and try again")

// ErrGroupInUse reports that a group still has members and no disposition for
// them was given.
var ErrGroupInUse = errors.New("store: group still has members")

// Assignments is a user's inbound access, split by where it comes from.
type Assignments struct {
	Direct    []uint `json:"direct"`
	Inherited []uint `json:"inherited"`
	Effective []uint `json:"effective"`
	GroupID   uint   `json:"group_id"`
	GroupName string `json:"group_name,omitempty"`
}

// UserAssignments resolves a user's direct, inherited and effective inbounds.
func (s *Store) UserAssignments(userID uint) (*Assignments, error) {
	u, err := s.UserByID(userID)
	if err != nil {
		return nil, err
	}
	out := &Assignments{GroupID: u.GroupID}

	var rows []UserInbound
	if err := s.db.Where("user_id = ?", userID).Order("inbound_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	seen := map[uint]bool{}
	for _, r := range rows {
		if !seen[r.InboundID] {
			seen[r.InboundID] = true
			out.Direct = append(out.Direct, r.InboundID)
			out.Effective = append(out.Effective, r.InboundID)
		}
	}

	// A user with no group is a valid, persistent state — not an error.
	if u.GroupID != 0 {
		if g, err := s.GroupByID(u.GroupID); err == nil {
			out.GroupName = g.Name
			for _, id := range g.InboundIDs {
				out.Inherited = append(out.Inherited, id)
				if !seen[id] {
					seen[id] = true
					out.Effective = append(out.Effective, id)
				}
			}
		}
	}
	return out, nil
}

// SetUserInbounds replaces a user's DIRECT assignments with ids, transactionally.
// Inherited group inbounds are untouched: they are not the user's to remove.
// allowed, when non-nil, is the set of inbound IDs the caller may assign — every
// id is checked against it here, in the repository, rather than trusting the
// list the UI rendered.
func (s *Store) SetUserInbounds(userID uint, ids []uint, allowed map[uint]bool) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, userID).Error; err != nil {
			return err
		}
		// De-duplicate and validate before writing anything.
		want, err := validInboundIDs(tx, ids, allowed)
		if err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userID).Delete(&UserInbound{}).Error; err != nil {
			return err
		}
		for _, id := range want {
			if err := tx.Create(&UserInbound{UserID: userID, InboundID: id}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// validInboundIDs de-duplicates ids and refuses any that is outside allowed or
// does not exist, INSIDE the caller's transaction.
//
// It is a function rather than a loop inlined in SetUserInbounds because a
// second writer of user_inbounds now exists (ApplyTemplateToUser). A saved plan
// that skipped these two checks would be a way to hand a user an inbound the
// caller could not have assigned by hand — the scope check would be enforced on
// the manual path and bypassed on the one the operator actually uses.
func validInboundIDs(tx *gorm.DB, ids []uint, allowed map[uint]bool) ([]uint, error) {
	want := make([]uint, 0, len(ids))
	seen := map[uint]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		if allowed != nil && !allowed[id] {
			return nil, fmt.Errorf("%w: inbound %d", ErrForbiddenRef, id)
		}
		var cnt int64
		if err := tx.Model(&Inbound{}).Where("id = ?", id).Count(&cnt).Error; err != nil {
			return nil, err
		}
		if cnt == 0 {
			return nil, fmt.Errorf("store: inbound %d does not exist", id)
		}
		seen[id] = true
		want = append(want, id)
	}
	return want, nil
}

// ErrForbiddenRef reports that a request referenced an object outside the
// caller's scope. It is returned from the repository layer so the check cannot be
// bypassed by calling a different handler.
var ErrForbiddenRef = errors.New("store: object is outside the caller's scope")

// UsersInGroup counts a group's members, so the UI can show the blast radius of
// a group edit before it is applied.
func (s *Store) UsersInGroup(groupID uint) (int64, error) {
	var n int64
	err := s.db.Model(&User{}).Where("group_id = ?", groupID).Count(&n).Error
	return n, err
}

// UpdateUserFields applies a whitelisted set of column updates to a user, with an
// optimistic-concurrency check against the caller's copy of updated_at. Passing a
// zero ifUnchanged skips the check (for callers that did not read first).
//
// Taking explicit columns rather than saving a whole struct is deliberate: a
// full-struct save would write back every field the caller happened to hold,
// silently clobbering concurrent edits to fields they never intended to touch.
func (s *Store) UpdateUserFields(userID uint, fields map[string]any, ifUnchanged time.Time) error {
	if len(fields) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, userID).Error; err != nil {
			return err
		}
		if !ifUnchanged.IsZero() && !u.UpdatedAt.Truncate(time.Second).Equal(ifUnchanged.Truncate(time.Second)) {
			return ErrStaleWrite
		}
		if gid, ok := fields["group_id"]; ok {
			id, _ := toUint(gid)
			if id != 0 {
				var cnt int64
				if err := tx.Model(&Group{}).Where("id = ?", id).Count(&cnt).Error; err != nil {
					return err
				}
				if cnt == 0 {
					return fmt.Errorf("store: group %d does not exist", id)
				}
			}
		}
		return tx.Model(&User{}).Where("id = ?", userID).Updates(fields).Error
	})
}

// UpdateGroupFields applies whitelisted column updates to a group with the same
// optimistic-concurrency check.
func (s *Store) UpdateGroupFields(groupID uint, fields map[string]any, ifUnchanged time.Time) error {
	if len(fields) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var g Group
		if err := tx.First(&g, groupID).Error; err != nil {
			return err
		}
		if !ifUnchanged.IsZero() && !g.UpdatedAt.Truncate(time.Second).Equal(ifUnchanged.Truncate(time.Second)) {
			return ErrStaleWrite
		}
		if ids, ok := fields["inbound_ids"]; ok {
			slice, _ := ids.(IntSlice)
			for _, id := range slice {
				var cnt int64
				if err := tx.Model(&Inbound{}).Where("id = ?", id).Count(&cnt).Error; err != nil {
					return err
				}
				if cnt == 0 {
					return fmt.Errorf("store: inbound %d does not exist", id)
				}
			}
		}
		if err := tx.Model(&Group{}).Where("id = ?", groupID).Updates(fields).Error; err != nil {
			return err
		}
		// Same transaction as the column write. This is the PATCH path the panel
		// uses for every membership change, so a join table not maintained here
		// is a join table that is wrong for every group after its first edit.
		if ids, ok := fields["inbound_ids"]; ok {
			slice, _ := ids.(IntSlice)
			return setGroupInbounds(tx, groupID, slice)
		}
		return nil
	})
}

// DeleteGroupSafely removes a group without ever deleting its members. Members
// are moved to reassignTo, or to "no group" when reassignTo is 0. If the group
// has members and allowOrphan is false, the delete is refused so the caller must
// make the disposition explicit.
func (s *Store) DeleteGroupSafely(groupID, reassignTo uint, allowOrphan bool) (moved int64, err error) {
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if e := tx.Model(&User{}).Where("group_id = ?", groupID).Count(&n).Error; e != nil {
			return e
		}
		if n > 0 && !allowOrphan && reassignTo == 0 {
			return fmt.Errorf("%w: %d member(s)", ErrGroupInUse, n)
		}
		if reassignTo != 0 {
			var cnt int64
			if e := tx.Model(&Group{}).Where("id = ?", reassignTo).Count(&cnt).Error; e != nil {
				return e
			}
			if cnt == 0 {
				return fmt.Errorf("store: target group %d does not exist", reassignTo)
			}
		}
		if n > 0 {
			// Members are moved, never deleted. Losing a group must not lose the
			// accounts that belonged to it.
			if e := tx.Model(&User{}).Where("group_id = ?", groupID).
				Update("group_id", reassignTo).Error; e != nil {
				return e
			}
			moved = n
		}
		// Its join rows go with it. A group row deleted while its mirror rows
		// remain leaves GroupsForInbound naming a group that does not exist.
		if err := tx.Where("group_id = ?", groupID).Delete(&GroupInbound{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Group{}, groupID).Error
	})
	return moved, err
}

// SetDefaultGroup makes one group the default (or clears the flag everywhere
// when groupID is 0), keeping "at most one default" true as a single
// transaction. The default is only ever a pre-selection in the create form; it
// is never applied behind the administrator's back.
func (s *Store) SetDefaultGroup(groupID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Group{}).Where("is_default = ?", true).
			Update("is_default", false).Error; err != nil {
			return err
		}
		if groupID == 0 {
			return nil
		}
		res := tx.Model(&Group{}).Where("id = ?", groupID).Update("is_default", true)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("store: group %d does not exist", groupID)
		}
		return nil
	})
}

// DefaultGroup returns the default group, or nil when none is set.
func (s *Store) DefaultGroup() *Group {
	var g Group
	if err := s.db.Where("is_default = ?", true).First(&g).Error; err != nil {
		return nil
	}
	return &g
}

// InboundsForUser returns the effective inbound IDs a user may connect through.
// This is what subscriptions render.
func (s *Store) InboundsForUser(userID uint) ([]uint, error) {
	a, err := s.UserAssignments(userID)
	if err != nil {
		return nil, err
	}
	return a.Effective, nil
}

// toUint coerces the numeric shapes JSON decoding can produce.
func toUint(v any) (uint, bool) {
	switch n := v.(type) {
	case uint:
		return n, true
	case int:
		return uint(n), true
	case int64:
		return uint(n), true
	case float64:
		return uint(n), true
	}
	return 0, false
}
