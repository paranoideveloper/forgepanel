package store

import (
	"fmt"

	"gorm.io/gorm"
)

// This file owns referential cleanup on delete.
//
// ForgePanel's tables carry no database-level foreign keys — SQLite only
// enforces them when PRAGMA foreign_keys is on, and the group→inbound binding is
// a comma-separated text column that no FK could cover anyway — so every
// reference has to be cleaned up by hand. Deleting an inbound used to leave the
// user_inbounds join rows and the group binding pointing at it. The damage is
// silent and cumulative: a subscription keeps resolving through an inbound that
// no longer exists, and because SQLite hands out the lowest free rowid, the next
// inbound created can inherit the dead inbound's users outright.
//
// Every delete below therefore runs as one transaction: the referencing rows and
// the row itself go together, or nothing goes.

// DeleteInbound removes an inbound together with every reference to it: the
// direct user→inbound assignments, and the id inside each group's binding list.
// A missing id is not an error — the caller's intent (that inbound is gone) is
// already satisfied — which keeps a retried delete safe.
func (s *Store) DeleteInbound(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error { return deleteInboundTx(tx, id) })
}

func deleteInboundTx(tx *gorm.DB, id uint) error {
	if id == 0 {
		return nil
	}
	if err := tx.Where("inbound_id = ?", id).Delete(&UserInbound{}).Error; err != nil {
		return fmt.Errorf("delete inbound %d assignments: %w", id, err)
	}
	if err := detachInboundFromGroups(tx, id); err != nil {
		return err
	}
	// The join rows go with it too. detachInboundFromGroups above rewrites the
	// text column; leaving the mirror behind would make GroupsForInbound answer
	// with a group that no longer references this inbound — confidently, from an
	// index. Same shape as the assignment leak this function already fixes.
	if err := tx.Where("inbound_id = ?", id).Delete(&GroupInbound{}).Error; err != nil {
		return fmt.Errorf("delete inbound %d group bindings: %w", id, err)
	}
	// The inbound's public endpoints go with it, inside the same transaction.
	// An orphaned host row publishes nothing and would be inherited outright by
	// whatever inbound next takes that id — SQLite hands out the lowest free
	// rowid, which is the same mechanism that made the assignment leak above
	// worth fixing.
	if err := tx.Where("inbound_id = ?", id).Delete(&InboundHost{}).Error; err != nil {
		return fmt.Errorf("delete inbound %d hosts: %w", id, err)
	}
	return tx.Delete(&Inbound{}, id).Error
}

// detachInboundFromGroups strips id out of every group's binding list. The list
// is a text column, so it has to be read and rewritten rather than deleted from;
// groups that do not reference the inbound are left untouched so their
// updated_at (which the UI shows as "last edited") is not disturbed.
func detachInboundFromGroups(tx *gorm.DB, id uint) error {
	var groups []Group
	if err := tx.Find(&groups).Error; err != nil {
		return fmt.Errorf("read groups: %w", err)
	}
	for i := range groups {
		kept, changed := withoutInboundID(groups[i].InboundIDs, id)
		if !changed {
			continue
		}
		if err := tx.Model(&Group{}).Where("id = ?", groups[i].ID).
			Update("inbound_ids", kept).Error; err != nil {
			return fmt.Errorf("detach inbound %d from group %d: %w", id, groups[i].ID, err)
		}
	}
	return nil
}

// withoutInboundID returns ids with drop removed, and whether anything changed.
func withoutInboundID(ids IntSlice, drop uint) (IntSlice, bool) {
	kept := make(IntSlice, 0, len(ids))
	changed := false
	for _, id := range ids {
		if id == drop {
			changed = true
			continue
		}
		kept = append(kept, id)
	}
	return kept, changed
}

// DeleteUser removes a user and everything keyed to them. It is the cascading
// delete: there is deliberately no non-cascading variant, because a caller that
// forgets to clean up is exactly how the orphan rows accumulated.
func (s *Store) DeleteUser(id uint) error { return s.DeleteUserCascade(id) }

// DeleteUserCascade removes a user, their direct inbound assignments and their
// per-node traffic baselines in one transaction, so no orphan survives to be
// re-applied to a recycled id.
func (s *Store) DeleteUserCascade(userID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error { return deleteUserTx(tx, userID) })
}

func deleteUserTx(tx *gorm.DB, userID uint) error {
	if userID == 0 {
		return nil
	}
	// The traffic baselines are keyed by the user's counter tag ("u<ID>"), and
	// SQLite hands out the LOWEST free rowid — so a user created after this one
	// is deleted can be given the same id. Leaving the baseline behind would
	// make that new account inherit a large stale counter: its first real
	// traffic computes a delta of zero, and it transfers free until its own
	// usage passes the dead account's total. Sweeping across every scope also
	// covers the per-node baselines, which are separate rows.
	if e := tx.Where("key = ?", UserCounterKey(userID)).Delete(&TrafficSnapshot{}).Error; e != nil {
		return fmt.Errorf("delete user %d traffic baselines: %w", userID, e)
	}
	if err := tx.Where("user_id = ?", userID).Delete(&UserInbound{}).Error; err != nil {
		return fmt.Errorf("delete user %d assignments: %w", userID, err)
	}
	return tx.Delete(&User{}, userID).Error
}

// DeleteNode removes a node, its per-user traffic baselines, and the pointer any
// inbound still holds to it.
//
// Inbounds are deliberately NOT deleted with the node: an inbound carries its
// own address and survives its node being decommissioned (that is what
// service.MigrateNodeInbounds relies on). What must not survive is the dangling
// node_id — the panel resolves an inbound's public address through it, so a
// recycled node id would silently re-point live subscriptions at a different
// machine. Clearing it makes the inbound fall back to its own stored address.
func (s *Store) DeleteNode(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error { return deleteNodeTx(tx, id) })
}

func deleteNodeTx(tx *gorm.DB, id uint) error {
	if id == 0 {
		return nil
	}
	// Every baseline this node reported against. A node re-enrolled onto the
	// same id would otherwise be measured from the dead node's totals, and its
	// first heartbeats would count as nothing.
	if err := tx.Where("scope = ?", NodeScope(id)).Delete(&TrafficSnapshot{}).Error; err != nil {
		return fmt.Errorf("delete node %d traffic baselines: %w", id, err)
	}
	if err := tx.Model(&Inbound{}).Where("node_id = ?", id).
		Update("node_id", 0).Error; err != nil {
		return fmt.Errorf("detach node %d from inbounds: %w", id, err)
	}
	return tx.Delete(&Node{}, id).Error
}

// OrphanReport counts what a referential sweep removed or repaired.
type OrphanReport struct {
	// Assignments is user_inbounds rows whose user or inbound is gone.
	Assignments int64
	// TrafficBaselines is node_client_traffics rows whose node is gone.
	TrafficBaselines int64
	// GroupBindings is groups whose binding list named a missing inbound.
	GroupBindings int64
	// UserGroups is users pointing at a group that no longer exists.
	UserGroups int64
	// InboundNodes is inbounds pointing at a node that no longer exists.
	InboundNodes int64
}

// Empty reports whether the database was already referentially clean.
func (r OrphanReport) Empty() bool {
	return r.Assignments == 0 && r.TrafficBaselines == 0 && r.GroupBindings == 0 &&
		r.UserGroups == 0 && r.InboundNodes == 0
}

// repairOrphans sweeps every dangling reference the pre-cascade deletes left
// behind; migVRepairOrphans runs it once against an adopted database. It is
// idempotent — a second pass finds nothing — so re-running it can never do harm.
//
// It deliberately does not touch node_client_traffics rows whose *username* has
// no user. Those are keyed by a natural key that can legitimately arrive before
// the account does — a node reports a tag, the operator creates the matching
// user afterwards — and deleting the baseline would reset the counter and
// double-count that user's traffic. Only the id-keyed reference is unambiguous.
func repairOrphans(tx *gorm.DB) (OrphanReport, error) {
	var rep OrphanReport
	fresh := func() *gorm.DB { return tx.Session(&gorm.Session{NewDB: true}) }

	res := tx.Where("user_id NOT IN (?)", fresh().Model(&User{}).Select("id")).
		Or("inbound_id NOT IN (?)", fresh().Model(&Inbound{}).Select("id")).
		Delete(&UserInbound{})
	if res.Error != nil {
		return rep, fmt.Errorf("sweep orphaned assignments: %w", res.Error)
	}
	rep.Assignments = res.RowsAffected

	// Baselines whose user no longer exists. The scope side (a deleted node) is
	// swept by deleteNodeTx; this catches rows left by any path that removed a
	// user without going through the cascade — an older release, or a manual
	// delete — because the consequence is silent: a reused id inherits the
	// stale counter and transfers free.
	res = tx.Where("key LIKE ?", "u%").
		Where("CAST(SUBSTR(key, 2) AS INTEGER) NOT IN (?)", fresh().Model(&User{}).Select("id")).
		Delete(&TrafficSnapshot{})
	if res.Error != nil {
		return rep, fmt.Errorf("sweep orphaned traffic baselines: %w", res.Error)
	}
	rep.TrafficBaselines = res.RowsAffected

	res = tx.Model(&User{}).
		Where("group_id <> 0").
		Where("group_id NOT IN (?)", fresh().Model(&Group{}).Select("id")).
		Update("group_id", 0)
	if res.Error != nil {
		return rep, fmt.Errorf("clear orphaned user groups: %w", res.Error)
	}
	rep.UserGroups = res.RowsAffected

	res = tx.Model(&Inbound{}).
		Where("node_id <> 0").
		Where("node_id NOT IN (?)", fresh().Model(&Node{}).Select("id")).
		Update("node_id", 0)
	if res.Error != nil {
		return rep, fmt.Errorf("clear orphaned inbound nodes: %w", res.Error)
	}
	rep.InboundNodes = res.RowsAffected

	n, err := pruneGroupBindings(tx)
	if err != nil {
		return rep, err
	}
	rep.GroupBindings = n
	return rep, nil
}

// pruneGroupBindings drops ids naming a missing inbound out of every group's
// binding list. The list is text, so the filtering happens in Go.
func pruneGroupBindings(tx *gorm.DB) (int64, error) {
	var live []uint
	if err := tx.Model(&Inbound{}).Pluck("id", &live).Error; err != nil {
		return 0, fmt.Errorf("read inbound ids: %w", err)
	}
	exists := make(map[uint]bool, len(live))
	for _, id := range live {
		exists[id] = true
	}
	var groups []Group
	if err := tx.Find(&groups).Error; err != nil {
		return 0, fmt.Errorf("read groups: %w", err)
	}
	var fixed int64
	for i := range groups {
		kept := make(IntSlice, 0, len(groups[i].InboundIDs))
		for _, id := range groups[i].InboundIDs {
			if exists[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) == len(groups[i].InboundIDs) {
			continue
		}
		if err := tx.Model(&Group{}).Where("id = ?", groups[i].ID).
			Update("inbound_ids", kept).Error; err != nil {
			return fixed, fmt.Errorf("prune group %d bindings: %w", groups[i].ID, err)
		}
		fixed++
	}
	return fixed, nil
}
