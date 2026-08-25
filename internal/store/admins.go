package store

// Admin accounts: listing, counting owners, and reassigning what an admin owns.
//
// The reseller model — roles, per-admin user quotas, traffic credit and
// OwnerAdminID scoping — was implemented and enforced throughout the repository
// layer, and there was no way to create a second admin at all. The whole of
// multi-tenancy was unreachable: a panel could only ever have the one account
// setup minted.
//
// The queries here exist to make the DESTRUCTIVE cases safe. Deleting an admin
// is not a row delete: it decides the fate of every user that admin owns, and it
// can lock the panel out of its own administration.

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// ErrLastOwner is returned when a change would leave the panel with no owner.
//
// There is no recovery path from that state through the panel itself: no account
// could grant the role back, and the only fix is editing the database by hand.
// It is refused rather than warned about.
var ErrLastOwner = errors.New("store: this would leave the panel with no owner")

// ErrAdminOwnsUsers is returned when an admin still owns users at delete time.
var ErrAdminOwnsUsers = errors.New("store: admin still owns users")

// ListAdmins returns every admin account, oldest first so the list is stable
// across calls and the original owner stays at the top.
func (s *Store) ListAdmins() ([]Admin, error) {
	var out []Admin
	if err := s.db.Order("id asc").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list admins: %w", err)
	}
	return out, nil
}

// CountOwners returns how many enabled owner accounts exist.
//
// Disabled owners do not count: an account that cannot sign in cannot restore
// anyone else's access, so leaving one behind is the same lockout with a
// reassuring row in the table.
func (s *Store) CountOwners() (int64, error) {
	var n int64
	err := s.db.Model(&Admin{}).Where("role = ? AND disabled = ?", RoleOwner, false).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("count owners: %w", err)
	}
	return n, nil
}

// CountUsersOwnedBy returns how many users an admin owns.
func (s *Store) CountUsersOwnedBy(adminID uint) (int64, error) {
	var n int64
	err := s.db.Model(&User{}).Where("owner_admin_id = ?", adminID).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("count users owned by %d: %w", adminID, err)
	}
	return n, nil
}

// SaveAdminChecked persists an admin, refusing a change that would remove the
// last owner.
//
// The check and the write happen in ONE transaction. Two owners demoting each
// other concurrently would otherwise both read "2 owners", both pass, and both
// commit — leaving zero.
func (s *Store) SaveAdminChecked(a *Admin) error {
	if a == nil || a.ID == 0 {
		return errors.New("store: admin has no id")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var before Admin
		if err := tx.First(&before, a.ID).Error; err != nil {
			return err
		}
		losingOwner := before.Role == RoleOwner && !before.Disabled &&
			(a.Role != RoleOwner || a.Disabled)
		if losingOwner {
			var others int64
			if err := tx.Model(&Admin{}).
				Where("role = ? AND disabled = ? AND id <> ?", RoleOwner, false, a.ID).
				Count(&others).Error; err != nil {
				return err
			}
			if others == 0 {
				return ErrLastOwner
			}
		}
		return tx.Save(a).Error
	})
}

// DeleteAdmin removes an admin, moving the users it owns to reassignTo.
//
// Reassignment is REQUIRED when the admin owns users, and that is deliberate.
// Users whose OwnerAdminID points at an account that no longer exists belong to
// nobody: no reseller can see them, quota accounting stops counting them, and
// they keep being served with no one able to manage them. Orphaning is the one
// outcome this must never produce silently, so a caller that has not decided
// gets ErrAdminOwnsUsers and the count, rather than a surprise.
//
// reassignTo == 0 is allowed only when the admin owns nothing.
func (s *Store) DeleteAdmin(id, reassignTo uint) error {
	if id == 0 {
		return errors.New("store: admin has no id")
	}
	if id == reassignTo {
		return errors.New("store: cannot reassign an admin's users to itself")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var a Admin
		if err := tx.First(&a, id).Error; err != nil {
			return err
		}
		if a.Role == RoleOwner && !a.Disabled {
			var others int64
			if err := tx.Model(&Admin{}).
				Where("role = ? AND disabled = ? AND id <> ?", RoleOwner, false, id).
				Count(&others).Error; err != nil {
				return err
			}
			if others == 0 {
				return ErrLastOwner
			}
		}

		var owned int64
		if err := tx.Model(&User{}).Where("owner_admin_id = ?", id).Count(&owned).Error; err != nil {
			return err
		}
		if owned > 0 {
			if reassignTo == 0 {
				return fmt.Errorf("%w: %d", ErrAdminOwnsUsers, owned)
			}
			var target Admin
			if err := tx.First(&target, reassignTo).Error; err != nil {
				return fmt.Errorf("reassign target %d: %w", reassignTo, err)
			}
			if err := tx.Model(&User{}).Where("owner_admin_id = ?", id).
				Update("owner_admin_id", reassignTo).Error; err != nil {
				return fmt.Errorf("reassign users of admin %d: %w", id, err)
			}
		}
		return tx.Delete(&Admin{}, id).Error
	})
}

// ValidRole reports whether r is one of the four roles the panel implements.
//
// Roles are compared as strings throughout the authorization policy, so an
// unknown value stored here would match no rule and fail closed — an account
// that exists, signs in, and can do nothing, with no error explaining why.
func ValidRole(r Role) bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleReseller, RoleViewer:
		return true
	}
	return false
}
