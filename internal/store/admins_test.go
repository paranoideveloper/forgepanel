package store

import (
	"errors"
	"testing"
)

// The reseller model was enforced everywhere and could not be used: nothing
// could create a second admin. These cover the destructive halves, because
// deleting an admin decides the fate of every user it owns and can lock the
// panel out of its own administration.

func adminStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mkAdmin(t *testing.T, s *Store, name string, role Role) *Admin {
	t.Helper()
	a := &Admin{Username: name, PasswordHash: "x", Role: role}
	if err := s.CreateAdmin(a); err != nil {
		t.Fatal(err)
	}
	return a
}

// There is no recovery path through the panel from an ownerless state: no
// account could grant the role back, and the only fix is editing the database.
func TestTheLastOwnerCannotBeDemoted(t *testing.T) {
	s := adminStore(t)
	owner := mkAdmin(t, s, "owner", RoleOwner)

	owner.Role = RoleReseller
	if err := s.SaveAdminChecked(owner); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demoting the last owner returned %v, want ErrLastOwner", err)
	}
	got, _ := s.AdminByID(owner.ID)
	if got.Role != RoleOwner {
		t.Fatalf("the demotion was applied anyway: role=%s", got.Role)
	}
}

func TestTheLastOwnerCannotBeDisabled(t *testing.T) {
	s := adminStore(t)
	owner := mkAdmin(t, s, "owner", RoleOwner)
	owner.Disabled = true
	if err := s.SaveAdminChecked(owner); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("disabling the last owner returned %v, want ErrLastOwner", err)
	}
}

func TestTheLastOwnerCannotBeDeleted(t *testing.T) {
	s := adminStore(t)
	owner := mkAdmin(t, s, "owner", RoleOwner)
	if err := s.DeleteAdmin(owner.ID, 0); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("deleting the last owner returned %v, want ErrLastOwner", err)
	}
}

// A second owner makes the first one removable.
func TestAnOwnerCanBeDemotedOnceAnotherExists(t *testing.T) {
	s := adminStore(t)
	first := mkAdmin(t, s, "first", RoleOwner)
	mkAdmin(t, s, "second", RoleOwner)

	first.Role = RoleAdmin
	if err := s.SaveAdminChecked(first); err != nil {
		t.Fatalf("demoting one of two owners failed: %v", err)
	}
}

// A DISABLED owner cannot restore anyone's access, so it must not count towards
// keeping an owner: leaving one behind is the same lockout with a reassuring row
// in the table.
func TestADisabledOwnerDoesNotCountAsTheRemainingOwner(t *testing.T) {
	s := adminStore(t)
	active := mkAdmin(t, s, "active", RoleOwner)
	disabled := mkAdmin(t, s, "disabled", RoleOwner)
	disabled.Disabled = true
	if err := s.SaveAdminChecked(disabled); err != nil {
		t.Fatal(err)
	}

	active.Role = RoleAdmin
	if err := s.SaveAdminChecked(active); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demoting the only ENABLED owner returned %v, want ErrLastOwner", err)
	}
}

// A user whose owner no longer exists belongs to nobody: no reseller sees them,
// quota accounting stops counting them, and nothing can manage them while they
// keep being served.
func TestDeletingAnAdminWithUsersRequiresReassignment(t *testing.T) {
	s := adminStore(t)
	mkAdmin(t, s, "owner", RoleOwner)
	reseller := mkAdmin(t, s, "reseller", RoleReseller)

	u := &User{Username: "customer", SubToken: "ct", OwnerAdminID: reseller.ID}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteAdmin(reseller.ID, 0); !errors.Is(err, ErrAdminOwnsUsers) {
		t.Fatalf("deleting an admin with users returned %v, want ErrAdminOwnsUsers", err)
	}
	if got, _ := s.AdminByID(reseller.ID); got == nil {
		t.Fatal("the admin was deleted despite the refusal")
	}
}

func TestReassignmentMovesTheUsers(t *testing.T) {
	s := adminStore(t)
	owner := mkAdmin(t, s, "owner", RoleOwner)
	reseller := mkAdmin(t, s, "reseller", RoleReseller)

	u := &User{Username: "customer", SubToken: "ct2", OwnerAdminID: reseller.ID}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(reseller.ID, owner.ID); err != nil {
		t.Fatalf("reassigning delete failed: %v", err)
	}
	got, err := s.UserByID(u.ID)
	if err != nil {
		t.Fatalf("the user was deleted with its owner: %v", err)
	}
	if got.OwnerAdminID != owner.ID {
		t.Fatalf("user owner is %d, want %d", got.OwnerAdminID, owner.ID)
	}
	if a, _ := s.AdminByID(reseller.ID); a != nil {
		t.Fatal("the admin survived a successful delete")
	}
}

// Reassigning to the admin being deleted would leave the users pointing at a
// row that is about to disappear.
func TestCannotReassignToTheAdminBeingDeleted(t *testing.T) {
	s := adminStore(t)
	mkAdmin(t, s, "owner", RoleOwner)
	r := mkAdmin(t, s, "reseller", RoleReseller)
	if err := s.DeleteAdmin(r.ID, r.ID); err == nil {
		t.Fatal("reassigning an admin's users to itself was allowed")
	}
}

// An unknown role matches no authorization rule and fails closed, so the account
// would exist, sign in, and be able to do nothing.
func TestValidRoleRejectsAnythingTheAuthorizationPolicyDoesNotKnow(t *testing.T) {
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleReseller, RoleViewer} {
		if !ValidRole(r) {
			t.Errorf("%s is a real role and was rejected", r)
		}
	}
	for _, r := range []Role{"", "root", "superuser", "Owner"} {
		if ValidRole(r) {
			t.Errorf("%q was accepted as a role", r)
		}
	}
}
