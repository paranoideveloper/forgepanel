package store

// Applying a migration plan as ONE transaction.
//
// An import is the operation an operator runs once, against a panel they have
// not used before, with data they cannot easily reconstruct. A half-finished one
// is the worst possible outcome: some users exist and some do not, nobody knows
// which, and running it again duplicates the half that landed.
//
// So the whole plan lands or none of it does. That makes "rollback" a property
// of the write rather than a feature that has to work correctly under failure —
// the database does it, and it cannot be got wrong.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// ImportInbound is one inbound to create, with the users that belong to it.
type ImportInbound struct {
	Node  *model.Node
	Users []ImportUser
	// SourceKey records where this row came from, so a later re-import
	// recognises it rather than creating a second copy.
	SourceKey string
}

// ImportUser is one account to create.
type ImportUser struct {
	Username string
	UUID     string
	Password string
	SubToken string
}

// ImportOutcome reports what actually landed.
type ImportOutcome struct {
	Inbounds int `json:"inbounds"`
	Users    int `json:"users"`
	// InboundIDs lets the caller reload exactly what changed rather than
	// everything.
	InboundIDs []uint `json:"inbound_ids"`
}

// ApplyImport writes an entire migration plan atomically.
//
// Users are attached to their inbound through the same assignment table the
// panel uses everywhere else, so an imported account behaves identically to one
// created by hand — no second code path that only migrated users take.
func (s *Store) ApplyImport(items []ImportInbound) (*ImportOutcome, error) {
	out := &ImportOutcome{}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// Reset the outcome inside the transaction: a retry must not report the
		// counts of the attempt that rolled back.
		out.Inbounds, out.Users, out.InboundIDs = 0, 0, nil

		for _, item := range items {
			if item.Node == nil {
				continue
			}
			var in Inbound
			in.Enabled = true
			in.ImportSource = item.SourceKey
			if err := in.SetNode(item.Node); err != nil {
				return fmt.Errorf("import %q: %w", item.Node.Remark, err)
			}
			if err := tx.Create(&in).Error; err != nil {
				return fmt.Errorf("import inbound %q: %w", item.Node.Remark, err)
			}
			out.Inbounds++
			out.InboundIDs = append(out.InboundIDs, in.ID)

			for _, iu := range item.Users {
				u := User{
					Username: iu.Username, UUID: iu.UUID, Password: iu.Password,
					SubToken: iu.SubToken, Status: StatusActive,
				}
				if err := tx.Create(&u).Error; err != nil {
					return fmt.Errorf("import user %q: %w", iu.Username, err)
				}
				out.Users++
				// The assignment is what actually serves them. Creating the user
				// without it produces an account that exists, looks correct, and
				// has no inbound — which reads as a panel bug rather than an
				// incomplete import.
				if err := tx.Create(&UserInbound{UserID: u.ID, InboundID: in.ID}).Error; err != nil {
					return fmt.Errorf("assign %q to %q: %w", iu.Username, item.Node.Remark, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
