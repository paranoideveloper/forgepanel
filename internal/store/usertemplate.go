package store

// Saved plans: the limits an operator stamps onto an account instead of
// re-typing them.
//
// Every field a plan is made of already existed on User — data limit, reset
// cadence, expiry, group, IP limit — and nothing grouped them. So "the 5 GB
// monthly trial" lived in the operator's head, and the fiftieth trial account
// differed from the first in whichever field was mistyped that afternoon. A
// template is a stamp applied at creation, NOT a live binding: a user carries no
// template id, so editing a plan never retroactively rewrites accounts already
// sold under the old one.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// UserTemplate is one saved plan.
type UserTemplate struct {
	Base
	Name string `gorm:"uniqueIndex;size:128;not null" json:"name"`
	Note string `json:"note"`

	DataLimit      int64         `json:"data_limit"`       // bytes; 0 = unlimited
	ExpireDays     int           `json:"expire_days"`      // 0 = never
	OnHoldDuration int64         `json:"on_hold_duration"` // seconds; used when Status=on_hold
	ResetStrategy  ResetStrategy `gorm:"default:no_reset" json:"reset_strategy"`
	Status         UserStatus    `gorm:"default:active" json:"status"`
	GroupID        uint          `json:"group_id"`
	InboundIDs     IntSlice      `gorm:"type:text" json:"inbound_ids"`
	IPLimit        int           `json:"ip_limit"`

	// Affixes wrap the name the operator types, server-side, so a plan can own
	// its own naming convention ("tr-" for trials) without anyone having to
	// remember it. They are applied at CREATION only — see ApplyTemplateToUser.
	UsernamePrefix string `gorm:"size:20" json:"username_prefix"`
	UsernameSuffix string `gorm:"size:20" json:"username_suffix"`

	// OwnerAdminID scopes a plan to the tenant that saved it. Without it one
	// reseller's plan — carrying another tenant's group and inbound ids —
	// appears in the next reseller's dropdown and stamps accounts with access
	// they were never sold.
	OwnerAdminID uint `gorm:"index" json:"owner_admin_id"`
}

// TableName pins the table name so it reads clearly in migrations.
func (UserTemplate) TableName() string { return "user_templates" }

// ErrTemplateNameTaken reports a collision on the unique name index, separated
// from a generic write failure so the API can answer 409 rather than 500.
var ErrTemplateNameTaken = errors.New("store: a template with that name already exists")

// isUniqueNameViolation reports whether a write failed on a unique index.
//
// It reads the driver's message because gorm's TranslateError is off panel-wide
// (internal/store/store.go:31) and turning it on would change the error identity
// every existing caller in this package already matches against. The cost of
// getting this wrong is only that a duplicate name is answered 500 instead of
// 409 — the index refuses the row either way.
func isUniqueNameViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

// ListUserTemplates returns saved plans, oldest first. A non-zero owner narrows
// to that tenant's plans; zero means unrestricted (owner/admin).
func (s *Store) ListUserTemplates(owner uint) ([]UserTemplate, error) {
	var out []UserTemplate
	q := s.db.Order("id asc")
	if owner != 0 {
		q = q.Where("owner_admin_id = ?", owner)
	}
	err := q.Find(&out).Error
	return out, err
}

// UserTemplateByID loads one plan.
func (s *Store) UserTemplateByID(id uint) (*UserTemplate, error) {
	var t UserTemplate
	if err := s.db.First(&t, id).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateUserTemplate persists a plan.
func (s *Store) CreateUserTemplate(t *UserTemplate) error {
	// Status and ResetStrategy declare column defaults, and GORM omits a zero
	// value on INSERT when a column has one — so a plan saved with them empty
	// would come back reading "active"/"no_reset" from the database while the
	// struct the caller holds says "". Fill them here so the row and the caller
	// agree, and so a plan that deliberately creates accounts disabled is stored
	// as such rather than silently activated.
	if t.Status == "" {
		t.Status = StatusActive
	}
	if t.ResetStrategy == "" {
		t.ResetStrategy = ResetNo
	}
	if err := s.db.Create(t).Error; err != nil {
		if isUniqueNameViolation(err) {
			return fmt.Errorf("%w: %q", ErrTemplateNameTaken, t.Name)
		}
		return err
	}
	return nil
}

// UpdateUserTemplate applies a column-level update to a plan.
func (s *Store) UpdateUserTemplate(id uint, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	res := s.db.Model(&UserTemplate{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		if isUniqueNameViolation(res.Error) {
			return ErrTemplateNameTaken
		}
		return res.Error
	}
	return nil
}

// DeleteUserTemplate removes a plan. Users created from it are untouched: they
// hold values, not a reference.
func (s *Store) DeleteUserTemplate(id uint) error {
	return s.db.Delete(&UserTemplate{}, id).Error
}

// ApplyTemplateToUser stamps a saved plan onto an account that already exists.
//
// The username is deliberately NOT rewritten: the account's SubToken is already
// in a client somewhere, and renaming it mid-life changes what every generated
// config is called for no operator-visible reason.
//
// allowed carries the caller's assignable-inbound set exactly as SetUserInbounds
// takes it, and the same validation loop runs here inside the transaction —
// otherwise a template would be a way to hand a user an inbound the caller could
// not have assigned by hand.
func (s *Store) ApplyTemplateToUser(userID, templateID uint, allowed map[uint]bool) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var t UserTemplate
		if err := tx.First(&t, templateID).Error; err != nil {
			return err
		}
		var u User
		if err := tx.First(&u, userID).Error; err != nil {
			return err
		}

		fields := map[string]any{
			"data_limit":       t.DataLimit,
			"on_hold_duration": t.OnHoldDuration,
			"reset_strategy":   t.ResetStrategy,
			"status":           t.Status,
			"group_id":         t.GroupID,
			"ip_limit":         t.IPLimit,
		}
		if t.ExpireDays > 0 {
			fields["expire_at"] = time.Now().AddDate(0, 0, t.ExpireDays)
		} else {
			// A plan with no expiry means "never", which is a NULL column and
			// not "keep whatever was there" — a lifetime account that keeps an
			// old expiry silently dies on the old date.
			fields["expire_at"] = nil
		}
		if err := tx.Model(&User{}).Where("id = ?", userID).Updates(fields).Error; err != nil {
			return err
		}

		want, err := validInboundIDs(tx, t.InboundIDs, allowed)
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
