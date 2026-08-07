package store

import (
	"errors"
	"strings"

	"gorm.io/gorm"
)

// This file is the Domains registry repository (BUG-3). It is the list of
// domains an operator owns, distinct from the panel's own address: inbounds
// reference these by name, new inbounds inherit the default, and the §5 DNS
// wizard provisions them.

// ErrDomainInUse reports that a domain still backs inbounds and cannot be deleted.
var ErrDomainInUse = errors.New("store: domain is still used by one or more inbounds")

// normalizeDomainName lowercases and strips a trailing dot; it does not validate
// (the service layer does that) so lookups are forgiving.
func normalizeDomainName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// CreateDomain inserts a domain. The first domain created becomes the default
// automatically, so a fresh panel that adds one domain does not then require a
// separate "make default" step.
func (s *Store) CreateDomain(d *Domain) error {
	d.Name = normalizeDomainName(d.Name)
	if d.Name == "" {
		return errors.New("store: empty domain name")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&Domain{}).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			d.IsDefault = true
		} else if d.IsDefault {
			if err := tx.Model(&Domain{}).Where("is_default = ?", true).
				Update("is_default", false).Error; err != nil {
				return err
			}
		}
		return tx.Create(d).Error
	})
}

// ListDomains returns all domains, default first then alphabetical.
func (s *Store) ListDomains() ([]Domain, error) {
	var out []Domain
	err := s.db.Order("is_default DESC, name ASC").Find(&out).Error
	return out, err
}

// DomainByID loads one domain.
func (s *Store) DomainByID(id uint) (*Domain, error) {
	var d Domain
	if err := s.db.First(&d, id).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

// DomainByName loads a domain by its (normalized) name.
func (s *Store) DomainByName(name string) (*Domain, error) {
	var d Domain
	if err := s.db.Where("name = ?", normalizeDomainName(name)).First(&d).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

// DefaultDomain returns the default domain name, or "" when none is set. This is
// what a new inbound inherits.
func (s *Store) DefaultDomain() string {
	var d Domain
	if err := s.db.Where("is_default = ?", true).First(&d).Error; err != nil {
		return ""
	}
	return d.Name
}

// SetDefaultDomain makes one domain the default (or clears the flag everywhere
// when id is 0), keeping "at most one default" true in a single transaction.
func (s *Store) SetDefaultDomain(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Domain{}).Where("is_default = ?", true).
			Update("is_default", false).Error; err != nil {
			return err
		}
		if id == 0 {
			return nil
		}
		res := tx.Model(&Domain{}).Where("id = ?", id).Update("is_default", true)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}

// UpdateDomainFields applies whitelisted column updates to a domain.
func (s *Store) UpdateDomainFields(id uint, fields map[string]any) error {
	if name, ok := fields["name"].(string); ok {
		fields["name"] = normalizeDomainName(name)
	}
	// is_default is handled by SetDefaultDomain to preserve the single-default
	// invariant; refuse to set it here where that guard does not run.
	delete(fields, "is_default")
	if len(fields) == 0 {
		return nil
	}
	return s.db.Model(&Domain{}).Where("id = ?", id).Updates(fields).Error
}

// DeleteDomain removes a domain, refusing while any inbound still references it
// (by the domain embedded in the inbound's node JSON), so links do not silently
// break. force skips the check for an operator who accepts the consequence.
func (s *Store) DeleteDomain(id uint, force bool) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var d Domain
		if err := tx.First(&d, id).Error; err != nil {
			return err
		}
		if !force {
			var ins []Inbound
			if err := tx.Find(&ins).Error; err != nil {
				return err
			}
			needle := `"domain":"` + d.Name + `"`
			for _, in := range ins {
				if strings.Contains(in.NodeJSON, needle) {
					return ErrDomainInUse
				}
			}
		}
		return tx.Delete(&Domain{}, id).Error
	})
}
