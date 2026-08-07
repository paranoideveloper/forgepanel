package store

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"
)

// This file is the ForgeEdge deployment repository (§6). It records which edge
// Workers this panel feeds; see EdgeDeployment in models.go and
// deploy/cloudflare/forgeedge/docs/GO_WIRING.md §2.3.

// ErrEdgeOriginInvalid reports an origin that is not an absolute http(s) URL.
// Rejecting it here rather than at push time means a typo surfaces while the
// operator is still looking at the form, instead of as a silent no-op feed.
var ErrEdgeOriginInvalid = errors.New("store: edge origin must be an absolute http(s) URL")

// normalizeEdgeOrigin trims a trailing slash and validates the scheme/host.
func normalizeEdgeOrigin(raw string) (string, error) {
	s := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", ErrEdgeOriginInvalid
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", ErrEdgeOriginInvalid
	}
	return s, nil
}

// CreateEdgeDeployment registers an edge. Name and origin are required; target
// defaults to "workers".
func (s *Store) CreateEdgeDeployment(e *EdgeDeployment) error {
	e.Name = strings.TrimSpace(e.Name)
	if e.Name == "" {
		return errors.New("store: edge deployment needs a name")
	}
	origin, err := normalizeEdgeOrigin(e.Origin)
	if err != nil {
		return err
	}
	e.Origin = origin
	e.SecurePath = strings.Trim(strings.TrimSpace(e.SecurePath), "/")
	if e.Target == "" {
		e.Target = "workers"
	}
	return s.db.Create(e).Error
}

// ListEdgeDeployments returns every registered edge, newest first.
func (s *Store) ListEdgeDeployments() ([]EdgeDeployment, error) {
	var out []EdgeDeployment
	err := s.db.Order("id DESC").Find(&out).Error
	return out, err
}

// EdgeDeploymentByID loads one edge.
func (s *Store) EdgeDeploymentByID(id uint) (*EdgeDeployment, error) {
	var e EdgeDeployment
	if err := s.db.First(&e, id).Error; err != nil {
		return nil, err
	}
	return &e, nil
}

// EdgeDeploymentByName loads one edge by its Worker/Pages project name, which is
// the handle `forgectl edge` commands use.
func (s *Store) EdgeDeploymentByName(name string) (*EdgeDeployment, error) {
	var e EdgeDeployment
	if err := s.db.Where("name = ?", strings.TrimSpace(name)).First(&e).Error; err != nil {
		return nil, err
	}
	return &e, nil
}

// DeleteEdgeDeployment forgets an edge. It deliberately does NOT touch anything
// at Cloudflare: destroying a Worker is `forgectl edge delete`, and conflating
// the two would let a stray click kill every subscription it serves.
func (s *Store) DeleteEdgeDeployment(id uint) error {
	res := s.db.Delete(&EdgeDeployment{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// UpdateEdgePushStatus records the outcome of a feed push. status is stored
// verbatim so the UI can show the real failure ("401 Invalid feed push token")
// instead of a boolean that says only that something went wrong.
func (s *Store) UpdateEdgePushStatus(id uint, at time.Time, status string) error {
	return s.db.Model(&EdgeDeployment{}).Where("id = ?", id).
		Updates(map[string]any{"last_push_at": at, "last_status": status}).Error
}

// SaveEdgeDeployment persists field changes (push token rotation, a new secure
// path after `forgectl edge rotate-path`).
func (s *Store) SaveEdgeDeployment(e *EdgeDeployment) error { return s.db.Save(e).Error }
