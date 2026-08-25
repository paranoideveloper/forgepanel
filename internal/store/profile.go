package store

// One protocol definition, deployed to many nodes.
//
// Inbounds are per-panel rows bound to a single node, so serving "the same
// VLESS+REALITY definition" from ten nodes meant ten hand-made inbounds — and
// every credential rotation, transport change or SNI adjustment had to be
// repeated ten times, correctly, by hand. The tenth one is where the mistake
// lives, and a mismatched inbound fails for its users only.
//
// THREE TIERS, following the shape the reference implementations converged on:
//
//	Profile          the protocol definition, identical everywhere
//	ProfileBinding   profile × node, carrying what MUST differ per node
//	(Inbound)        the materialised row each binding owns
//
// The binding owns exactly the fields that cannot be shared — the port it
// listens on and the address clients reach it at — and nothing else. Anything
// else being per-node would mean the profile is not actually one definition.

import (
	"time"

	"gorm.io/gorm"
)

// Profile is a reusable protocol template.
type Profile struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"uniqueIndex;size:128" json:"name"`
	Note string `gorm:"size:255" json:"note"`
	// TemplateJSON is a marshalled model.Node holding everything shared:
	// protocol, credentials, transport, security. Address and port in it are
	// placeholders — each binding supplies its own.
	//
	// Stored as the canonical node rather than a parallel schema, so a profile
	// can express anything an inbound can and cannot drift from what the
	// renderer understands.
	TemplateJSON string    `gorm:"type:text" json:"-"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (Profile) TableName() string { return "profiles" }

// ProfileBinding deploys one profile to one node.
type ProfileBinding struct {
	ID        uint `gorm:"primaryKey" json:"id"`
	ProfileID uint `gorm:"index:idx_profile_node,unique" json:"profile_id"`
	NodeID    uint `gorm:"index:idx_profile_node,unique" json:"node_id"`
	// Port is what this node listens on. Zero means "use the template's",
	// which is right when every node can use the same one.
	Port int `json:"port"`
	// PublicHost is the address clients are given for THIS node. It is separate
	// from the listen address because a node behind a CDN or a NAT is reached at
	// a name that has nothing to do with what it binds locally.
	PublicHost string `gorm:"size:255" json:"public_host"`
	// InboundID is the materialised row this binding owns. The binding is the
	// authority; the row exists so everything downstream — rendering, traffic
	// accounting, subscriptions — keeps working unchanged.
	InboundID uint      `gorm:"index" json:"inbound_id"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ProfileBinding) TableName() string { return "profile_bindings" }

// --- queries ----------------------------------------------------------------

func (s *Store) ListProfiles() ([]Profile, error) {
	var out []Profile
	return out, s.db.Order("name").Find(&out).Error
}

func (s *Store) ProfileByID(id uint) (*Profile, error) {
	var p Profile
	if err := s.db.First(&p, id).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) SaveProfile(p *Profile) error { return s.db.Save(p).Error }

// DeleteProfile removes a profile and its bindings in ONE transaction.
//
// Bindings that outlive their profile own inbound rows nothing can ever update
// again — orphans that keep serving traffic under a definition no longer visible
// anywhere in the panel.
func (s *Store) DeleteProfile(id uint) ([]uint, error) {
	var orphaned []uint
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var bindings []ProfileBinding
		if err := tx.Where("profile_id = ?", id).Find(&bindings).Error; err != nil {
			return err
		}
		for _, b := range bindings {
			if b.InboundID != 0 {
				orphaned = append(orphaned, b.InboundID)
			}
		}
		if err := tx.Where("profile_id = ?", id).Delete(&ProfileBinding{}).Error; err != nil {
			return err
		}
		return tx.Delete(&Profile{}, id).Error
	})
	return orphaned, err
}

func (s *Store) ListBindings(profileID uint) ([]ProfileBinding, error) {
	var out []ProfileBinding
	q := s.db.Order("id")
	if profileID != 0 {
		q = q.Where("profile_id = ?", profileID)
	}
	return out, q.Find(&out).Error
}

func (s *Store) SaveBinding(b *ProfileBinding) error { return s.db.Save(b).Error }

func (s *Store) DeleteBinding(id uint) (inboundID uint, err error) {
	var b ProfileBinding
	if err := s.db.First(&b, id).Error; err != nil {
		return 0, err
	}
	return b.InboundID, s.db.Delete(&ProfileBinding{}, id).Error
}

// BindingByInbound finds the binding that owns an inbound row, if any.
//
// This is what lets a direct edit of a managed inbound be REFUSED rather than
// silently overwritten by the next profile sync.
func (s *Store) BindingByInbound(inboundID uint) (*ProfileBinding, error) {
	var b ProfileBinding
	if err := s.db.Where("inbound_id = ?", inboundID).First(&b).Error; err != nil {
		return nil, err
	}
	return &b, nil
}
