package store

// Operator-selected proxy-core versions.
//
// binmgr ships one pinned version per engine as a compile-time constant with a
// baked-in SHA-256 for every platform asset. That is the right default and a
// terrible ceiling: when upstream fixes a CVE, or a release breaks a transport an
// operator depends on, the only way off the shipped version was to rebuild the
// panel. These rows are the way off it — and they carry the digest, because the
// checksum mandate in binmgr is not something a database row gets to relax.

import "gorm.io/gorm"

// CorePin is an operator-supplied (engine, version, asset) -> SHA-256 row.
//
// It is a table rather than a settings value because a version needs a digest
// PER PLATFORM ASSET: a panel on amd64 that pins a core its arm64 nodes will
// also fetch has to be able to hold both.
type CorePin struct {
	Base
	Engine  string `gorm:"index:idx_core_pin,unique;not null" json:"engine"`
	Version string `gorm:"index:idx_core_pin,unique;not null" json:"version"`
	Asset   string `gorm:"index:idx_core_pin,unique;not null" json:"asset"`
	SHA256  string `gorm:"not null" json:"sha256"`
}

// SaveCorePins replaces the whole digest set for one (engine, version).
//
// Replace, not upsert: re-pinning a version after correcting a digest must not
// leave the wrong one behind under a stale asset name, because binmgr resolves
// digests by asset filename and would then verify against the corpse.
func (s *Store) SaveCorePins(engine, version string, pins []CorePin) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("engine = ? AND version = ?", engine, version).
			Delete(&CorePin{}).Error; err != nil {
			return err
		}
		for i := range pins {
			pins[i].Engine, pins[i].Version = engine, version
			if err := tx.Create(&pins[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// CorePinsFor returns the digests stored for one engine version.
func (s *Store) CorePinsFor(engine, version string) ([]CorePin, error) {
	var out []CorePin
	err := s.db.Where("engine = ? AND version = ?", engine, version).
		Order("asset asc").Find(&out).Error
	return out, err
}

// CorePinVersions lists the versions an operator has supplied digests for, which
// is the set a pin or a rollback can name without re-uploading checksums.
func (s *Store) CorePinVersions(engine string) ([]string, error) {
	var out []string
	err := s.db.Model(&CorePin{}).Where("engine = ?", engine).
		Distinct().Order("version asc").Pluck("version", &out).Error
	return out, err
}

// AllCorePins returns every stored digest, for the boot-time apply.
func (s *Store) AllCorePins() ([]CorePin, error) {
	var out []CorePin
	err := s.db.Order("engine asc, version asc, asset asc").Find(&out).Error
	return out, err
}
