package store

// Machine credentials that are not "the whole panel".
//
// The only machine credential the panel had was a full-privilege admin JWT: to
// let a monitoring script read a traffic figure, you handed it a token that
// could also delete every inbound. There was no way to issue something narrower,
// nothing expired on its own, and revoking meant changing the admin's password
// and breaking every other integration at the same time.

import (
	"time"
)

// TokenScope is what a token is allowed to do.
//
// Scopes map onto the EXISTING role authorisation table rather than introducing
// a parallel permission system. A second permission model is a second thing to
// get wrong, and the one that disagrees with the router is the one that grants
// too much.
type TokenScope string

const (
	// ScopeRead is everything the OWNING ADMIN can see, and nothing they can
	// change.
	//
	// It maps to the owner role and is then clamped to the minting admin, so it
	// reads exactly as far as that person does and no further. An earlier
	// version mapped it to the viewer role, which made a "read" token unable to
	// list users — useless for the monitoring job it exists for, because a
	// viewer cannot see tenant data at all.
	ScopeRead TokenScope = "read"
	// ScopeObservability is the narrowest useful scope: health, metrics and
	// usage. It exists because "let Prometheus scrape this" should not require
	// handing over the user list.
	ScopeObservability TokenScope = "observability"
	// ScopeWrite is customer management — the reseller's job — without panel
	// reconfiguration.
	ScopeWrite TokenScope = "write"
	// ScopeAdmin is everything the owning admin can do. It is deliberately last
	// and deliberately named plainly: a token with this scope is as dangerous as
	// the account that minted it.
	ScopeAdmin TokenScope = "admin"
	// ScopeNodeSync is for a remote node agent: heartbeat and config pull only.
	ScopeNodeSync TokenScope = "node-sync"
)

// ValidScopes lists every scope, for validation and for the UI.
func ValidScopes() []TokenScope {
	return []TokenScope{ScopeObservability, ScopeRead, ScopeWrite, ScopeAdmin, ScopeNodeSync}
}

// EffectiveRole maps a scope onto the role the authorisation table already
// understands.
//
// A scope can never grant MORE than the admin who created the token — that is
// enforced at issue time, not here — so this is a ceiling, not a grant.
func (s TokenScope) EffectiveRole() Role {
	switch s {
	case ScopeAdmin:
		return RoleOwner
	case ScopeRead:
		// Same reach as admin, made harmless by ReadOnly below. "Everything I
		// can see, nothing I can change" is what a read-only credential is for,
		// and it cannot exceed its owner because the caller clamps it.
		return RoleOwner
	case ScopeWrite:
		return RoleReseller
	case ScopeObservability, ScopeNodeSync:
		return RoleViewer
	default:
		// An unknown scope gets the least privilege rather than the most. A
		// typo in a stored row must not become an escalation.
		return RoleViewer
	}
}

// ReadOnly reports whether a scope may only make safe requests.
//
// Enforced by METHOD on top of the role, because the role table alone cannot
// express "may look at everything a reseller can, but may not change any of
// it" — and inventing a whole second matrix to express it would be the parallel
// permission system this deliberately avoids.
func (s TokenScope) ReadOnly() bool {
	return s == ScopeRead || s == ScopeObservability
}

// APIToken is one issued machine credential.
//
// The SECRET IS NOT STORED. Only its hash is, so a stolen database yields no
// usable token — and the panel physically cannot show a token again after
// creation, which is why the UI says so rather than offering a "reveal" that
// would be a lie.
type APIToken struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"size:128" json:"name"`
	// AdminID is the owner. A token acts AS that admin, so reseller scoping and
	// audit attribution work through the machinery that already exists.
	AdminID uint       `gorm:"index" json:"admin_id"`
	Scope   TokenScope `gorm:"size:32" json:"scope"`
	// Prefix is the public half, stored in clear and shown in listings.
	//
	// It exists so verification is ONE hash rather than one per stored row:
	// without a lookup key, checking a token means comparing it against every
	// token in the table. It also lets an operator recognise a token that has
	// leaked into a log without ever holding the secret.
	Prefix string `gorm:"uniqueIndex;size:32" json:"prefix"`
	// Hash is SHA-256 of the secret half. See auth.HashAPIToken for why this is
	// not argon2.
	Hash string `gorm:"size:64" json:"-"`
	// ExpiresAt is when the token stops working. Nil means never, which is
	// allowed but is not the default the UI offers.
	ExpiresAt *time.Time `json:"expires_at"`
	// RevokedAt disables a token WITHOUT deleting the row, so the audit trail
	// keeps pointing at something real. A deleted token turns every historical
	// entry that names it into a dangling reference.
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (APIToken) TableName() string { return "api_tokens" }

// Usable reports whether a token may authenticate a request right now.
func (t *APIToken) Usable(now time.Time) bool {
	if t == nil || t.RevokedAt != nil {
		return false
	}
	// Expiry is inclusive of the instant it passes: a token that expired this
	// microsecond is expired.
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}

// --- queries ----------------------------------------------------------------

// CreateAPIToken stores a new token record.
func (s *Store) CreateAPIToken(t *APIToken) error {
	return s.db.Create(t).Error
}

// APITokenByPrefix resolves the public half to its record.
//
// One indexed lookup, then one hash comparison by the caller. Without the
// prefix, authenticating a request would mean hashing it against every row.
func (s *Store) APITokenByPrefix(prefix string) (*APIToken, error) {
	var t APIToken
	if err := s.db.Where("prefix = ?", prefix).First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

// ListAPITokens returns an admin's tokens, or every token when adminID is 0.
//
// Revoked and expired tokens are INCLUDED. A list that hides them cannot answer
// "was this token still live last Tuesday", which is the question asked after an
// incident.
func (s *Store) ListAPITokens(adminID uint) ([]APIToken, error) {
	var out []APIToken
	q := s.db.Order("created_at desc")
	if adminID != 0 {
		q = q.Where("admin_id = ?", adminID)
	}
	return out, q.Find(&out).Error
}

// RevokeAPIToken disables a token without deleting it.
func (s *Store) RevokeAPIToken(id uint, at time.Time) error {
	return s.db.Model(&APIToken{}).Where("id = ? AND revoked_at IS NULL", id).
		UpdateColumn("revoked_at", at).Error
}

// TouchAPIToken records that a token was just used.
//
// Best-effort and deliberately not in the request's critical path: knowing a
// token is still in use is worth having, and failing an authenticated request
// because a bookkeeping write failed is not.
func (s *Store) TouchAPIToken(id uint, at time.Time) {
	_ = s.db.Model(&APIToken{}).Where("id = ?", id).UpdateColumn("last_used_at", at).Error
}

// SetAPITokenExpiry changes when a token stops working.
//
// Exists so an expiry can be brought FORWARD — shortening a token's life is a
// softer response to a suspected leak than revocation, and tests need to reach
// an elapsed expiry without waiting for one.
func (s *Store) SetAPITokenExpiry(id uint, at *time.Time) error {
	return s.db.Model(&APIToken{}).Where("id = ?", id).UpdateColumn("expires_at", at).Error
}
