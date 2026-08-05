package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token lifetimes (spec §2): access 15m, refresh 7d.
const (
	AccessTTL  = 15 * time.Minute
	RefreshTTL = 7 * 24 * time.Hour
)

// Claims is the JWT payload for an authenticated admin.
type Claims struct {
	AdminID  uint   `json:"aid"`
	Username string `json:"usr"`
	Role     string `json:"role"`
	Kind     string `json:"knd"` // "access" or "refresh"
	// SessionEpoch is the account's session generation at issue time. A token
	// whose epoch is behind the account's current one has been invalidated —
	// this is what makes "sign out everywhere" work with stateless tokens.
	SessionEpoch uint `json:"sep,omitempty"`
	jwt.RegisteredClaims
}

// Signer mints and verifies tokens with an HMAC secret derived from the panel
// master key. The secret never touches the DB.
type Signer struct {
	secret   []byte
	now      func() time.Time
	sessions SessionValidator
}

// NewSigner builds a signer from raw secret bytes.
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret, now: time.Now}
}

// Issue mints an access+refresh pair for an admin at session epoch 0. Prefer
// IssueAt, which stamps the account's current epoch so the pair can be
// invalidated later.
func (s *Signer) Issue(adminID uint, username, role string) (access, refresh string, err error) {
	return s.IssueAt(adminID, username, role, 0)
}

// IssueAt mints an access+refresh pair stamped with the account's session epoch.
func (s *Signer) IssueAt(adminID uint, username, role string, epoch uint) (access, refresh string, err error) {
	access, err = s.mint(adminID, username, role, "access", AccessTTL, epoch)
	if err != nil {
		return "", "", err
	}
	refresh, err = s.mint(adminID, username, role, "refresh", RefreshTTL, epoch)
	return access, refresh, err
}

func (s *Signer) mint(adminID uint, username, role, kind string, ttl time.Duration, epoch uint) (string, error) {
	now := s.now()
	c := Claims{
		AdminID: adminID, Username: username, Role: role, Kind: kind, SessionEpoch: epoch,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "forgepanel",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.secret)
}

// Verify parses and validates a token, returning its claims.
func (s *Signer) Verify(token string) (*Claims, error) {
	var c Claims
	t, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil || !t.Valid {
		return nil, errors.New("auth: invalid token")
	}
	return &c, nil
}
