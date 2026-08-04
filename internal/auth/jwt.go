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
	jwt.RegisteredClaims
}

// Signer mints and verifies tokens with an HMAC secret derived from the panel
// master key. The secret never touches the DB.
type Signer struct {
	secret []byte
	now    func() time.Time
}

// NewSigner builds a signer from raw secret bytes.
func NewSigner(secret []byte) *Signer {
	return &Signer{secret: secret, now: time.Now}
}

// Issue mints an access+refresh pair for an admin.
func (s *Signer) Issue(adminID uint, username, role string) (access, refresh string, err error) {
	access, err = s.mint(adminID, username, role, "access", AccessTTL)
	if err != nil {
		return "", "", err
	}
	refresh, err = s.mint(adminID, username, role, "refresh", RefreshTTL)
	return access, refresh, err
}

func (s *Signer) mint(adminID uint, username, role, kind string, ttl time.Duration) (string, error) {
	now := s.now()
	c := Claims{
		AdminID: adminID, Username: username, Role: role, Kind: kind,
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
