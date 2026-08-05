package auth

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// ctxKey is the gin context key under which the authenticated claims are stored.
const ctxKey = "forgepanel.claims"

// SessionValidator reports whether a token minted at the given session epoch is
// still valid for the admin. It exists as a callback so this package stays free
// of a storage dependency; the API layer wires it to the admin table.
type SessionValidator func(adminID uint, epoch uint) bool

// SetSessionValidator installs the callback the middleware consults to honour
// session invalidation. Without one, tokens remain valid until they expire.
func (s *Signer) SetSessionValidator(v SessionValidator) { s.sessions = v }

// SessionValid reports whether a token's epoch is still current. A signer with
// no validator accepts everything, preserving the stateless behaviour.
func (s *Signer) SessionValid(claims *Claims) bool {
	if s.sessions == nil || claims == nil {
		return true
	}
	return s.sessions(claims.AdminID, claims.SessionEpoch)
}

// Middleware requires a valid access token (Bearer header or "token" cookie)
// and stashes the claims in the gin context.
func (s *Signer) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := bearer(c)
		if tok == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "authentication required"})
			return
		}
		claims, err := s.Verify(tok)
		if err != nil || claims.Kind != "access" {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid or expired token"})
			return
		}
		// A token minted before the account's session epoch advanced has been
		// revoked (recovery-code login, 2FA disabled, password changed).
		if !s.SessionValid(claims) {
			c.AbortWithStatusJSON(401, gin.H{"error": "session revoked; sign in again"})
			return
		}
		c.Set(ctxKey, claims)
		c.Next()
	}
}

// ClaimsFrom returns the authenticated claims from the context, if any.
func ClaimsFrom(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(ctxKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}

// RequireRole aborts unless the caller holds one of the allowed roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok || !allowed[claims.Role] {
			c.AbortWithStatusJSON(403, gin.H{"error": "insufficient role"})
			return
		}
		c.Next()
	}
}

func bearer(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if ck, err := c.Cookie("token"); err == nil {
		return ck
	}
	return ""
}
