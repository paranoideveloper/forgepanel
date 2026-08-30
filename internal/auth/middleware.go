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
		// Already authenticated by another mechanism (an API token). Verifying
		// its value as a JWT would fail and reject a request that has been
		// properly authenticated — so the chain defers to whoever got here
		// first rather than each layer insisting on its own credential type.
		if _, ok := ClaimsFrom(c); ok {
			c.Next()
			return
		}
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

// bearer reads the access token from the Authorization header, and ONLY from
// there.
//
// There was a fallback to a "token" cookie. Nothing in the panel ever set that
// cookie — the frontend authenticates with localStorage and an Authorization
// header — so the branch was dead for the shipped UI while remaining live for
// anyone who set the cookie themselves.
//
// That distinction is the entire CSRF surface of this panel. A browser attaches
// cookies to cross-site requests automatically, so any page on the internet
// could have made a state-changing request to the panel and had the browser
// authenticate it. An Authorization header cannot be set cross-site, so the
// header path is immune by construction.
//
// The fix is removal rather than CSRF tokens: tokens are machinery to defend a
// door, and this door was one nobody was using. Deleting it removes the
// vulnerability class instead of mitigating it, and there is a test that the
// cookie is no longer accepted.
// SetClaims installs already-verified claims on the request.
//
// Used by the API-token path, which authenticates by a completely different
// mechanism and then reuses every downstream authorisation check unchanged. That
// reuse is the point: a second authorisation path is a second thing to get
// wrong, and the one that disagrees with the router grants too much.
func SetClaims(c *gin.Context, claims *Claims) { c.Set(ctxKey, claims) }

// Bearer returns the raw bearer value, whatever kind of credential it is.
func Bearer(c *gin.Context) string { return bearer(c) }

func bearer(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	// A WebSocket handshake, and ONLY a WebSocket handshake, may carry the token
	// in the query.
	//
	// The browser's WebSocket constructor takes a URL and nothing else: there is
	// no way to set an Authorization header on it. Without this, a live-log route
	// mounted correctly behind a correct handler answers 401 for the only client
	// that will ever call it, and every Go test still passes because tests can
	// set headers.
	//
	// This does NOT reopen the CSRF hole the cookie path was removed for. The
	// danger there was that browsers attach cookies to cross-site requests
	// automatically, so a foreign page could act as the operator without ever
	// seeing the credential. A query parameter is not attached by anything; the
	// caller has to know the token. Confined to the handshake so an ordinary
	// request cannot be authenticated this way — that would put a live session
	// token in every proxy access log and Referer header the panel touches.
	if isWebsocketUpgrade(c) {
		return c.Query("access_token")
	}
	return ""
}

func isWebsocketUpgrade(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}
	// Connection is a comma-separated list ("keep-alive, Upgrade"), which is what
	// Firefox sends, so it is searched rather than compared.
	if !strings.Contains(strings.ToLower(c.GetHeader("Connection")), "upgrade") {
		return false
	}
	return strings.EqualFold(c.GetHeader("Upgrade"), "websocket")
}
