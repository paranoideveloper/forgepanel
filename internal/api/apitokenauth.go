package api

// Authenticating a request with a scoped API token.
//
// A token acts AS the admin that minted it, which is what makes reseller
// scoping, audit attribution and quota accounting work through the machinery
// that already exists rather than through a second copy of it.
//
// Two restrictions are applied ON TOP of that identity, and both matter:
//
//   - the scope's EffectiveRole is a CEILING, never a grant. A token cannot do
//     something its owner cannot: a reseller's admin-scoped token is still a
//     reseller. Without this, minting a token would be a privilege escalation
//     available to anyone who can mint one.
//   - a read-only scope rejects any method that is not GET/HEAD/OPTIONS. The
//     role table alone cannot express "may see everything a reseller can and
//     change none of it", and inventing a second permission matrix to say it is
//     exactly the parallel system this design avoids.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// roleRank orders roles so a token's scope can be clamped to its owner's
// authority. Higher is more privileged.
var roleRank = map[store.Role]int{
	store.RoleViewer:   0,
	store.RoleReseller: 1,
	store.RoleAdmin:    2,
	store.RoleOwner:    3,
}

// clampRole returns the LESSER of what the scope allows and what the owner has.
func clampRole(scope store.Role, owner store.Role) store.Role {
	if roleRank[scope] <= roleRank[owner] {
		return scope
	}
	return owner
}

// apiTokenAuth authenticates an API token, or passes through untouched when the
// request does not carry one.
//
// It runs BEFORE the JWT middleware and only claims requests whose bearer value
// is shaped like one of our tokens, so a JWT is never sent down this path and a
// malformed token never reaches the JWT verifier.
func (s *Server) apiTokenAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := auth.Bearer(c)
		if raw == "" || !auth.LooksLikeAPIToken(raw) {
			c.Next()
			return
		}
		if s.db == nil {
			abortFail(c, http.StatusUnauthorized, "API tokens are unavailable")
			return
		}

		prefix, secret, ok := auth.SplitAPIToken(raw)
		if !ok {
			abortFail(c, http.StatusUnauthorized, "malformed API token")
			return
		}
		tok, err := s.db.APITokenByPrefix(prefix)
		if err != nil || tok == nil {
			abortFail(c, http.StatusUnauthorized, "unknown API token")
			return
		}
		if !auth.APITokenMatches(secret, tok.Hash) {
			// Deliberately the SAME message as an unknown prefix. Distinguishing
			// "this token exists but you got the secret wrong" from "no such
			// token" tells an attacker which prefixes are real.
			abortFail(c, http.StatusUnauthorized, "unknown API token")
			return
		}
		now := time.Now()
		if !tok.Usable(now) {
			// Revoked and expired ARE distinguished, because this one is the
			// legitimate holder and the difference decides what they do next:
			// renew it, or ask why it was revoked.
			msg := "this API token has expired"
			if tok.RevokedAt != nil {
				msg = "this API token has been revoked"
			}
			abortFail(c, http.StatusUnauthorized, msg)
			return
		}

		owner, err := s.db.AdminByID(tok.AdminID)
		if err != nil || owner == nil {
			abortFail(c, http.StatusUnauthorized, "the account that owns this token no longer exists")
			return
		}
		if owner.Disabled {
			// Disabling an account must take its machine credentials with it,
			// or "disabled" means nothing for the half of access that is
			// automated.
			abortFail(c, http.StatusUnauthorized, "the account that owns this token is disabled")
			return
		}

		if tok.Scope.ReadOnly() && !isSafeMethod(c.Request.Method) {
			abortFailWith(c, &apierr.Error{Op: "api-token-auth", Kind: apierr.KindPermission,
				Message: "this token is read-only",
				Details: map[string]any{"scope": string(tok.Scope)}})
			return
		}

		role := clampRole(tok.Scope.EffectiveRole(), owner.Role)
		claims := &auth.Claims{
			AdminID:  owner.ID,
			Username: owner.Username,
			Role:     string(role),
			Kind:     "access",
		}
		auth.SetClaims(c, claims)
		// Bookkeeping, off the critical path: a failure here must not fail an
		// otherwise valid request.
		s.db.TouchAPIToken(tok.ID, now)
		c.Set(ctxAPITokenName, tok.Name)
		// Claims are now set, and the JWT middleware downstream passes through
		// rather than trying to verify an API token as a JWT and rejecting it.
		c.Next()
	}
}

// ctxAPITokenName marks a request as token-authenticated, so the audit trail can
// say WHICH credential acted rather than only which account.
const ctxAPITokenName = "forgepanel_api_token_name"

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
