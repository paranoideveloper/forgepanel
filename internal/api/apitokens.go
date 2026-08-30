package api

// Issuing, listing and revoking API tokens.

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// maxTokenLifetime bounds how far out an expiry may be set.
//
// Not a hard security property — an operator can always issue a new one — but a
// credential that outlives everyone's memory of why it exists is the one still
// working three years after the integration was decommissioned.
const maxTokenLifetime = 5 * 365 * 24 * time.Hour

func (s *Server) handleListAPITokens(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil {
		fail(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	// An owner sees every token; anyone else sees only their own. A reseller
	// being able to enumerate another tenant's credentials would tell them what
	// integrations exist and when they were last used.
	scopeTo := claims.AdminID
	if claims.Role == string(store.RoleOwner) {
		scopeTo = 0
	}
	toks, err := s.db.ListAPITokens(scopeTo)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if toks == nil {
		toks = []store.APIToken{}
	}
	c.JSON(http.StatusOK, gin.H{
		"tokens": toks,
		"scopes": store.ValidScopes(),
		// Said plainly, because the UI cannot offer a "reveal" later and an
		// operator who assumes it can will not write the token down.
		"note": "the secret is shown once at creation and is not stored; it cannot be recovered",
	})
}

func (s *Server) handleCreateAPIToken(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil {
		fail(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	var req struct {
		Name string `json:"name"`
		// Scope is required and deliberately has NO default. Defaulting would
		// mean a caller who omits it gets whatever the panel guessed, and the
		// safe guess ("read") silently breaks integrations while the useful
		// guess ("admin") silently over-grants.
		Scope     string `json:"scope"`
		ExpiresIn string `json:"expires_in"` // Go duration, e.g. "720h"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		fail(c, http.StatusBadRequest,
			"a token needs a name: a list of anonymous credentials cannot be audited or safely revoked")
		return
	}
	scope := store.TokenScope(req.Scope)
	valid := false
	for _, v := range store.ValidScopes() {
		if v == scope {
			valid = true
		}
	}
	if !valid {
		apierr.Fail(c, &apierr.Error{Op: "api-token-create", Kind: apierr.KindValidation,
			Message: fmt.Sprintf("unknown scope %q", req.Scope),
			Details: map[string]any{"scopes": store.ValidScopes()}})
		return
	}

	var expires *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 {
			fail(c, http.StatusBadRequest,
				"expires_in must be a positive Go duration, e.g. \"720h\" for 30 days")
			return
		}
		if d > maxTokenLifetime {
			fail(c, http.StatusBadRequest,
				fmt.Sprintf("expires_in exceeds the %s maximum", maxTokenLifetime))
			return
		}
		t := time.Now().Add(d)
		expires = &t
	}

	plaintext, prefix, hash, err := auth.NewAPIToken()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	tok := &store.APIToken{
		Name: req.Name, AdminID: claims.AdminID, Scope: scope,
		Prefix: prefix, Hash: hash, ExpiresAt: expires,
	}
	if err := s.db.CreateAPIToken(tok); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}

	// The scope is audited but the secret never is — an audit trail that records
	// the credential it is auditing is a second place secrets live.
	s.auditNote(c, "apitoken.create", req.Name,
		fmt.Sprintf("scope: %s; prefix: %s", scope, prefix))

	c.JSON(http.StatusCreated, gin.H{
		"token": tok,
		// The ONLY time this value exists outside the caller's own memory.
		"secret": plaintext,
		"note":   "copy this now: it is not stored and cannot be shown again",
	})
}

func (s *Server) handleRevokeAPIToken(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	if claims == nil {
		fail(c, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid token id")
		return
	}
	toks, err := s.db.ListAPITokens(0)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	var found *store.APIToken
	for i := range toks {
		if toks[i].ID == uint(id) {
			found = &toks[i]
		}
	}
	if found == nil {
		fail(c, http.StatusNotFound, "no such token")
		return
	}
	// Anyone may revoke their own; only an owner may revoke someone else's.
	// Revocation is the safe direction, so this is permissive on purpose — the
	// dangerous mistake is being unable to kill a leaked credential quickly.
	if found.AdminID != claims.AdminID && claims.Role != string(store.RoleOwner) {
		fail(c, http.StatusForbidden, "this token belongs to another account")
		return
	}
	if err := s.db.RevokeAPIToken(found.ID, time.Now()); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.auditNote(c, "apitoken.revoke", found.Name, "prefix: "+found.Prefix)
	c.Status(http.StatusNoContent)
}
