package api

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// generateRecoveryCodes mints a fresh set of one-time 2FA recovery codes for an
// admin, persisting ONLY their hashes and returning the plaintext codes for a
// single display. It replaces any previous set (regeneration invalidates old
// codes). Never logs the codes.
func (s *Server) generateRecoveryCodes(adminID uint, n int) ([]string, error) {
	codes, err := auth.RecoveryCodes(n)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, auth.HashRecoveryCode(c))
	}
	raw, _ := json.Marshal(hashes)
	if err := s.db.SetAdminRecoveryCodes(adminID, string(raw)); err != nil {
		return nil, err
	}
	return codes, nil
}

// recoveryRemaining reports how many unused recovery-code hashes an admin has.
func recoveryRemaining(codesJSON string) int {
	if codesJSON == "" {
		return 0
	}
	var hashes []string
	if json.Unmarshal([]byte(codesJSON), &hashes) != nil {
		return 0
	}
	return len(hashes)
}

// handle2FASetup generates a TOTP secret + otpauth URI for the current admin,
// without enabling it yet (spec §12). The panel renders the URI as a QR.
func (s *Server) handle2FASetup(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	// Stash the pending secret in settings until confirmed. A write that fails
	// here would hand the admin a QR code that 2fa/enable can never match, so it
	// is reported rather than discarded.
	if err := s.knobs().Set("pending_totp_"+claims.Username, secret); err != nil {
		failErr(c, 500, err)
		return
	}
	uri := auth.TOTPURI("ForgePanel", claims.Username, secret)
	c.JSON(200, gin.H{"secret": secret, "otpauth_url": uri})
}

// handle2FAEnable verifies a code against the pending secret and turns on 2FA,
// returning single-use recovery codes.
func (s *Server) handle2FAEnable(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	secret := s.knobs().String("pending_totp_" + claims.Username)
	if secret == "" {
		fail(c, 400, "run 2fa/setup first")
		return
	}
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	// Claimed against the account even though the secret is still the pending
	// one: the code being spent here is a code for the secret that is about to
	// become the account's, and leaving it unspent would let the same code be
	// replayed straight back at 2fa/disable.
	if !s.claimTOTP(admin, secret, req.Code) {
		fail(c, 400, "invalid code")
		return
	}
	admin.TOTPSecret = secret
	_ = s.db.SaveAdmin(admin)
	_ = s.knobs().Set("pending_totp_"+claims.Username, "")
	// Persist HASHES of the recovery codes; return the plaintext exactly once.
	codes, err := s.generateRecoveryCodes(admin.ID, 8)
	if err != nil {
		fail(c, 500, "could not generate recovery codes")
		return
	}
	// Adding a factor changes what an authenticated session means, so sessions
	// minted before 2FA existed are revoked. The caller keeps working via the
	// fresh pair below.
	_ = s.db.BumpAdminSessionEpoch(admin.ID)
	s.audit(c, "2fa.enable", claims.Username)
	s.audit(c, "2fa.recovery.generate", claims.Username)
	s.audit(c, "sessions.revoke", claims.Username)
	resp := gin.H{"enabled": true, "recovery_codes": codes, "sessions_revoked": true}
	if epoch, err := s.db.AdminSessionEpoch(admin.ID); err == nil {
		if access, refresh, err := s.signer.IssueAt(admin.ID, admin.Username, string(admin.Role), epoch); err == nil {
			resp["access_token"], resp["refresh_token"] = access, refresh
		}
	}
	c.JSON(200, resp)
}

// handle2FADisable turns off 2FA after verifying a current code.
func (s *Server) handle2FADisable(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req struct {
		Code string `json:"code"`
	}
	_ = c.ShouldBindJSON(&req)
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	if admin.TOTPSecret == "" {
		c.JSON(200, gin.H{"enabled": false})
		return
	}
	if !s.claimTOTP(admin, admin.TOTPSecret, req.Code) {
		fail(c, 400, "invalid code")
		return
	}
	admin.TOTPSecret = ""
	admin.RecoveryCodes = "" // invalidate recovery codes when 2FA is turned off
	_ = s.db.SaveAdmin(admin)
	// Dropping a factor changes what every existing session was authenticated
	// with, so revoke them and make the operator sign in again under the new
	// (weaker) policy rather than leaving pre-existing sessions in place.
	_ = s.db.BumpAdminSessionEpoch(admin.ID)
	s.audit(c, "2fa.disable", claims.Username)
	s.audit(c, "sessions.revoke", claims.Username)
	c.JSON(200, gin.H{"enabled": false, "sessions_revoked": true})
}

// handle2FARecoveryStatus reports how many unused recovery codes remain (never
// the codes themselves) so the UI can prompt regeneration when the set runs low
// or was never generated (existing 2FA admins after upgrade).
func (s *Server) handle2FARecoveryStatus(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, gin.H{
		"enabled":   admin.TOTPSecret != "",
		"remaining": recoveryRemaining(admin.RecoveryCodes),
	})
}

// handle2FARecoveryRegenerate issues a fresh recovery-code set, invalidating the
// previous one. It requires reauthentication (a current TOTP code or the account
// password) so a hijacked session can't silently mint new codes.
func (s *Server) handle2FARecoveryRegenerate(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	_ = c.ShouldBindJSON(&req)
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	if admin.TOTPSecret == "" {
		fail(c, 400, "enable 2FA first")
		return
	}
	reauthed := false
	if req.Code != "" && s.claimTOTP(admin, admin.TOTPSecret, req.Code) {
		reauthed = true
	} else if req.Password != "" {
		if ok, _ := auth.VerifyPassword(req.Password, admin.PasswordHash); ok {
			reauthed = true
		}
	}
	if !reauthed {
		fail(c, 401, "reauthentication required: provide a current 2FA code or your password")
		return
	}
	codes, err := s.generateRecoveryCodes(admin.ID, 8)
	if err != nil {
		fail(c, 500, "could not generate recovery codes")
		return
	}
	s.audit(c, "2fa.recovery.regenerate", claims.Username)
	c.JSON(200, gin.H{"recovery_codes": codes})
}

// handleChangePassword updates the current admin's password (argon2id).
func (s *Server) handleChangePassword(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.New) < 8 {
		fail(c, 400, "new password must be >= 8 chars")
		return
	}
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	if ok, _ := auth.VerifyPassword(req.Old, admin.PasswordHash); !ok {
		fail(c, 401, "current password incorrect")
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	admin.PasswordHash = hash
	_ = s.db.SaveAdmin(admin)
	// A credential reset must not leave sessions minted under the old password
	// alive, or changing a leaked password would not actually evict the intruder.
	_ = s.db.BumpAdminSessionEpoch(admin.ID)
	s.audit(c, "password.change", claims.Username)
	s.audit(c, "sessions.revoke", claims.Username)
	// The caller's own token is now stale too; hand back a fresh pair so the UI
	// does not bounce the operator to the login screen for their own action.
	epoch, _ := s.db.AdminSessionEpoch(admin.ID)
	access, refresh, err := s.signer.IssueAt(admin.ID, admin.Username, string(admin.Role), epoch)
	if err != nil {
		c.JSON(200, gin.H{"ok": true, "sessions_revoked": true})
		return
	}
	c.JSON(200, gin.H{"ok": true, "sessions_revoked": true,
		"access_token": access, "refresh_token": refresh})
}

// claimTOTP verifies a code and spends its time step, so the same code cannot be
// used twice.
//
// RFC 6238 §5.2 requires a verifier to accept each one-time password only once.
// A code stays valid across the ±1-step skew window — up to 90 seconds — so
// without this an observed code (shoulder-surfed, phished, captured by a proxy)
// can be replayed for the rest of that window. Login has always claimed the
// step; these management flows did not, which left the more dangerous
// operations as the unprotected ones: a replayed code here turns 2FA OFF or
// mints a fresh set of recovery codes.
//
// The claim is a conditional UPDATE rather than a read-then-write, so two
// concurrent requests carrying the same code cannot both succeed.
func (s *Server) claimTOTP(admin *store.Admin, secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	step, ok := auth.VerifyTOTPStep(secret, code, time.Now(), admin.LastTOTPStep)
	if !ok {
		return false
	}
	claimed, err := s.db.ClaimTOTPStep(admin.ID, step)
	if err != nil || !claimed {
		return false
	}
	// Keep the in-memory copy in step with the row, so a later SaveAdmin in the
	// same handler cannot write back the stale value and un-spend the code.
	admin.LastTOTPStep = step
	return true
}
