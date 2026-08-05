package api

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
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
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// Stash the pending secret in settings until confirmed.
	s.db.SetSetting("pending_totp_"+claims.Username, secret)
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
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	secret := s.db.GetSetting("pending_totp_" + claims.Username)
	if secret == "" {
		c.JSON(400, gin.H{"error": "run 2fa/setup first"})
		return
	}
	if !auth.VerifyTOTP(secret, req.Code, time.Now()) {
		c.JSON(400, gin.H{"error": "invalid code"})
		return
	}
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	admin.TOTPSecret = secret
	_ = s.db.SaveAdmin(admin)
	s.db.SetSetting("pending_totp_"+claims.Username, "")
	// Persist HASHES of the recovery codes; return the plaintext exactly once.
	codes, err := s.generateRecoveryCodes(admin.ID, 8)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not generate recovery codes"})
		return
	}
	s.audit(c, "2fa.enable", claims.Username)
	s.audit(c, "2fa.recovery.generate", claims.Username)
	c.JSON(200, gin.H{"enabled": true, "recovery_codes": codes})
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
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if admin.TOTPSecret == "" {
		c.JSON(200, gin.H{"enabled": false})
		return
	}
	if !auth.VerifyTOTP(admin.TOTPSecret, req.Code, time.Now()) {
		c.JSON(400, gin.H{"error": "invalid code"})
		return
	}
	admin.TOTPSecret = ""
	admin.RecoveryCodes = "" // invalidate recovery codes when 2FA is turned off
	_ = s.db.SaveAdmin(admin)
	s.audit(c, "2fa.disable", claims.Username)
	c.JSON(200, gin.H{"enabled": false})
}

// handle2FARecoveryStatus reports how many unused recovery codes remain (never
// the codes themselves) so the UI can prompt regeneration when the set runs low
// or was never generated (existing 2FA admins after upgrade).
func (s *Server) handle2FARecoveryStatus(c *gin.Context) {
	claims, _ := auth.ClaimsFrom(c)
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
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
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if admin.TOTPSecret == "" {
		c.JSON(400, gin.H{"error": "enable 2FA first"})
		return
	}
	reauthed := false
	if req.Code != "" && auth.VerifyTOTP(admin.TOTPSecret, req.Code, time.Now()) {
		reauthed = true
	} else if req.Password != "" {
		if ok, _ := auth.VerifyPassword(req.Password, admin.PasswordHash); ok {
			reauthed = true
		}
	}
	if !reauthed {
		c.JSON(401, gin.H{"error": "reauthentication required: provide a current 2FA code or your password"})
		return
	}
	codes, err := s.generateRecoveryCodes(admin.ID, 8)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not generate recovery codes"})
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
		c.JSON(400, gin.H{"error": "new password must be >= 8 chars"})
		return
	}
	admin, err := s.db.AdminByUsername(claims.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if ok, _ := auth.VerifyPassword(req.Old, admin.PasswordHash); !ok {
		c.JSON(401, gin.H{"error": "current password incorrect"})
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	admin.PasswordHash = hash
	_ = s.db.SaveAdmin(admin)
	s.audit(c, "password.change", claims.Username)
	c.JSON(200, gin.H{"ok": true})
}
