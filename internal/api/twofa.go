package api

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
)

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
	codes, _ := auth.RecoveryCodes(8)
	s.audit(c, "2fa.enable", claims.Username)
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
	_ = s.db.SaveAdmin(admin)
	s.audit(c, "2fa.disable", claims.Username)
	c.JSON(200, gin.H{"enabled": false})
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
