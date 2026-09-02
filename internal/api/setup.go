package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/auth"
	"github.com/forgepanel/forgepanel/internal/store"
)

// setupRequired reports whether first-run administrator setup is still pending
// (no admin account exists yet). It reads the live admin table, not a cached
// flag, so it can never wrongly gate an install that already has an owner.
func (s *Server) setupRequired() bool {
	if s.db == nil {
		return false
	}
	n, err := s.db.CountAdmins()
	return err == nil && n == 0
}

// handleSetupStatus (public) tells the frontend whether to show the first-run
// setup screen instead of the login form. It never reveals the setup token.
func (s *Server) handleSetupStatus(c *gin.Context) {
	c.JSON(200, gin.H{"setup_required": s.setupRequired()})
}

// handleSetupInit (public, token-gated, rate-limited) creates the first owner
// administrator. It is a no-op once any admin exists — the endpoint effectively
// disables itself after completion, and the one-time token is invalidated.
func (s *Server) handleSetupInit(c *gin.Context) {
	if s.db == nil {
		fail(c, 501, "this server has no user database")
		return
	}
	ip := c.ClientIP()
	if s.login != nil && !s.login.Allowed(ip) {
		fail(c, 429, "too many attempts; try again later")
		return
	}
	if !s.setupRequired() {
		fail(c, 409, "setup already completed")
		return
	}
	var req struct {
		Token           string `json:"token"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"password_confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	p := s.cfg.Panel()

	// Validate the one-time token (constant-time) and its expiry.
	if p.SetupToken == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(p.SetupToken)) != 1 {
		if s.login != nil {
			s.login.Fail(ip)
		}
		fail(c, 401, "invalid setup token")
		return
	}
	if exp, err := time.Parse(time.RFC3339, p.SetupExpires); err == nil && time.Now().After(exp) {
		fail(c, 401, "setup token expired — restart the panel to mint a new one")
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		fail(c, 400, "username is required")
		return
	}
	if req.Password != req.PasswordConfirm {
		fail(c, 400, "passwords do not match")
		return
	}
	if err := validatePasswordPolicy(req.Password); err != nil {
		failErr(c, 400, err)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		fail(c, 500, "hash password")
		return
	}
	if err := s.db.CreateAdmin(&store.Admin{
		Username: username, PasswordHash: hash, Role: store.RoleOwner,
	}); err != nil {
		fail(c, 500, "create admin")
		return
	}

	// Completion: invalidate token, mark setup done, disable the endpoint.
	p.SetupCompleted = true
	p.SetupToken, p.SetupExpires = "", ""
	_ = s.cfg.SavePanel()
	s.SetupToken = ""
	s.removeSetupToken()
	c.JSON(200, gin.H{"ok": true, "username": username})
}

// validatePasswordPolicy enforces a secure minimum: at least 10 characters and
// a mix of character classes. Kept deliberately simple and explicit so the UI
// can mirror it and the tests can pin it.
func validatePasswordPolicy(pw string) error {
	if len(pw) < 10 {
		return errPolicy("password must be at least 10 characters")
	}
	var hasLetter, hasDigit, hasOther bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLetter, hasDigit, hasOther} {
		if ok {
			classes++
		}
	}
	if classes < 2 {
		return errPolicy("password must combine at least two of: letters, digits, symbols")
	}
	return nil
}

type policyError string

func (e policyError) Error() string { return string(e) }
func errPolicy(msg string) error    { return policyError(msg) }

// removeSetupToken deletes the on-disk setup-token.txt helper file.
func (s *Server) removeSetupToken() {
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "setup-token.txt"))
}

// randHex returns nBytes of hex-encoded entropy (used for the setup token).
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// detectServerIP returns the primary outbound IPv4 of the host without sending
// any traffic (a connected UDP socket just selects the route). Falls back to
// 127.0.0.1 when no route can be determined.
func detectServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "127.0.0.1"
}
