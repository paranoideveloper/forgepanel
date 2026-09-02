package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuth_MiddlewareAndRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	signer := NewSigner([]byte("secret-key-32-bytes-long-for-jwt"))

	// SetSessionValidator
	signer.SetSessionValidator(func(adminID, epoch uint) bool {
		return epoch >= 1
	})

	// Mint tokens (epoch 1 = valid, epoch 0 = revoked)
	validToken, _, err := signer.IssueAt(1, "admin", "owner", 1)
	if err != nil {
		t.Fatalf("IssueAt failed: %v", err)
	}
	revokedToken, _, err := signer.IssueAt(1, "admin", "owner", 0)
	if err != nil {
		t.Fatalf("IssueAt failed: %v", err)
	}

	r := gin.New()
	r.GET("/protected", signer.Middleware(), RequireRole("owner"), func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok || claims == nil {
			c.JSON(500, gin.H{"error": "no claims"})
			return
		}
		c.JSON(200, gin.H{"username": claims.Username})
	})

	// 1. Missing Token -> 401
	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 for missing token, got %d", w.Code)
	}

	// 2. Revoked Token -> 401
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+revokedToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 for revoked token, got %d", w.Code)
	}

	// 3. Valid Token -> 200
	req = httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 for valid token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuth_RecoveryAndTOTP(t *testing.T) {
	// Recovery Codes
	code := "ABCD-1234"
	hash := HashRecoveryCode(code)
	if !RecoveryCodeMatches(hash, code) {
		t.Fatalf("RecoveryCodeMatches expected true")
	}
	if RecoveryCodeMatches(hash, "WRONG-CODE") {
		t.Fatalf("RecoveryCodeMatches expected false for wrong code")
	}

	codes, err := RecoveryCodes(5)
	if err != nil || len(codes) != 5 {
		t.Fatalf("RecoveryCodes count mismatch: got %d, err %v", len(codes), err)
	}

	// TOTP URI
	uri := TOTPURI("ForgePanel", "admin@example.com", "JBSWY3DPEHPK3PXP")
	if uri == "" {
		t.Fatalf("TOTPURI returned empty string")
	}
}
