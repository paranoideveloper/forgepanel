package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forgepanel/forgepanel/internal/geoip"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/gin-gonic/gin"
)

func TestHandleGeoIP(t *testing.T) {
	s := dbServerT(t)
	owner := &store.Admin{Username: "o", Role: store.RoleOwner, PasswordHash: "x"}
	if err := s.db.CreateAdmin(owner); err != nil {
		t.Fatal(err)
	}
	tok, _, _ := s.signer.Issue(owner.ID, owner.Username, string(store.RoleOwner))

	// Point geoip at a mock so the handler test is deterministic and offline.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"country_code":"de"}`))
	}))
	defer mock.Close()
	oldP, oldC := geoip.Providers, geoip.HTTPClient
	geoip.Providers = []geoip.Provider{{URLTmpl: mock.URL + "/%s", Field: "country_code"}}
	geoip.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	defer func() { geoip.Providers, geoip.HTTPClient = oldP, oldC }()

	r := gin.New()
	r.Group("/api/admin", s.signer.Middleware()).GET("/geoip", s.handleGeoIP)

	req := httptest.NewRequest("GET", "/api/admin/geoip?host=203.0.113.9", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("geoip: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		CountryCode string `json:"country_code"`
		Flag        string `json:"flag"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.CountryCode != "DE" || out.Flag != "🇩🇪" {
		t.Fatalf("geoip response = %+v, want DE 🇩🇪", out)
	}
}
