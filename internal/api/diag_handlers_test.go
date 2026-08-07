package api

import (
	"encoding/json"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestValidateInboundReportsFindings(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.POST("/api/admin/inbounds/validate", s.handleValidateInbound)
	// A plaintext-as-secure inbound (security none over tcp) must be flagged.
	rec := dreq(t, r, "POST", "/api/admin/inbounds/validate",
		`{"protocol":"vless","port":80,"transport":{"network":"tcp"},"security":{"type":"none"}}`)
	if rec.Code != 200 {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK       bool `json:"ok"`
		Findings []struct {
			Code    string `json:"code"`
			TitleFA string `json:"title_fa"`
		} `json:"findings"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	found := false
	for _, f := range out.Findings {
		if f.Code == "FP-TLS-002" {
			found = true
			if f.TitleFA == "" {
				t.Error("finding missing Farsi text")
			}
		}
	}
	if !found {
		t.Fatalf("plaintext-as-secure not flagged: %+v", out.Findings)
	}
}

func TestDoctorRunsBattery(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.GET("/api/admin/doctor", s.handleDoctor)
	rec := dreq(t, r, "GET", "/api/admin/doctor", "")
	if rec.Code != 200 {
		t.Fatalf("doctor: %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"system_findings", "inbounds", "health", "ok"} {
		if _, present := out[k]; !present {
			t.Fatalf("doctor report missing %q", k)
		}
	}
}
