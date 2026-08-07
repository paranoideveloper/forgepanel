package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/store"
)

func domainsRouter(s *Server) *gin.Engine {
	r := gin.New()
	g := r.Group("/api/admin")
	g.GET("/domains", s.handleListDomains)
	g.POST("/domains", s.handleCreateDomain)
	g.PUT("/domains/:id", s.handleUpdateDomain)
	g.DELETE("/domains/:id", s.handleDeleteDomain)
	g.GET("/domains-status", s.handleDomainStatus)
	g.POST("/inbounds", s.handleCreateInbound)
	g.POST("/inbounds/reality-quickstart", s.handleRealityQuickstart)
	g.POST("/inbounds/:id/tls", s.handleInboundOneClickTLS)
	return r
}

func dreq(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestFirstDomainBecomesDefaultAndCascades: adding the first domain makes it the
// default, and a subsequently-created inbound inherits it and cascades SNI/Host.
func TestFirstDomainBecomesDefaultAndCascades(t *testing.T) {
	s := dbServerT(t)
	r := domainsRouter(s)

	if rec := dreq(t, r, "POST", "/api/admin/domains", `{"name":"vpn.example.com"}`); rec.Code != 201 {
		t.Fatalf("create domain: %d %s", rec.Code, rec.Body.String())
	}
	if got := s.db.DefaultDomain(); got != "vpn.example.com" {
		t.Fatalf("first domain should be default, got %q", got)
	}

	// Create a VLESS-WS-TLS inbound with NO domain field — it must inherit + cascade.
	rec := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":8443,"remark":"x","transport":{"network":"ws"},"security":{"type":"tls"}}`)
	if rec.Code != 201 {
		t.Fatalf("create inbound: %d %s", rec.Code, rec.Body.String())
	}
	var cr struct {
		ID uint `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &cr)
	in, err := s.db.InboundByID(cr.ID)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := in.Node()
	if n.Domain != "vpn.example.com" {
		t.Errorf("inbound did not inherit default domain: %q", n.Domain)
	}
	if n.Security.ServerName != "vpn.example.com" {
		t.Errorf("SNI not cascaded: %q", n.Security.ServerName)
	}
	if n.Transport.Host != "vpn.example.com" {
		t.Errorf("WS Host not cascaded: %q", n.Transport.Host)
	}
}

// TestDomainStatusGuidesWhenNoDomain: with no domain, status is loud and offers
// REALITY as the recommended domain-free path (never silently plaintext).
func TestDomainStatusGuidesWhenNoDomain(t *testing.T) {
	s := dbServerT(t)
	r := domainsRouter(s)
	rec := dreq(t, r, "GET", "/api/admin/domains-status", "")
	var st struct {
		HasDomain  bool `json:"has_domain"`
		DomainFree []struct {
			Protocol    string `json:"protocol"`
			Recommended bool   `json:"recommended"`
		} `json:"domain_free"`
		GuidanceEN string `json:"guidance_en"`
		GuidanceFA string `json:"guidance_fa"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.HasDomain {
		t.Fatal("has_domain should be false")
	}
	if st.GuidanceEN == "" || st.GuidanceFA == "" {
		t.Fatal("guidance must be present in English AND Farsi")
	}
	rec1 := false
	for _, p := range st.DomainFree {
		if p.Protocol == "vless" && p.Recommended {
			rec1 = true
		}
	}
	if !rec1 {
		t.Fatal("REALITY (vless) must be the recommended domain-free option")
	}
}

// TestRealityQuickstartCreatesConnectableInbound: one click, zero inputs, a real
// REALITY inbound with minted keys.
func TestRealityQuickstartCreatesConnectableInbound(t *testing.T) {
	s := dbServerT(t)
	r := domainsRouter(s)
	rec := dreq(t, r, "POST", "/api/admin/inbounds/reality-quickstart", `{}`)
	if rec.Code != 201 {
		t.Fatalf("quickstart: %d %s", rec.Code, rec.Body.String())
	}
	ins, _ := s.db.ListInbounds()
	if len(ins) != 1 {
		t.Fatalf("expected 1 inbound, got %d", len(ins))
	}
	n, _ := ins[0].Node()
	if n.Security.Type != "reality" || n.Security.Reality == nil {
		t.Fatalf("not a REALITY inbound: %+v", n.Security)
	}
	if n.Security.Reality.PrivateKey == "" || n.Security.Reality.PublicKey == "" {
		t.Fatal("REALITY keypair was not minted")
	}
}

// TestOneClickTLSAppliesAndReportsPreflightHonestly: the TLS config is applied,
// and because the test domain does not resolve to this host, the response says
// so instead of claiming success.
func TestOneClickTLSAppliesAndReportsPreflightHonestly(t *testing.T) {
	s := dbServerT(t)
	r := domainsRouter(s)
	dreq(t, r, "POST", "/api/admin/domains", `{"name":"tls.example.com"}`)
	cr := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":9443,"remark":"t","transport":{"network":"tcp"},"security":{"type":"none"}}`)
	var c struct {
		ID uint `json:"id"`
	}
	json.Unmarshal(cr.Body.Bytes(), &c)

	rec := dreq(t, r, "POST", "/api/admin/inbounds/"+strconv.FormatUint(uint64(c.ID), 10)+"/tls", `{"domain":"tls.example.com"}`)
	if rec.Code != 200 {
		t.Fatalf("one-click tls: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Applied bool   `json:"applied"`
		TLS     string `json:"tls"`
		Ready   bool   `json:"ready"`
		Note    string `json:"note"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Applied || resp.TLS != "acme" {
		t.Fatalf("tls not applied: %+v", resp)
	}
	in, _ := s.db.InboundByID(c.ID)
	n, _ := in.Node()
	if n.Security.Type != "tls" || n.Security.ServerName != "tls.example.com" {
		t.Fatalf("inbound not switched to TLS on the domain: %+v", n.Security)
	}
	// The non-resolving domain must be reported honestly, not as ready.
	if resp.Ready {
		t.Fatal("preflight claimed ready for a domain that does not resolve here")
	}
}

// TestDeleteDomainInUseIsRefused: a domain still on an inbound cannot be deleted
// without force, so links do not silently break.
func TestDeleteDomainInUseIsRefused(t *testing.T) {
	s := dbServerT(t)
	r := domainsRouter(s)
	dreq(t, r, "POST", "/api/admin/domains", `{"name":"used.example.com"}`)
	dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":7443,"remark":"u","transport":{"network":"ws"},"security":{"type":"tls"}}`)
	d, _ := s.db.DomainByName("used.example.com")
	rec := dreq(t, r, "DELETE", "/api/admin/domains/"+strconv.FormatUint(uint64(d.ID), 10), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleting an in-use domain should be 409, got %d %s", rec.Code, rec.Body.String())
	}
	// force deletes.
	if rec := dreq(t, r, "DELETE", "/api/admin/domains/"+strconv.FormatUint(uint64(d.ID), 10)+"?force=true", ""); rec.Code != 200 {
		t.Fatalf("force delete: %d %s", rec.Code, rec.Body.String())
	}
}

var _ = store.Domain{}

// TestOverviewEndpointShape locks the dashboard endpoint the frontend needs
// (OverviewView was calling /api/health, which did not exist → a 404 on login).
func TestOverviewEndpointShape(t *testing.T) {
	s := dbServerT(t)
	r := gin.New()
	r.GET("/api/admin/overview", s.handleOverview)
	rec := dreq(t, r, "GET", "/api/admin/overview", "")
	if rec.Code != 200 {
		t.Fatalf("overview: %d", rec.Code)
	}
	var o struct {
		Status     string `json:"status"`
		NodesTotal int    `json:"nodes_total"`
		Uptime     int64  `json:"uptime_seconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.Status != "ok" {
		t.Fatalf("status=%q", o.Status)
	}
}
