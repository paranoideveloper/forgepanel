package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func opsRouter(s *Server) *gin.Engine {
	r := gin.New()
	g := r.Group("/api/admin")
	g.POST("/inbounds", s.handleCreateInbound)
	g.PUT("/inbounds/:id", s.handleUpdateInbound)
	g.POST("/inbounds/:id/clone", s.handleCloneInbound)
	g.POST("/inbounds/:id/toggle", s.handleToggleInbound)
	g.POST("/inbounds/:id/undo", s.handleUndoInbound)
	g.POST("/inbounds/bulk", s.handleBulkInbounds)
	return r
}

// TestSafeEditWarnsOnBreakingChange: changing a port must be refused without
// confirm, with the breaking change reported — never a silent orphan.
func TestSafeEditWarnsOnBreakingChange(t *testing.T) {
	s := dbServerT(t)
	r := opsRouter(s)
	cr := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":20443,"remark":"e","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	var c struct {
		ID uint `json:"id"`
	}
	json.Unmarshal(cr.Body.Bytes(), &c)
	id := strconv.FormatUint(uint64(c.ID), 10)

	// change the port without confirm -> 409 with breaking list
	rec := dreq(t, r, "PUT", "/api/admin/inbounds/"+id,
		`{"protocol":"vless","port":20444,"remark":"e","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("breaking edit without confirm: got %d want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "port") {
		t.Fatalf("breaking change not reported: %s", rec.Body.String())
	}
	// with confirm -> applied
	rec = dreq(t, r, "PUT", "/api/admin/inbounds/"+id+"?confirm=true",
		`{"protocol":"vless","port":20444,"remark":"e","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	if rec.Code != 200 {
		t.Fatalf("confirmed breaking edit: got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestUndoRestoresPreviousConfig.
func TestUndoRestoresPreviousConfig(t *testing.T) {
	s := dbServerT(t)
	r := opsRouter(s)
	cr := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":21443,"remark":"orig","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	var c struct {
		ID uint `json:"id"`
	}
	json.Unmarshal(cr.Body.Bytes(), &c)
	id := strconv.FormatUint(uint64(c.ID), 10)

	dreq(t, r, "PUT", "/api/admin/inbounds/"+id,
		`{"protocol":"vless","port":21443,"remark":"renamed","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	in, _ := s.db.InboundByID(c.ID)
	if in.Remark != "renamed" {
		t.Fatalf("edit not applied: %q", in.Remark)
	}
	rec := dreq(t, r, "POST", "/api/admin/inbounds/"+id+"/undo", "")
	if rec.Code != 200 {
		t.Fatalf("undo: %d %s", rec.Code, rec.Body.String())
	}
	in, _ = s.db.InboundByID(c.ID)
	if in.Remark != "orig" {
		t.Fatalf("undo did not restore the previous config: %q", in.Remark)
	}
}

// TestCloneAndToggle.
func TestCloneAndToggle(t *testing.T) {
	s := dbServerT(t)
	r := opsRouter(s)
	cr := dreq(t, r, "POST", "/api/admin/inbounds",
		`{"protocol":"vless","port":22443,"remark":"src","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
	var c struct {
		ID uint `json:"id"`
	}
	json.Unmarshal(cr.Body.Bytes(), &c)
	id := strconv.FormatUint(uint64(c.ID), 10)

	rec := dreq(t, r, "POST", "/api/admin/inbounds/"+id+"/clone", "")
	if rec.Code != 201 {
		t.Fatalf("clone: %d %s", rec.Code, rec.Body.String())
	}
	var cl struct {
		ID      uint `json:"id"`
		Port    int  `json:"port"`
		Enabled bool `json:"enabled"`
	}
	json.Unmarshal(rec.Body.Bytes(), &cl)
	if cl.Port == 22443 {
		t.Fatal("clone must get a fresh port")
	}
	if cl.Enabled {
		t.Fatal("clone must start disabled")
	}
	// toggle the clone on
	rec = dreq(t, r, "POST", "/api/admin/inbounds/"+strconv.FormatUint(uint64(cl.ID), 10)+"/toggle", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("toggle: %d %s", rec.Code, rec.Body.String())
	}
}

// TestBulkDisable.
func TestBulkDisable(t *testing.T) {
	s := dbServerT(t)
	r := opsRouter(s)
	var ids []uint
	for i := 0; i < 3; i++ {
		cr := dreq(t, r, "POST", "/api/admin/inbounds",
			`{"protocol":"vless","port":`+strconv.Itoa(23443+i)+`,"remark":"b","transport":{"network":"tcp"},"security":{"type":"reality"}}`)
		var c struct {
			ID uint `json:"id"`
		}
		json.Unmarshal(cr.Body.Bytes(), &c)
		ids = append(ids, c.ID)
	}
	body, _ := json.Marshal(map[string]any{"action": "disable", "ids": ids})
	rec := dreq(t, r, "POST", "/api/admin/inbounds/bulk", string(body))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"succeeded":3`) {
		t.Fatalf("bulk disable: %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range ids {
		in, _ := s.db.InboundByID(id)
		if in.Enabled {
			t.Fatalf("inbound %d still enabled after bulk disable", id)
		}
	}
}
