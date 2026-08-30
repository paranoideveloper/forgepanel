package api

// CRUD for an inbound's public endpoints.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

// hostRequest is the create/update body. Pointers where a zero value is a
// legitimate setting, so "leave alone" and "set to false/0" stay distinct.
type hostRequest struct {
	Label         string `json:"label"`
	Remark        string `json:"remark"`
	Address       string `json:"address"`
	Port          *int   `json:"port"`
	Security      string `json:"security"`
	SNI           string `json:"sni"`
	HostHeader    string `json:"host_header"`
	Path          string `json:"path"`
	ALPN          string `json:"alpn"`
	Fingerprint   string `json:"fingerprint"`
	AllowInsecure *bool  `json:"allow_insecure"`
	Enabled       *bool  `json:"enabled"`
	Priority      *int   `json:"priority"`
}

// validSecurityOverride is the set an endpoint may ask for. "" means inherit.
func validSecurityOverride(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none", "tls", "reality":
		return true
	}
	return false
}

func (r hostRequest) validate() string {
	if r.Port != nil && (*r.Port < 0 || *r.Port > 65535) {
		return "port must be between 0 and 65535 (0 means inherit the inbound's port)"
	}
	if !validSecurityOverride(r.Security) {
		return `security must be one of "", "none", "tls" or "reality"`
	}
	if fp := strings.TrimSpace(r.Fingerprint); fp != "" {
		ok := false
		for _, v := range model.ValidFingerprints() {
			if strings.EqualFold(v, fp) {
				ok = true
				break
			}
		}
		if !ok {
			// A fingerprint the core does not know is not a harmless typo: uTLS
			// rejects it and the inbound refuses to start, so catching it here
			// keeps a bad endpoint from taking a working listener down.
			return "fingerprint must be one of: " + strings.Join(model.ValidFingerprints(), ", ")
		}
	}
	return ""
}

func (r hostRequest) apply(h *store.InboundHost) {
	h.Label = strings.TrimSpace(r.Label)
	h.Remark = strings.TrimSpace(r.Remark)
	h.Address = strings.TrimSpace(r.Address)
	h.Security = strings.ToLower(strings.TrimSpace(r.Security))
	h.SNI = strings.TrimSpace(r.SNI)
	h.HostHeader = strings.TrimSpace(r.HostHeader)
	h.Path = strings.TrimSpace(r.Path)
	h.ALPN = strings.TrimSpace(r.ALPN)
	h.Fingerprint = strings.ToLower(strings.TrimSpace(r.Fingerprint))
	if r.Port != nil {
		h.Port = *r.Port
	}
	if r.AllowInsecure != nil {
		h.AllowInsecure = *r.AllowInsecure
	}
	if r.Enabled != nil {
		h.Enabled = *r.Enabled
	}
	if r.Priority != nil {
		h.Priority = *r.Priority
	}
}

// handleListHosts returns an inbound's endpoints.
func (s *Server) handleListHosts(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid inbound id")
		return
	}
	hosts, err := s.db.HostsForInbound(uint(id))
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if hosts == nil {
		hosts = []store.InboundHost{}
	}
	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}

// handleCreateHost adds an endpoint to an inbound.
func (s *Server) handleCreateHost(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid inbound id")
		return
	}
	if _, err := s.db.InboundByID(uint(id)); err != nil {
		fail(c, http.StatusNotFound, "no such inbound")
		return
	}
	var req hostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if msg := req.validate(); msg != "" {
		fail(c, http.StatusBadRequest, msg)
		return
	}
	// New endpoints are live unless the caller says otherwise: adding one and
	// having it silently not appear reads as a bug.
	h := &store.InboundHost{InboundID: uint(id), Enabled: true}
	req.apply(h)
	if err := s.db.CreateHost(h); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "inbound.host.create", h.Label)
	c.JSON(http.StatusCreated, h)
}

// handleUpdateHost edits an endpoint.
func (s *Server) handleUpdateHost(c *gin.Context) {
	hid, err := strconv.ParseUint(c.Param("hostID"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid host id")
		return
	}
	h, err := s.db.HostByID(uint(hid))
	if err != nil {
		fail(c, http.StatusNotFound, "no such host")
		return
	}
	var req hostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if msg := req.validate(); msg != "" {
		fail(c, http.StatusBadRequest, msg)
		return
	}
	before, _ := json.Marshal(h)
	req.apply(h)
	if err := s.db.SaveHost(h); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	after, _ := json.Marshal(h)
	// The diffing audit, not the plain one: an endpoint edit changes exactly the
	// fields that decide whether a route still works, and "someone changed this
	// host" without saying what is not something anyone can act on afterwards.
	s.auditWithDiff(c, "inbound.host.update", h.Label, before, after)
	c.JSON(http.StatusOK, h)
}

// handleDeleteHost removes an endpoint.
func (s *Server) handleDeleteHost(c *gin.Context) {
	hid, err := strconv.ParseUint(c.Param("hostID"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid host id")
		return
	}
	h, err := s.db.HostByID(uint(hid))
	if err != nil {
		fail(c, http.StatusNotFound, "no such host")
		return
	}
	if err := s.db.DeleteHost(uint(hid)); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "inbound.host.delete", h.Label)
	c.JSON(http.StatusOK, gin.H{"deleted": hid})
}
