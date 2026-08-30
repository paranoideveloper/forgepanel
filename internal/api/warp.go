package api

// Cloudflare WARP as an outbound the panel owns.
//
// WARP is free egress on an address that is not the VPS's own, which is useful
// both for giving traffic a different exit and for reaching things the
// datacentre's own IP is blocked from. Once an account exists it is an ordinary
// WireGuard outbound, so all of this is account lifecycle: register, optionally
// attach a WARP+ license, render, and rotate the endpoint on a schedule.
//
// SCOPE, stated because it is not obvious from the outside: operator outbounds
// are rendered into the XRAY config only (engine.RenderOutbounds feeds
// multi.go's xrayCfg; the sing-box config is assembled from direct plus the
// egress chains and never sees them). So the provisioned outbound is an Xray
// one. internal/warp renders both shapes because the account is the same either
// way, but nothing here can put a WireGuard outbound in front of a sing-box
// inbound today, and pretending otherwise would produce a tag no rule can
// reach.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"github.com/forgepanel/forgepanel/internal/protocol/render"
	"github.com/forgepanel/forgepanel/internal/store"
	"github.com/forgepanel/forgepanel/internal/warp"
)

// warpAccountKey holds the registered device as JSON.
//
// It carries a private key and a bearer token. It is a registered def with
// ScopeInternal rather than a raw key: everything goes through the registry
// (internal/settings enforces that), and ScopeInternal is what keeps it out of
// GET /api/admin/settings/registry, which serves every non-internal def to the
// UI. Nothing reads it back to a client — handleWarpStatus reports whether an
// account exists, never the account.
const warpAccountKey = "warp_account"

// warpDefaultTag is the outbound tag rules refer to.
const warpDefaultTag = "warp"

// warpRotateKey stores the rotation cadence in whole hours. Absent or
// non-positive means rotation is off.
const warpRotateKey = "warp_rotate_hours"

type warpStatusView struct {
	Configured bool   `json:"configured"`
	Premium    bool   `json:"premium"`
	Endpoint   string `json:"endpoint"`
	Tag        string `json:"tag"`
	// OutboundExists distinguishes "registered" from "actually routable". They
	// come apart when the outbound row is deleted directly, which leaves an
	// account that looks configured and a tag no rule can select.
	OutboundExists bool `json:"outbound_exists"`
	Enabled        bool `json:"enabled"`
	// RotateHours is the scheduled rotation cadence; 0 means it is off.
	RotateHours int `json:"rotate_hours"`
}

func (s *Server) storedWarpAccount() (warp.Account, bool) {
	var acct warp.Account
	raw := s.knobs().String(warpAccountKey)
	if strings.TrimSpace(raw) == "" {
		return acct, false
	}
	if err := json.Unmarshal([]byte(raw), &acct); err != nil {
		return warp.Account{}, false
	}
	return acct, acct.PrivateKey != ""
}

func (s *Server) handleWarpStatus(c *gin.Context) {
	view := warpStatusView{Tag: warpDefaultTag}
	acct, ok := s.storedWarpAccount()
	if ok {
		view.Configured = true
		view.Premium = acct.Premium
		view.Endpoint = acct.Endpoint
	}
	if ob := s.warpOutbound(); ob != nil {
		view.OutboundExists = true
		view.Enabled = ob.Enabled
		view.Tag = ob.Tag
	}
	view.RotateHours = int(warpRotateInterval(s.knobs().String(warpRotateKey)) / time.Hour)
	c.JSON(http.StatusOK, view)
}

// warpOutbound finds the provisioned row, by tag.
func (s *Server) warpOutbound() *store.Outbound {
	obs, err := s.db.ListOutbounds()
	if err != nil {
		return nil
	}
	for i := range obs {
		if obs[i].Tag == warpDefaultTag {
			return &obs[i]
		}
	}
	return nil
}

type warpProvisionRequest struct {
	// License attaches WARP+ to the device. Optional: a free account works, it
	// is simply rate-limited by Cloudflare.
	License string `json:"license"`
	// Endpoint overrides the address dialled, for a host where the default is
	// blocked. Empty takes warp.DefaultEndpoint.
	Endpoint string `json:"endpoint"`
	// Reregister mints a NEW device even though one is stored. The default is to
	// keep the existing account, because re-registering silently discards a
	// WARP+ license that was attached to the old device and cannot be moved.
	Reregister bool `json:"reregister"`
	// RotateHours sets the scheduled rotation cadence in whole hours. A pointer
	// so that omitting it leaves the existing schedule alone: provisioning again
	// to attach a license must not silently switch rotation off.
	RotateHours *int `json:"rotate_hours"`
}

// handleWarpProvision registers a device if needed and writes the outbound.
func (s *Server) handleWarpProvision(c *gin.Context) {
	var req warpProvisionRequest
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		failErr(c, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	hc := netegress.Client(30 * time.Second)

	acct, have := s.storedWarpAccount()
	if !have || req.Reregister {
		fresh, err := warp.Register(ctx, hc)
		if err != nil {
			failErr(c, http.StatusBadGateway, err)
			return
		}
		acct = fresh
	}
	if e := strings.TrimSpace(req.Endpoint); e != "" {
		acct.Endpoint = e
	}
	if lic := strings.TrimSpace(req.License); lic != "" {
		updated, err := warp.ActivateLicense(ctx, hc, acct, lic)
		if err != nil {
			// The device is registered and usable without WARP+, so persist it
			// before reporting the license failure. Discarding it here would
			// burn a registration on every mistyped key.
			s.persistWarp(acct)
			failErr(c, http.StatusBadGateway, err)
			return
		}
		acct = updated
	}

	if err := s.writeWarpOutbound(c, acct); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	if req.RotateHours != nil {
		n := *req.RotateHours
		if n < 0 {
			n = 0
		}
		_ = s.knobs().Set(warpRotateKey, strconv.Itoa(n))
		// Start the clock now, so enabling a schedule does not immediately fire
		// against a zero timestamp.
		acct.RotatedAt = time.Now().UTC()
	}
	s.persistWarp(acct)
	s.audit(c, "routing.warp.provisioned", acct.Endpoint)
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, warpStatusView{
		Configured: true, Premium: acct.Premium, Endpoint: acct.Endpoint,
		Tag: warpDefaultTag, OutboundExists: true, Enabled: true,
		RotateHours: int(warpRotateInterval(s.knobs().String(warpRotateKey)) / time.Hour),
	})
}

// handleWarpRotate moves the account to a different WARP address.
//
// Rotation changes which address a censor sees; every endpoint in the pool
// terminates on the same Cloudflare edge, so it does not change where traffic
// comes out and does not need re-registration.
func (s *Server) handleWarpRotate(c *gin.Context) {
	acct, ok := s.storedWarpAccount()
	if !ok {
		fail(c, http.StatusNotFound, "no WARP account is registered, so there is no endpoint to rotate")
		return
	}
	before := acct.Endpoint
	acct.Endpoint = warp.NextEndpoint(acct.Endpoint)
	// Stamped here too: a manual rotation restarts the scheduled interval, so
	// the schedule does not fire again moments after an operator just rotated.
	acct.RotatedAt = time.Now().UTC()
	if err := s.writeWarpOutbound(c, acct); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	s.persistWarp(acct)
	s.audit(c, "routing.warp.rotated", before+" -> "+acct.Endpoint)
	s.startBackground(s.reloadEngines)
	c.JSON(http.StatusOK, gin.H{"endpoint": acct.Endpoint, "previous": before})
}

// handleWarpDelete removes the outbound and forgets the device.
func (s *Server) handleWarpDelete(c *gin.Context) {
	if ob := s.warpOutbound(); ob != nil {
		if err := s.db.DeleteOutbound(ob.ID); err != nil {
			// The store refuses while a rule still targets it, because removing
			// it anyway leaves the core rejecting the entire config.
			failErr(c, http.StatusConflict, err)
			return
		}
	}
	_ = s.knobs().Set(warpAccountKey, "")
	s.audit(c, "routing.warp.removed", warpDefaultTag)
	s.startBackground(s.reloadEngines)
	c.Status(http.StatusNoContent)
}

func (s *Server) persistWarp(acct warp.Account) {
	raw, err := json.Marshal(acct)
	if err != nil {
		return
	}
	_ = s.knobs().Set(warpAccountKey, string(raw))
}

// writeWarpOutbound renders the account and saves it as the WARP outbound,
// inside the same checkpoint every other outbound edit uses: the core is the
// only authority on whether a config is acceptable, so a render that the core
// rejects must roll back rather than wait to break the next reload.
func (s *Server) writeWarpOutbound(c *gin.Context, acct warp.Account) error {
	prev, err := s.saveWarpOutbound(acct)
	if err != nil {
		return err
	}
	if !s.validateRoutingOrFail(c) {
		s.rollbackOutbound(prev, warpOutboundID(s))
		// validateRoutingOrFail has already written the response describing what
		// the core objected to.
	}
	return nil
}

func warpOutboundID(s *Server) uint {
	if ob := s.warpOutbound(); ob != nil {
		return ob.ID
	}
	return 0
}

// saveWarpOutbound renders the account and writes the row, returning whatever
// was there before so a caller that validates can roll back.
func (s *Server) saveWarpOutbound(acct warp.Account) (*store.Outbound, error) {
	n, err := warp.Node(acct)
	if err != nil {
		return nil, err
	}
	out, err := render.XrayOutbound(n)
	if err != nil {
		return nil, err
	}
	settings, err := json.Marshal(out["settings"])
	if err != nil {
		return nil, err
	}

	prev := s.warpOutbound()
	ob := store.Outbound{
		Tag:      warpDefaultTag,
		Protocol: "wireguard",
		Enabled:  true,
		Note:     "Cloudflare WARP, managed by the panel",
	}
	if prev != nil {
		// Keep the row's identity and the operator's own choices: SortOrder
		// decides which outbound is the core's default, and resetting it on
		// every rotation would silently move where unmatched traffic goes.
		ob.ID = prev.ID
		ob.SortOrder = prev.SortOrder
		ob.Enabled = prev.Enabled
		ob.SendThrough = prev.SendThrough
		if strings.TrimSpace(prev.Note) != "" {
			ob.Note = prev.Note
		}
	}
	if err := ob.SetSettings(settings); err != nil {
		return nil, err
	}
	if err := s.db.SaveOutbound(&ob); err != nil {
		return nil, err
	}
	return prev, nil
}

// rotateWarpIfDue is the scheduled half of rotation.
//
// It hangs off runMaintenance rather than taking a scheduler field of its own:
// the Config comment is explicit that a scheduler with a field per chore
// accumulates fields nobody wires up, and this one only needs to be asked
// often enough to notice its own interval has passed. So the cadence lives
// here, in the stored account, rather than in the scheduler.
func (s *Server) rotateWarpIfDue() {
	if s.db == nil {
		return
	}
	every := warpRotateInterval(s.knobs().String(warpRotateKey))
	if every <= 0 {
		return
	}
	acct, ok := s.storedWarpAccount()
	if !ok {
		return
	}
	// A zero RotatedAt is an account provisioned before rotation was switched
	// on. Stamping it rather than rotating immediately means enabling rotation
	// does not itself change the endpoint — the operator asked for a schedule,
	// not for a change right now.
	if acct.RotatedAt.IsZero() {
		acct.RotatedAt = time.Now().UTC()
		s.persistWarp(acct)
		return
	}
	if time.Since(acct.RotatedAt) < every {
		return
	}
	before := acct.Endpoint
	acct.Endpoint = warp.NextEndpoint(acct.Endpoint)
	acct.RotatedAt = time.Now().UTC()
	if _, err := s.saveWarpOutbound(acct); err != nil {
		// Leave RotatedAt alone on failure so the next sweep tries again rather
		// than waiting out a whole interval on a rotation that never happened.
		return
	}
	s.persistWarp(acct)
	if s.db != nil {
		s.db.Audit(&store.AuditLog{Actor: "system", Action: "routing.warp.rotated",
			Target: before + " -> " + acct.Endpoint})
	}
	s.startBackground(s.reloadEngines)
}

// warpRotateInterval parses the stored cadence in hours. Anything unparseable
// or non-positive disables rotation, which is the safe reading: a typo must not
// turn into a rotation every sweep.
func warpRotateInterval(raw string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Hour
}
