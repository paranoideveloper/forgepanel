package api

// Reverse-tunnel bridges, from the panel.
//
// The panel manages the EXIT half only. The bridge box is by definition a
// machine in Iran the panel usually cannot reach — bought in someone else's
// name, on an ISP that blocks inbound connections — so its half is handed over
// as a bundle a person pastes there.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/bridge"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// bridgeManager returns the supervisor for the exit halves.
//
// On the Server, not a package singleton: two panels in one process would
// otherwise share one data directory and one process table.
func (s *Server) bridgeManager() *bridge.Manager {
	s.bridgeOnce.Do(func() {
		s.bridgeMgr = bridge.NewManager(s.cfg.DataDir)
	})
	return s.bridgeMgr
}

// bridgeSealer seals the shared token at rest.
func (s *Server) bridgeSealer() (dns.Encryptor, error) {
	return dns.NewAESGCMFromPassphrase(deriveSecret(s.cfg))
}

// specFor rebuilds a render spec from a stored row.
func (s *Server) specFor(b *store.Bridge) (bridge.Spec, error) {
	spec := bridge.Spec{
		Backend: b.Backend, ExitAddr: b.ExitAddr, TunnelPort: b.TunnelPort,
		Transport: b.Transport,
	}
	if len(b.Services) > 0 {
		if err := json.Unmarshal([]byte(b.Services), &spec.Services); err != nil {
			return spec, fmt.Errorf("stored services are unreadable: %w", err)
		}
	}
	enc, err := s.bridgeSealer()
	if err != nil {
		return spec, err
	}
	tok, err := enc.Decrypt(b.TokenEnc)
	if err != nil {
		return spec, fmt.Errorf("the shared token could not be decrypted: %w", err)
	}
	spec.Token = string(tok)
	return spec, nil
}

type bridgeRequest struct {
	Name       string           `json:"name"`
	Backend    string           `json:"backend"`
	ExitAddr   string           `json:"exit_addr"`
	TunnelPort int              `json:"tunnel_port"`
	Transport  string           `json:"transport"`
	Token      string           `json:"token"`
	Services   []bridge.Service `json:"services"`
	Enabled    *bool            `json:"enabled"`
}

// handleListBridgeBackends reports the available backends and what they can do.
func (s *Server) handleListBridgeBackends(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"backends": bridge.All()})
}

// handleListBridges returns every configured bridge with its live state.
func (s *Server) handleListBridges(c *gin.Context) {
	rows, err := s.db.ListBridges()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	live := map[string]bridge.Status{}
	for _, st := range s.bridgeManager().Status() {
		live[st.Name] = st
	}
	out := make([]gin.H, 0, len(rows))
	for i := range rows {
		b := rows[i]
		var svcs []bridge.Service
		_ = json.Unmarshal([]byte(b.Services), &svcs)
		row := gin.H{"id": b.ID, "name": b.Name, "backend": b.Backend,
			"exit_addr": b.ExitAddr, "tunnel_port": b.TunnelPort,
			"transport": b.Transport, "enabled": b.Enabled, "services": svcs}
		if st, ok := live[b.Name]; ok {
			row["state"] = st.State
			row["pid"] = st.PID
			row["restarts"] = st.Restarts
			row["last_error"] = st.LastErr
		} else {
			row["state"] = bridge.StateStopped
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, gin.H{"bridges": out})
}

// handleCreateBridge registers a bridge and starts its exit half.
func (s *Server) handleCreateBridge(c *gin.Context) {
	var req bridgeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		fail(c, http.StatusBadRequest, "a bridge needs a name")
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		// Generated rather than demanded: an operator asked to invent a shared
		// secret picks a memorable one, and this token is the whole of the
		// tunnel's authentication.
		tok, err := keygen.Password(32)
		if err != nil {
			failErr(c, http.StatusInternalServerError, err)
			return
		}
		req.Token = tok
	}
	spec := bridge.Spec{Backend: req.Backend, ExitAddr: req.ExitAddr,
		TunnelPort: req.TunnelPort, Transport: req.Transport,
		Token: req.Token, Services: req.Services}
	if err := spec.Validate(); err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	enc, err := s.bridgeSealer()
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	sealed, err := enc.Encrypt([]byte(req.Token))
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	svcJSON, _ := json.Marshal(spec.Services)
	row := &store.Bridge{
		Name: strings.TrimSpace(req.Name), Backend: spec.Backend,
		ExitAddr: spec.ExitAddr, TunnelPort: spec.TunnelPort, Transport: spec.Transport,
		TokenEnc: sealed, Services: svcJSON, Enabled: req.Enabled == nil || *req.Enabled,
	}
	if err := s.db.CreateBridge(row); err != nil {
		failErr(c, http.StatusConflict, err)
		return
	}
	s.audit(c, "bridge.create", row.Name+" ("+row.Backend+")")

	if row.Enabled {
		// Started in the BACKGROUND, deliberately. Bringing the exit half up
		// downloads the backend's binary on first use — frp's archive is 14 MB —
		// and a create request that blocks on that either times out in the
		// browser or holds a connection for minutes. The row is saved either
		// way, the bundle below is already useful, and the list endpoint reports
		// the exit's real state as it changes.
		go s.startBridgeAsync(row.ID, row.Name, spec)
	}
	bundle, err := bridge.Bundle(spec)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": row.ID, "name": row.Name, "bundle": bundle,
		"note": "the exit half is starting in the background; watch its state in the bridge list"})
}

// startBridgeAsync brings an exit half up away from the request path and records
// why if it fails.
//
// A failure here is not lost: it lands on the row, so the bridge list says
// "failed: address already in use" instead of just never turning green.
func (s *Server) startBridgeAsync(id uint, name string, spec bridge.Spec) {
	err := s.bridgeManager().Start(context.Background(), name, spec)
	row, lerr := s.db.BridgeByID(id)
	if lerr != nil {
		return
	}
	now := time.Now().UTC()
	if err != nil {
		row.LastError = err.Error()
		row.LastState = string(bridge.StateFailed)
		fmt.Fprintf(os.Stderr, "forgepanel: bridge %s did not start: %v\n", name, err)
	} else {
		row.LastError = ""
		row.LastState = string(bridge.StateRunning)
		row.LastSeen = &now
	}
	_ = s.db.SaveBridge(row)
}

// handleBridgeBundle returns the bridge-side instructions again.
func (s *Server) handleBridgeBundle(c *gin.Context) {
	row, err := s.db.BridgeByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such bridge")
		return
	}
	spec, err := s.specFor(row)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	bundle, err := bridge.Bundle(spec)
	if err != nil {
		failErr(c, http.StatusBadRequest, err)
		return
	}
	c.JSON(http.StatusOK, bundle)
}

// handleDeleteBridge stops and removes a bridge.
func (s *Server) handleDeleteBridge(c *gin.Context) {
	row, err := s.db.BridgeByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such bridge")
		return
	}
	s.bridgeManager().Stop(row.Name)
	if err := s.db.DeleteBridge(row.ID); err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	s.audit(c, "bridge.delete", row.Name)
	c.JSON(http.StatusOK, gin.H{"deleted": row.ID})
}

// handleRestartBridge re-renders and restarts one bridge's exit half.
func (s *Server) handleRestartBridge(c *gin.Context) {
	row, err := s.db.BridgeByID(parseID(c))
	if err != nil {
		fail(c, http.StatusNotFound, "no such bridge")
		return
	}
	spec, err := s.specFor(row)
	if err != nil {
		failErr(c, http.StatusInternalServerError, err)
		return
	}
	if err := s.bridgeManager().Start(c.Request.Context(), row.Name, spec); err != nil {
		row.LastError = err.Error()
		row.LastState = string(bridge.StateFailed)
		_ = s.db.SaveBridge(row)
		failErr(c, http.StatusBadGateway, err)
		return
	}
	s.audit(c, "bridge.restart", row.Name)
	now := time.Now().UTC()
	row.LastSeen, row.LastError = &now, ""
	_ = s.db.SaveBridge(row)
	c.JSON(http.StatusOK, gin.H{"restarted": row.Name})
}

// StartBridges brings up every enabled bridge's exit half at boot.
//
// Without this the panel would forget its bridges on restart: the rows survive,
// the tunnels do not, and every inbound reached through one goes dark until
// somebody notices and clicks restart.
func (s *Server) StartBridges() {
	if s.db == nil {
		return
	}
	rows, err := s.db.ListBridges()
	if err != nil {
		return
	}
	for i := range rows {
		row := rows[i]
		if !row.Enabled {
			continue
		}
		spec, err := s.specFor(&row)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forgepanel: bridge %s not started: %v\n", row.Name, err)
			continue
		}
		if err := s.bridgeManager().Start(context.Background(), row.Name, spec); err != nil {
			fmt.Fprintf(os.Stderr, "forgepanel: bridge %s not started: %v\n", row.Name, err)
		}
	}
}

// StopBridges tears every supervised bridge down.
func (s *Server) StopBridges() {
	if s.bridgeMgr != nil {
		s.bridgeMgr.StopAll()
	}
}
