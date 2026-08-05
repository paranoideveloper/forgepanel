package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/domain"
	"github.com/forgepanel/forgepanel/internal/forgedns/adapter"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/store"
)

// A zone is served by one of two implementations, chosen by its adapter name:
// the panel-native codec (`forge`/`native`), or a real upstream binary
// (`stormdns`/`masterdns`/`cottendns`) that the panel downloads, configures and
// supervises — see docs/FORGEDNS_UPSTREAM_SETUP.md §4. Everything below routes
// on upstream.IsUpstream so both kinds share one CRUD surface.

// syncForgeDNS pushes the panel's enabled zones to the DNS controller — called
// after any zone mutation and at boot, so activation is entirely UI-driven.
func (s *Server) syncForgeDNS() {
	if s.fdns == nil || s.db == nil {
		return
	}
	zones, err := s.db.ListZones()
	if err != nil {
		return
	}
	var specs []core.ZoneSpec
	for i := range zones {
		z := &zones[i]
		if !z.Enabled {
			continue
		}
		sp := core.ZoneSpec{Zone: z.Zone, Adapter: z.Adapter}
		if upstream.IsUpstream(z.Adapter) {
			// A zone switched to an upstream adapter after creation (or migrated
			// from an older schema) has no shared secret yet; mint it once here so
			// the key stays stable for the life of the zone.
			if z.EncryptKey == "" {
				if k, err := upstream.GenerateKey(); err == nil {
					z.EncryptKey = k
					_ = s.db.SaveZone(z)
				}
			}
			sp.Upstream = &upstream.Spec{Config: upstreamConfig(z), PinnedTag: z.PinnedTag}
		}
		specs = append(specs, sp)
	}
	_, _ = s.fdns.SyncZones(specs)
	s.pinUpstreamTags(zones)
}

// pinUpstreamTags records the release tag each upstream zone actually resolved
// to. Pinning is what makes an upgrade explicit (§4a): once written, a restart
// re-installs that exact build instead of silently following `latest`.
func (s *Server) pinUpstreamTags(zones []store.ForgeDNSZone) {
	for i := range zones {
		z := &zones[i]
		if !z.Enabled || z.PinnedTag != "" || !upstream.IsUpstream(z.Adapter) {
			continue
		}
		if tag := s.fdns.UpstreamTag(z.Zone); tag != "" {
			z.PinnedTag = tag
			_ = s.db.SaveZone(z)
		}
	}
}

// upstreamConfig projects a stored zone onto the renderer's input (§4b).
func upstreamConfig(z *store.ForgeDNSZone) upstream.ZoneConfig {
	return upstream.ZoneConfig{
		Zone:            z.Zone,
		Adapter:         z.Adapter,
		Domains:         upstream.SplitDomains(z.Domains),
		BindHost:        z.BindHost,
		BindPort:        z.BindPort,
		Mode:            z.Mode,
		Cipher:          z.Cipher,
		ForwardIP:       z.ForwardIP,
		ForwardPort:     z.ForwardPort,
		ExternalSocks5:  z.ExternalSocks5,
		TCPListener:     z.TCPListener,
		DoTListener:     z.DoTListener,
		DoHListener:     z.DoHListener,
		AutoDetect:      z.AutoDetect,
		ARecordDelivery: z.ARecordDelivery,
		QueryTypes:      upstream.NormalizeQueryTypes(strings.Split(z.QueryTypes, ",")),
		EncryptKey:      z.EncryptKey,
		// The advanced-override layer travels with the zone so the supervised
		// process, the client bundle and the config editor all see the same
		// merged result (see internal/api/forgedns_config.go).
		OverrideTOML:       z.OverrideTOML,
		ClientOverrideTOML: z.ClientOverrideTOML,
	}
}

// handleForgeDNSAdapters lists the selectable wire-format adapters for the UI
// dropdown (spec §5): the operator picks one when creating a zone.
func (s *Server) handleForgeDNSAdapters(c *gin.Context) {
	c.JSON(200, adapter.Names())
}

// handleForgeDNSUpstreamAdapters describes the real-binary adapters and the
// choices that go with them, so the UI can build the zone form without
// hard-coding upstream facts it would then have to keep in sync.
func (s *Server) handleForgeDNSUpstreamAdapters(c *gin.Context) {
	c.JSON(200, gin.H{
		"adapters":    upstream.Descriptors(),
		"default":     upstream.DefaultAdapter,
		"modes":       []string{upstream.ModeSocks5, upstream.ModeTCP},
		"query_types": upstream.QueryTypeChoices(),
		"client_port": upstream.DefaultClientPort,
		"ciphers": []gin.H{
			{"value": 0, "label": "None"}, {"value": 1, "label": "XOR"},
			{"value": 2, "label": "ChaCha20"}, {"value": 3, "label": "AES-128-GCM"},
			{"value": 4, "label": "AES-192-GCM"}, {"value": 5, "label": "AES-256-GCM"},
		},
	})
}

// handleForgeDNSList lists the panel's tunnel zones.
func (s *Server) handleForgeDNSList(c *gin.Context) {
	zones, err := s.db.ListZones()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, zones)
}

// zoneReq is the create/update payload. Pointer fields let an update leave a
// setting alone instead of resetting it to the zero value.
type zoneReq struct {
	Zone            string   `json:"zone"`
	Adapter         string   `json:"adapter"`
	Domains         []string `json:"domains"`
	NSHost          string   `json:"ns_host"`
	BindHost        string   `json:"bind_host"`
	BindPort        int      `json:"bind_port"`
	Mode            string   `json:"mode"`
	Cipher          *int     `json:"cipher"`
	ForwardIP       string   `json:"forward_ip"`
	ForwardPort     int      `json:"forward_port"`
	ExternalSocks5  *bool    `json:"external_socks5"`
	TCPListener     *bool    `json:"tcp_listener"`
	DoTListener     *bool    `json:"dot_listener"`
	DoHListener     *bool    `json:"doh_listener"`
	AutoDetect      *bool    `json:"encryption_auto_detect"`
	ARecordDelivery *bool    `json:"a_record_delivery"`
	QueryTypes      []string `json:"query_types"`
	PinnedTag       *string  `json:"pinned_tag"`
	Enabled         *bool    `json:"enabled"`
}

// applyZoneReq copies a request onto a zone row.
func applyZoneReq(z *store.ForgeDNSZone, r *zoneReq) {
	if r.Adapter != "" {
		z.Adapter = upstream.Canonical(r.Adapter)
	}
	if r.Domains != nil {
		z.Domains = upstream.JoinDomains(r.Domains)
	}
	if r.NSHost != "" {
		z.NSHost = r.NSHost
	}
	if r.BindHost != "" {
		z.BindHost = r.BindHost
	}
	if r.BindPort != 0 {
		z.BindPort = r.BindPort
	}
	if r.Mode != "" {
		z.Mode = strings.ToLower(r.Mode)
	}
	if r.Cipher != nil {
		z.Cipher = *r.Cipher
	}
	if r.ForwardIP != "" {
		z.ForwardIP = r.ForwardIP
	}
	if r.ForwardPort != 0 {
		z.ForwardPort = r.ForwardPort
	}
	if r.QueryTypes != nil {
		z.QueryTypes = strings.Join(upstream.NormalizeQueryTypes(r.QueryTypes), ",")
	}
	if r.PinnedTag != nil {
		z.PinnedTag = strings.TrimSpace(*r.PinnedTag)
	}
	for _, f := range []struct {
		src *bool
		dst *bool
	}{
		{r.ExternalSocks5, &z.ExternalSocks5}, {r.TCPListener, &z.TCPListener},
		{r.DoTListener, &z.DoTListener}, {r.DoHListener, &z.DoHListener},
		{r.AutoDetect, &z.AutoDetect}, {r.ARecordDelivery, &z.ARecordDelivery},
		{r.Enabled, &z.Enabled},
	} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
}

// validateZone rejects a zone the upstream binary would reject, at request time
// rather than silently at sync time.
func validateZone(z *store.ForgeDNSZone) error {
	if !upstream.IsUpstream(z.Adapter) {
		// `native` and the empty string are aliases for the panel's own codec,
		// which the wire-format registry knows as `forge`.
		name := z.Adapter
		if name == "" || name == "native" {
			name = "forge"
		}
		_, err := adapter.Get(name)
		return err
	}
	d, err := upstream.Lookup(z.Adapter)
	if err != nil {
		return err
	}
	cfg := upstreamConfig(z)
	cfg.Normalize(d)
	return cfg.Validate()
}

// handleForgeDNSCreate adds a tunnel zone and activates it — the whole setup the
// user previously had to do by hand in a terminal, now one API call. New zones
// default to the CottenDNS adapter (§4e).
func (s *Server) handleForgeDNSCreate(c *gin.Context) {
	var req zoneReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Zone) == "" {
		c.JSON(400, gin.H{"error": "zone required"})
		return
	}
	if req.Adapter == "" {
		req.Adapter = upstream.DefaultAdapter
	}
	key, _ := keygen.Password(12)
	encKey, err := upstream.GenerateKey()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	z := &store.ForgeDNSZone{
		Zone: strings.ToLower(strings.TrimSpace(req.Zone)), Enabled: true,
		Key: key, EncryptKey: encKey,
	}
	applyZoneReq(z, &req)
	// Ship the upstream's own defaults for the CottenDNS extras unless the
	// caller said otherwise: TCP listener on, encryption auto-detect on (§3).
	if upstream.Canonical(z.Adapter) == upstream.AdapterCottenDNS {
		if req.TCPListener == nil {
			z.TCPListener = true
		}
		if req.AutoDetect == nil {
			z.AutoDetect = true
		}
	}
	// Persist the adapter's shipped cipher explicitly rather than leaning on the
	// renderer's zero-value fallback, so the stored row says what will actually
	// be rendered.
	if d, err := upstream.Lookup(z.Adapter); err == nil && req.Cipher == nil {
		z.Cipher = d.DefaultCipher
	}
	if err := validateZone(z); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.CreateZone(z); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "forgedns.zone.create", z.Zone)
	go s.syncForgeDNS()
	c.JSON(201, z)
}

// handleForgeDNSUpdate edits a zone's settings and re-syncs. Changing anything
// the rendered config depends on restarts that zone's process; nothing else.
func (s *Server) handleForgeDNSUpdate(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	var req zoneReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	applyZoneReq(z, &req)
	if upstream.IsUpstream(z.Adapter) && z.EncryptKey == "" {
		if k, err := upstream.GenerateKey(); err == nil {
			z.EncryptKey = k
		}
	}
	if err := validateZone(z); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.SaveZone(z); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "forgedns.zone.update", z.Zone)
	go s.syncForgeDNS()
	c.JSON(200, z)
}

// handleForgeDNSToggle enables/disables a zone (activate/deactivate from the UI).
func (s *Server) handleForgeDNSToggle(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	z.Enabled = !z.Enabled
	_ = s.db.SaveZone(z)
	s.audit(c, "forgedns.zone.toggle", z.Zone)
	go s.syncForgeDNS()
	c.JSON(200, z)
}

// handleForgeDNSDelete removes a zone.
func (s *Server) handleForgeDNSDelete(c *gin.Context) {
	z, _ := s.db.ZoneByID(parseID(c))
	if err := s.db.DeleteZone(parseID(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if z != nil {
		s.audit(c, "forgedns.zone.delete", z.Zone)
	}
	go s.syncForgeDNS()
	c.JSON(200, gin.H{"deleted": parseID(c)})
}

// handleForgeDNSStatus returns the listener state + served zones.
func (s *Server) handleForgeDNSStatus(c *gin.Context) {
	if s.fdns == nil {
		c.JSON(200, gin.H{"listening": false})
		return
	}
	c.JSON(200, s.fdns.Status())
}

// handleForgeDNSSessions streams live per-session metrics for a zone (spec §5.3).
func (s *Server) handleForgeDNSSessions(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	if s.fdns == nil {
		c.JSON(200, []any{})
		return
	}
	c.JSON(200, s.fdns.Sessions(z.Zone))
}

// handleForgeDNSInstall downloads (or re-pins) the upstream release for a zone.
// ?tag= pins an exact release; ?tag=latest re-resolves and upgrades. Kept as an
// explicit action so a panel restart never changes which build is running.
func (s *Server) handleForgeDNSInstall(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	mgr := s.upstreamManager()
	if mgr == nil {
		c.JSON(503, gin.H{"error": "forgedns upstream manager unavailable"})
		return
	}
	d, err := upstream.Lookup(z.Adapter)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	tag := strings.TrimSpace(c.Query("tag"))
	if tag == "latest" {
		tag = ""
	} else if tag == "" {
		tag = z.PinnedTag
	}
	in, err := mgr.Installer().Ensure(d, tag)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	z.PinnedTag = in.Tag
	_ = s.db.SaveZone(z)
	s.audit(c, "forgedns.zone.install", z.Zone+" "+in.Tag)
	go s.syncForgeDNS()
	c.JSON(200, in)
}

// handleForgeDNSBundle returns everything a user needs to connect to an upstream
// zone (§4d): the NS delegation block with the Cloudflare grey-cloud warning,
// and a generated client_config.toml + client_resolvers.txt. Neither upstream
// tool defines a URI scheme — the config file IS the credential, so this route
// hands out the zone's shared key and is audited.
func (s *Server) handleForgeDNSBundle(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	b, err := s.buildBundle(z, c.Query("ip"), c.Query("resolvers"))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	s.audit(c, "forgedns.zone.bundle", z.Zone)
	c.JSON(200, b)
}

// buildBundle renders the client bundle for an upstream zone.
func (s *Server) buildBundle(z *store.ForgeDNSZone, ip, resolvers string) (*upstream.Bundle, error) {
	d, err := upstream.Lookup(z.Adapter)
	if err != nil {
		return nil, err
	}
	b, err := upstream.BuildBundle(d, upstreamConfig(z), upstream.BundleOptions{
		ServerIP:  ip,
		NSHost:    z.NSHost,
		Tag:       z.PinnedTag,
		Resolvers: upstream.SplitList(resolvers),
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// upstreamManager returns the real-binary manager if one is configured.
func (s *Server) upstreamManager() *upstream.Manager {
	if s.fdns == nil {
		return nil
	}
	return s.fdns.Upstream()
}

// handleForgeDNSClientConfig returns the client profile for a zone — the config a
// user imports into a ForgeDNS-capable client. Includes the NS delegation
// records so the operator can finish setup from the panel. For zones on a real
// upstream adapter it also carries the full upstream bundle, so a UI that only
// knows this route still gets the right instructions.
func (s *Server) handleForgeDNSClientConfig(c *gin.Context) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "zone not found"})
		return
	}
	serverIP := c.Query("ip")
	if upstream.IsUpstream(z.Adapter) {
		b, err := s.buildBundle(z, serverIP, c.Query("resolvers"))
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		s.audit(c, "forgedns.zone.bundle", z.Zone)
		c.JSON(200, gin.H{"kind": "upstream", "adapter": z.Adapter, "bundle": b, "ns_records": b.NSRecords})
		return
	}
	profile := gin.H{
		"zone": z.Zone, "adapter": z.Adapter, "key": z.Key,
		"rrtype": "TXT", "edns_buffer": 1232,
	}
	raw, _ := json.Marshal(profile)
	c.JSON(200, gin.H{
		"kind":        "native",
		"profile":     profile,
		"profile_b64": base64.StdEncoding.EncodeToString(raw),
		"uri":         "forgedns://" + z.Adapter + "@" + z.Zone + "?key=" + z.Key,
		"ns_records":  nsRecords(z.Zone, serverIP),
	})
}

// nsRecords returns the delegation records for a zone (reuses the domain wizard).
func nsRecords(zone, ip string) any {
	records, err := domain.NSDelegation(zone, ip)
	if err != nil {
		return []domain.Record{}
	}
	return records
}
