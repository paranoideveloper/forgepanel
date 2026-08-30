package api

import (
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/forgedns/upstream"
	"github.com/forgepanel/forgepanel/internal/store"
)

// The editable-config surface for upstream ForgeDNS zones: read the effective
// TOML with per-key provenance, replace the advanced-override layer, import a
// config the operator already runs, and describe an adapter's option manifest so
// the UI can build the editor without hard-coding upstream facts.
//
// ROUTES TO REGISTER in internal/api/server.go, inside the same authenticated
// `admin` group as the existing /forgedns routes (~line 192):
//
//	admin.GET("/forgedns/upstream/adapters/:adapter/options", s.handleForgeDNSAdapterOptions)
//	admin.GET("/forgedns/zones/:id/config", s.handleForgeDNSZoneConfig)
//	admin.PUT("/forgedns/zones/:id/config", s.handleForgeDNSZoneOverride)
//	admin.POST("/forgedns/zones/:id/config/import", s.handleForgeDNSZoneImport)
//
// Secrets are masked in every response here — the shared key, an imported
// client key, a SOCKS5 password, and any undeclared key whose NAME looks like
// key material. A masked value sent back on PUT means "keep what you have"
// (upstream.UnmaskDocument), so an edit round-trip cannot destroy the zone key.

// handleForgeDNSAdapterOptions returns one adapter's option manifest: every key
// it accepts with type, range, default, secrecy, restart cost and whether the
// managed form may edit it.
func (s *Server) handleForgeDNSAdapterOptions(c *gin.Context) {
	m, err := upstream.ManifestFor(c.Param("adapter"))
	if err != nil {
		failErr(c, 404, err)
		return
	}
	c.JSON(200, gin.H{
		"manifest": m,
		"layers": []string{string(upstream.LayerDefault), string(upstream.LayerManaged),
			string(upstream.LayerOverride), string(upstream.LayerRuntime)},
		"masked_value": upstream.MaskedValue,
	})
}

// scopeOf reads the ?scope= / body scope, defaulting to the server config.
func scopeOf(raw string) upstream.Scope {
	if strings.EqualFold(strings.TrimSpace(raw), string(upstream.ScopeClient)) {
		return upstream.ScopeClient
	}
	return upstream.ScopeServer
}

// upstreamZone loads a zone and rejects the ones this surface does not apply to:
// the panel-native codec has no upstream TOML to edit.
func (s *Server) upstreamZone(c *gin.Context) (*store.ForgeDNSZone, upstream.Descriptor, bool) {
	z, err := s.db.ZoneByID(parseID(c))
	if err != nil {
		fail(c, 404, "zone not found")
		return nil, upstream.Descriptor{}, false
	}
	d, err := upstream.Lookup(z.Adapter)
	if err != nil {
		fail(c, 400, "advanced config applies to upstream adapters only: "+err.Error())
		return nil, upstream.Descriptor{}, false
	}
	return z, d, true
}

// handleForgeDNSZoneConfig returns the effective server AND client TOML for a
// zone, with the layer each key resolved at.
func (s *Server) handleForgeDNSZoneConfig(c *gin.Context) {
	z, d, ok := s.upstreamZone(c)
	if !ok {
		return
	}
	m, _ := upstream.ManifestFor(d.Adapter)
	cfg := upstreamConfig(z)
	server, err := s.configView(m, d, cfg, upstream.ScopeServer, z.OverrideTOML)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	client, err := s.configView(m, d, cfg, upstream.ScopeClient, z.ClientOverrideTOML)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	c.JSON(200, gin.H{
		"zone": z.Zone, "adapter": d.Adapter, "config_version": d.ConfigVersion,
		"server": server, "client": client, "masked_value": upstream.MaskedValue,
	})
}

// keyView is one key of an effective document, as the editor shows it.
type keyView struct {
	Key      string         `json:"key"`
	Layer    upstream.Layer `json:"layer"`
	Value    any            `json:"value"` // masked when secret
	Known    bool           `json:"known"`
	Secret   bool           `json:"secret"`
	Restart  bool           `json:"restart_required"`
	SafeEdit bool           `json:"safe_for_managed_editing"`
}

// configView merges the layers for one scope and renders the display form.
func (s *Server) configView(m upstream.Manifest, d upstream.Descriptor,
	cfg upstream.ZoneConfig, scope upstream.Scope, overrideText string) (gin.H, error) {

	e, err := effectiveFor(d, cfg, scope)
	if err != nil {
		return nil, err
	}
	masked := e.Masked(m)
	keys := make([]keyView, 0, len(e.Order))
	for _, k := range e.Order {
		o, known := m.Option(scope, k)
		keys = append(keys, keyView{
			Key: k, Layer: e.Origin[k], Value: masked[k], Known: known,
			Secret:  o.Secret || (!known && masked[k] == upstream.MaskedValue),
			Restart: o.Restart, SafeEdit: o.SafeEdit,
		})
	}
	text, err := e.MaskedTOML(m, "")
	if err != nil {
		return nil, err
	}
	overrideDoc, err := upstream.ParseTOML(overrideText)
	if err != nil {
		return nil, err
	}
	overrideView, err := upstream.RenderOverride(m, scope, upstream.MaskDocument(m, scope, overrideDoc))
	if err != nil {
		return nil, err
	}
	return gin.H{
		"toml": text, "keys": keys, "override_toml": overrideView,
		"unknown_keys": e.Unknown, "ignored_keys": e.Ignored,
		"secret_keys": e.SecretKeys(m), "warnings": upstream.Warnings(m, scope, overrideDoc),
	}, nil
}

func effectiveFor(d upstream.Descriptor, cfg upstream.ZoneConfig, scope upstream.Scope) (upstream.Effective, error) {
	if scope == upstream.ScopeClient {
		return upstream.EffectiveClient(d, cfg, upstream.ClientOptions{})
	}
	return upstream.EffectiveServer(d, cfg)
}

// overrideReq is the advanced-override payload.
type overrideReq struct {
	Scope string `json:"scope"` // server (default) | client
	TOML  string `json:"toml"`
	Apply *bool  `json:"apply"` // import only: also adopt the recognised settings
}

// handleForgeDNSZoneOverride replaces a zone's advanced-override document. The
// document is validated on its own AND as part of the merged result before it is
// stored, so a save can never leave a zone with a config the binary would reject
// at start — the failure mode this replaces is a silent crash-loop (§4b).
func (s *Server) handleForgeDNSZoneOverride(c *gin.Context) {
	z, d, ok := s.upstreamZone(c)
	if !ok {
		return
	}
	var req overrideReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	scope := scopeOf(req.Scope)
	m, _ := upstream.ManifestFor(d.Adapter)

	stored := z.OverrideTOML
	if scope == upstream.ScopeClient {
		stored = z.ClientOverrideTOML
	}
	prev, err := upstream.ParseTOML(stored)
	if err != nil {
		prev = upstream.Document{}
	}
	doc, warnings, err := upstream.ValidateOverrideTOML(m, scope, req.TOML)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Kind: apierr.KindValidation, Status: 400,
			Message: err.Error(), Cause: err, Details: map[string]any{"detail": err}})
		return
	}
	doc = upstream.UnmaskDocument(doc, prev)
	text, err := upstream.RenderOverride(m, scope, doc)
	if err != nil {
		failErr(c, 400, err)
		return
	}

	// Dry-run the merge on a copy: the effective document must still be a
	// complete, valid config for this adapter before anything is persisted.
	cfg := upstreamConfig(z)
	if scope == upstream.ScopeClient {
		cfg.ClientOverrideTOML = text
	} else {
		cfg.OverrideTOML = text
	}
	e, err := effectiveFor(d, cfg, scope)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	if err := upstream.ValidateComplete(m, scope, e.Values); err != nil {
		apierr.Fail(c, &apierr.Error{Kind: apierr.KindValidation, Status: 400,
			Message: err.Error(), Cause: err, Details: map[string]any{"detail": err}})
		return
	}

	if scope == upstream.ScopeClient {
		z.ClientOverrideTOML = text
	} else {
		z.OverrideTOML = text
	}
	if err := s.db.SaveZone(z); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "forgedns.zone.override", z.Zone+" "+string(scope))
	s.startBackground(s.syncForgeDNS)
	c.JSON(200, gin.H{
		"zone": z.Zone, "scope": scope, "warnings": warnings,
		"overridden_keys": e.Unknown, "ignored_keys": e.Ignored,
	})
}

// handleForgeDNSZoneImport adopts an existing server/client config file: the keys
// the panel models become zone settings, and everything else — including keys
// this panel has never heard of — is preserved verbatim in the override layer.
// Nothing is written unless "apply" is true, so an operator can see the split
// first.
func (s *Server) handleForgeDNSZoneImport(c *gin.Context) {
	z, d, ok := s.upstreamZone(c)
	if !ok {
		return
	}
	var req overrideReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	scope := scopeOf(req.Scope)
	imported, override, err := importFor(scope, req.TOML)
	if err != nil {
		apierr.Fail(c, &apierr.Error{Kind: apierr.KindValidation, Status: 400,
			Message: err.Error(), Cause: err, Details: map[string]any{"detail": err}})
		return
	}
	m, err := upstream.ManifestFor(imported.Adapter)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	text, err := upstream.RenderOverride(m, scope, override)
	if err != nil {
		failErr(c, 400, err)
		return
	}
	result := gin.H{
		"zone": z.Zone, "scope": scope, "adapter": imported.Adapter,
		"managed_keys":  sortedDocKeys(imported.Values),
		"override_toml": mustRenderMasked(m, scope, override, text),
		"warnings":      imported.Warnings, "applied": false,
	}
	if req.Apply == nil || !*req.Apply {
		c.JSON(200, result)
		return
	}

	cfg := upstreamConfig(z)
	imported.ApplyTo(&cfg)
	if scope == upstream.ScopeClient {
		cfg.ClientOverrideTOML = text
	} else {
		cfg.OverrideTOML = text
	}
	cfg.Normalize(d)
	if err := cfg.Validate(); err != nil {
		failErr(c, 400, err)
		return
	}
	applyUpstreamConfig(z, cfg)
	if err := s.db.SaveZone(z); err != nil {
		failErr(c, 500, err)
		return
	}
	result["applied"] = true
	s.audit(c, "forgedns.zone.import", z.Zone+" "+string(scope))
	s.startBackground(s.syncForgeDNS)
	c.JSON(200, result)
}

func importFor(scope upstream.Scope, text string) (upstream.Managed, upstream.Document, error) {
	if scope == upstream.ScopeClient {
		return upstream.ImportClientTOML(text)
	}
	return upstream.ImportServerTOML(text)
}

// mustRenderMasked renders the override for display; on the (already validated)
// render path a failure can only mean an unrenderable value, so fall back to the
// canonical text rather than failing the whole response.
func mustRenderMasked(m upstream.Manifest, scope upstream.Scope, doc upstream.Document, fallback string) string {
	out, err := upstream.RenderOverride(m, scope, upstream.MaskDocument(m, scope, doc))
	if err != nil {
		return fallback
	}
	return out
}

func sortedDocKeys(doc upstream.Document) []string {
	out := make([]string, 0, len(doc))
	for k := range doc {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applyUpstreamConfig writes a rendered zone config back onto the store row — the
// reverse of upstreamConfig, used only by import.
func applyUpstreamConfig(z *store.ForgeDNSZone, cfg upstream.ZoneConfig) {
	z.Adapter = upstream.Canonical(cfg.Adapter)
	if cfg.Zone != "" {
		z.Zone = cfg.Zone
	}
	z.Domains = upstream.JoinDomains(cfg.Domains)
	z.BindHost, z.BindPort = cfg.BindHost, cfg.BindPort
	z.Mode, z.Cipher = cfg.Mode, cfg.Cipher
	z.ForwardIP, z.ForwardPort = cfg.ForwardIP, cfg.ForwardPort
	z.ExternalSocks5 = cfg.ExternalSocks5
	z.TCPListener, z.DoTListener, z.DoHListener = cfg.TCPListener, cfg.DoTListener, cfg.DoHListener
	z.AutoDetect, z.ARecordDelivery = cfg.AutoDetect, cfg.ARecordDelivery
	z.QueryTypes = strings.Join(cfg.QueryTypes, ",")
	if cfg.EncryptKey != "" {
		// An imported client config carries the zone's existing shared key;
		// adopting it is what keeps already-deployed clients working.
		z.EncryptKey = cfg.EncryptKey
	}
	z.OverrideTOML, z.ClientOverrideTOML = cfg.OverrideTOML, cfg.ClientOverrideTOML
}
