package dns

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Deps is everything the HTTP layer needs from the panel. It is deliberately
// narrow — three repository interfaces and an encryptor — so this package has
// no dependency on the panel's own API or store internals and can be mounted
// with a single line.
type Deps struct {
	// Credentials persists encrypted provider credentials. Required.
	Credentials CredentialRepo
	// Encryptor protects credential material at rest. Required.
	Encryptor Encryptor
	// Pools persists rotation-pool entries. Optional; pool routes 501 without it.
	Pools PoolRepo
	// CleanIPs persists scan results. Optional; scan routes 501 without it.
	CleanIPs CleanIPRepo
	// Resolver is used for delegation and preflight checks. Nil uses the public
	// recursive resolvers.
	Resolver Resolver
	// Preflight overrides the ACME readiness checker. Nil uses the defaults
	// (Let's Encrypt's directory and crt.sh); set it to pin a staging CA, an
	// internal ACME server, or to disable the certificate-transparency lookup.
	Preflight *Preflight
	// Audit records a mutating action. Optional.
	Audit func(c *gin.Context, action, target, result string)
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) resolver() Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return NewResolver()
}

// preflight returns the configured readiness checker with the deps' resolver
// and clock filled in.
func (d Deps) preflight() Preflight {
	pf := Preflight{}
	if d.Preflight != nil {
		pf = *d.Preflight
	}
	if pf.Resolver == nil {
		pf.Resolver = d.resolver()
	}
	if pf.Now == nil {
		pf.Now = d.Now
	}
	return pf
}

func (d Deps) audit(c *gin.Context, action, target, result string) {
	if d.Audit != nil {
		d.Audit(c, action, target, result)
	}
}

// handlers carries the wired-up store alongside the deps.
type handlers struct {
	deps  Deps
	creds *CredentialStore
	// initErr is returned by every route when the deps were incomplete, so a
	// misconfiguration is a clear 500 on use rather than a panic at mount time.
	initErr error
}

// RegisterRoutes mounts the DNS wizard API on rg. Every path is relative, so
// the caller decides the prefix and the auth middleware:
//
//	dns.RegisterRoutes(admin, dns.Deps{...})
//
// mounts them under whatever group `admin` is.
func RegisterRoutes(rg gin.IRouter, deps Deps) {
	h := &handlers{deps: deps}
	store, err := NewCredentialStore(deps.Credentials, deps.Encryptor)
	if err != nil {
		h.initErr = err
	} else {
		h.creds = store
	}

	g := rg.Group("/dns")
	g.GET("/providers", h.listProviders)

	g.GET("/credentials", h.listCredentials)
	g.POST("/credentials", h.createCredential)
	g.DELETE("/credentials/:id", h.deleteCredential)
	g.POST("/credentials/:id/verify", h.verifyCredential)

	g.GET("/zones", h.listZones)
	g.POST("/zones/resolve", h.resolveZone)

	g.GET("/records", h.listRecords)
	g.POST("/records", h.upsertRecord)
	g.DELETE("/records", h.deleteRecord)
	g.POST("/records/bulk", h.bulkRecords)
	g.POST("/records/proxy", h.setProxied)

	g.GET("/zone-settings", h.getZoneSettings)
	g.POST("/zone-settings", h.applyZoneSettings)

	g.POST("/preflight", h.preflight)

	g.GET("/pool/:name", h.listPool)
	g.POST("/pool/:name/entries", h.addPoolEntry)
	g.DELETE("/pool/:name/entries", h.removePoolEntry)
	g.POST("/pool/:name/check", h.checkPool)
	g.POST("/pool/:name/rotate", h.rotatePool)

	g.GET("/cleanip", h.listCleanIPs)
	g.GET("/cleanip/:name", h.getCleanIPs)
	g.POST("/cleanip/scan", h.scanCleanIPs)

	g.POST("/provision", h.provision)
}

// fail writes a typed error with the HTTP status its kind implies.
func fail(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	body := gin.H{"error": err.Error()}
	if e, ok := AsError(err); ok {
		body = gin.H{
			"error":       e.Message,
			"kind":        string(e.Kind),
			"provider":    e.Provider,
			"op":          e.Op,
			"remediation": e.Remediation,
		}
		if e.MissingScope != "" {
			body["missing_scope"] = e.MissingScope
		}
		switch e.Kind {
		case KindValidation:
			status = http.StatusBadRequest
		case KindAuth:
			status = http.StatusUnauthorized
		case KindPermission:
			status = http.StatusForbidden
		case KindNotFound:
			status = http.StatusNotFound
		case KindConflict:
			status = http.StatusConflict
		case KindRateLimit:
			status = http.StatusTooManyRequests
		case KindUnsupported, KindNotImplemented:
			status = http.StatusNotImplemented
		case KindPreflight:
			status = http.StatusUnprocessableEntity
		case KindNetwork:
			status = http.StatusBadGateway
		}
	}
	c.JSON(status, body)
}

// store returns the credential store or writes the init error.
func (h *handlers) store(c *gin.Context) (*CredentialStore, bool) {
	if h.initErr != nil {
		fail(c, h.initErr)
		return nil, false
	}
	return h.creds, true
}

// provider resolves the credential named by the request into a live provider.
func (h *handlers) provider(c *gin.Context, credID string) (Provider, bool) {
	store, ok := h.store(c)
	if !ok {
		return nil, false
	}
	if strings.TrimSpace(credID) == "" {
		fail(c, &Error{Op: "resolve-credential", Kind: KindValidation,
			Message:     "no credential id was supplied",
			Remediation: "pass `credential` (query parameter or JSON field) naming a stored credential from GET /dns/credentials"})
		return nil, false
	}
	p, _, err := store.Provider(credID)
	if err != nil {
		fail(c, err)
		return nil, false
	}
	return p, true
}

func (h *handlers) listProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"providers": Providers(), "implemented": ImplementedProviders()})
}

func (h *handlers) listCredentials(c *gin.Context) {
	store, ok := h.store(c)
	if !ok {
		return
	}
	recs, err := store.List()
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"credentials": recs})
}

func (h *handlers) createCredential(c *gin.Context) {
	store, ok := h.store(c)
	if !ok {
		return
	}
	var req struct {
		ID       string            `json:"id"`
		Provider string            `json:"provider"`
		Label    string            `json:"label"`
		Data     map[string]string `json:"data"`
		// Verify runs VerifyCredentials before storing, so a bad token is
		// rejected at registration instead of at provisioning time.
		Verify bool `json:"verify"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "create-credential", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"provider":"cloudflare","label":"main","data":{"api_token":"..."}}`})
		return
	}
	creds := Credentials(req.Data)
	if req.Verify {
		p, err := NewProvider(req.Provider, creds)
		if err != nil {
			fail(c, err)
			return
		}
		if _, err := p.VerifyCredentials(c.Request.Context()); err != nil {
			h.deps.audit(c, "dns.credential.create", req.Provider, "rejected")
			fail(c, err)
			return
		}
	}
	rec, err := store.Put(req.ID, req.Provider, req.Label, creds)
	if err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.credential.create", rec.Provider+"/"+rec.ID, "ok")
	c.JSON(http.StatusCreated, rec)
}

func (h *handlers) deleteCredential(c *gin.Context) {
	store, ok := h.store(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if err := store.Delete(id); err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.credential.delete", id, "ok")
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

func (h *handlers) verifyCredential(c *gin.Context) {
	store, ok := h.store(c)
	if !ok {
		return
	}
	id := c.Param("id")
	p, _, err := store.Provider(id)
	if err != nil {
		fail(c, err)
		return
	}
	ident, verifyErr := p.VerifyCredentials(c.Request.Context())
	_ = store.RecordVerification(id, verifyErr)
	if verifyErr != nil {
		h.deps.audit(c, "dns.credential.verify", id, "failed")
		fail(c, verifyErr)
		return
	}
	h.deps.audit(c, "dns.credential.verify", id, "ok")
	c.JSON(http.StatusOK, ident)
}

func (h *handlers) listZones(c *gin.Context) {
	p, ok := h.provider(c, c.Query("credential"))
	if !ok {
		return
	}
	zones, err := p.ListZones(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"zones": zones})
}

func (h *handlers) resolveZone(c *gin.Context) {
	var req struct {
		Credential string `json:"credential"`
		Domain     string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "resolve-zone", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","domain":"node.example.com"}`})
		return
	}
	p, ok := h.provider(c, req.Credential)
	if !ok {
		return
	}
	res, err := ResolveZone(c.Request.Context(), p, h.deps.resolver(), req.Domain)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *handlers) listRecords(c *gin.Context) {
	p, ok := h.provider(c, c.Query("credential"))
	if !ok {
		return
	}
	filter := RecordFilter{Name: c.Query("name"), Contains: c.Query("contains")}
	if t := c.Query("type"); t != "" {
		rt, err := NormalizeType(t)
		if err != nil {
			fail(c, err)
			return
		}
		filter.Type = rt
	}
	recs, err := p.ListRecords(c.Request.Context(), c.Query("zone"), filter)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"records": recs})
}

// recordRequest is the body for record mutations.
type recordRequest struct {
	Credential string   `json:"credential"`
	Zone       string   `json:"zone"`
	Record     Record   `json:"record"`
	SRV        *SRVData `json:"srv,omitempty"`
}

func (h *handlers) upsertRecord(c *gin.Context) {
	var req recordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "upsert-record", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","zone":"<zone id>","record":{"type":"A","name":"ws.example.com","content":"203.0.113.10","proxied":true}}`})
		return
	}
	p, ok := h.provider(c, req.Credential)
	if !ok {
		return
	}
	rec := req.Record
	if req.SRV != nil {
		rec.SRV = req.SRV
	}
	res, err := EnsureRecord(c.Request.Context(), p, req.Zone, rec)
	if err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.record."+res.Action, rec.Name, "ok")
	c.JSON(http.StatusOK, res)
}

func (h *handlers) deleteRecord(c *gin.Context) {
	p, ok := h.provider(c, c.Query("credential"))
	if !ok {
		return
	}
	zone := c.Query("zone")
	if id := c.Query("id"); id != "" {
		if err := p.DeleteRecord(c.Request.Context(), zone, id); err != nil {
			fail(c, err)
			return
		}
		h.deps.audit(c, "dns.record.delete", id, "ok")
		c.JSON(http.StatusOK, gin.H{"deleted": 1})
		return
	}
	name := c.Query("name")
	if name == "" {
		fail(c, &Error{Op: "delete-record", Kind: KindValidation,
			Message:     "neither a record id nor a name was supplied",
			Remediation: "pass ?id=<record id>, or ?name=<fqdn>&type=<TYPE> to delete by name"})
		return
	}
	rt, err := NormalizeType(c.DefaultQuery("type", "A"))
	if err != nil {
		fail(c, err)
		return
	}
	n, err := DeleteByName(c.Request.Context(), p, zone, rt, name)
	if err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.record.delete", name, "ok")
	c.JSON(http.StatusOK, gin.H{"deleted": n})
}

func (h *handlers) bulkRecords(c *gin.Context) {
	var req struct {
		Credential string     `json:"credential"`
		Zone       string     `json:"zone"`
		Domain     string     `json:"domain"`
		Template   string     `json:"template"`
		Type       RecordType `json:"type"`
		Content    string     `json:"content"`
		TTL        int        `json:"ttl"`
		Proxied    bool       `json:"proxied"`
		Count      int        `json:"count"`
		Proto      string     `json:"proto"`
		Node       string     `json:"node"`
		Region     string     `json:"region"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "bulk-records", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","zone":"<zone id>","domain":"example.com","count":10,"content":"203.0.113.10"}`})
		return
	}
	p, ok := h.provider(c, req.Credential)
	if !ok {
		return
	}
	results, err := BulkCreate(c.Request.Context(), p, BulkSpec{
		ZoneRef: req.Zone, Domain: req.Domain, Template: req.Template,
		Type: req.Type, Content: req.Content, TTL: req.TTL,
		Proxied: req.Proxied, Count: req.Count,
		Vars: TemplateVars{Proto: req.Proto, Node: req.Node, Region: req.Region, Now: h.deps.now()},
	})
	if err != nil {
		// Partial results still matter: return what landed alongside the error.
		if e, ok := AsError(err); ok && len(results) > 0 {
			c.JSON(http.StatusMultiStatus, gin.H{
				"results": results, "error": e.Message, "kind": string(e.Kind), "remediation": e.Remediation,
			})
			return
		}
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.record.bulk", req.Domain, "ok")
	c.JSON(http.StatusOK, gin.H{"results": results})
}

func (h *handlers) setProxied(c *gin.Context) {
	var req struct {
		Credential string `json:"credential"`
		Zone       string `json:"zone"`
		RecordID   string `json:"record_id"`
		Proxied    bool   `json:"proxied"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "set-proxied", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","zone":"<zone id>","record_id":"<id>","proxied":true}`})
		return
	}
	p, ok := h.provider(c, req.Credential)
	if !ok {
		return
	}
	pc, supported := p.(ProxyController)
	if !supported {
		fail(c, &Error{Provider: p.Name(), Op: "set-proxied", Kind: KindUnsupported,
			Message:     p.Name() + " has no CDN, so records cannot be proxied",
			Remediation: "this provider serves authoritative DNS only, which is correct for REALITY and direct-TLS inbounds. Use Cloudflare or ArvanCloud for a proxied hostname."})
		return
	}
	rec, err := pc.SetProxied(c.Request.Context(), req.Zone, req.RecordID, req.Proxied)
	if err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.record.proxy", rec.Name, "ok")
	c.JSON(http.StatusOK, rec)
}
