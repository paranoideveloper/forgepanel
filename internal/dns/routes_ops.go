package dns

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *handlers) getZoneSettings(c *gin.Context) {
	p, ok := h.provider(c, c.Query("credential"))
	if !ok {
		return
	}
	sc, supported := p.(ZoneSettingsController)
	if !supported {
		fail(c, unsupportedSettings(p))
		return
	}
	settings, err := sc.GetZoneSettings(c.Request.Context(), c.Query("zone"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

func (h *handlers) applyZoneSettings(c *gin.Context) {
	var req struct {
		Credential string       `json:"credential"`
		Zone       string       `json:"zone"`
		Settings   ZoneSettings `json:"settings"`
		// Recommended applies RecommendedZoneSettings instead of Settings.
		Recommended bool `json:"recommended"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "apply-zone-settings", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","zone":"<zone id>","recommended":true}`})
		return
	}
	p, ok := h.provider(c, req.Credential)
	if !ok {
		return
	}
	sc, supported := p.(ZoneSettingsController)
	if !supported {
		fail(c, unsupportedSettings(p))
		return
	}
	want := req.Settings
	if req.Recommended {
		want = RecommendedZoneSettings()
	}
	results, err := sc.ApplyZoneSettings(c.Request.Context(), req.Zone, want)
	if err != nil {
		if e, ok := AsError(err); ok && len(results) > 0 {
			c.JSON(http.StatusMultiStatus, gin.H{
				"results": results, "error": e.Message, "kind": string(e.Kind),
				"missing_scope": e.MissingScope, "remediation": e.Remediation,
			})
			return
		}
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.zone.settings", req.Zone, "ok")
	c.JSON(http.StatusOK, gin.H{"results": results})
}

func unsupportedSettings(p Provider) error {
	return &Error{Provider: p.Name(), Op: "zone-settings", Kind: KindUnsupported,
		Message:     p.Name() + " does not expose edge settings through its API",
		Remediation: "set origin-pull TLS to Full (strict) and enable WebSockets in the provider's dashboard by hand; a Flexible origin-pull mode breaks every TLS inbound."}
}

func (h *handlers) preflight(c *gin.Context) {
	var req struct {
		Credential string        `json:"credential"`
		Domain     string        `json:"domain"`
		ExpectIP   string        `json:"expect_ip"`
		Challenge  ChallengeType `json:"challenge"`
		Proxied    bool          `json:"proxied"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "preflight", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"domain":"ws.example.com","expect_ip":"203.0.113.10","challenge":"dns-01"}`})
		return
	}
	in := PreflightInput{
		Domain: req.Domain, ExpectIP: req.ExpectIP,
		Challenge: req.Challenge, Proxied: req.Proxied,
	}
	// A credential is optional: without it the DNS checks still run, they just
	// cannot compare against the provider's assigned nameservers.
	if strings.TrimSpace(req.Credential) != "" {
		if store, ok := h.store(c); ok {
			if p, _, err := store.Provider(req.Credential); err == nil {
				if res, err := ResolveZone(c.Request.Context(), p, h.deps.resolver(), req.Domain); err == nil {
					in.Resolution = res
					in.Zone = &res.Zone
				}
			}
		}
	}
	report, err := h.deps.preflight().Run(c.Request.Context(), in)
	if err != nil {
		fail(c, err)
		return
	}
	status := http.StatusOK
	if !report.OK {
		status = http.StatusUnprocessableEntity
	}
	c.JSON(status, report)
}

// poolFor builds a Pool for the named pool, optionally with a provider for
// healing.
func (h *handlers) poolFor(c *gin.Context, cfg PoolConfig) (*Pool, bool) {
	if h.deps.Pools == nil {
		fail(c, &Error{Op: "pool", Kind: KindNotImplemented,
			Message:     "no rotation-pool storage is configured",
			Remediation: "wire Deps.Pools (see dns.NewGormStore) when mounting the DNS routes"})
		return nil, false
	}
	cfg.Name = c.Param("name")
	if cfg.Now == nil {
		cfg.Now = h.deps.Now
	}
	pool, err := NewPool(cfg, h.deps.Pools)
	if err != nil {
		fail(c, err)
		return nil, false
	}
	return pool, true
}

func (h *handlers) listPool(c *gin.Context) {
	pool, ok := h.poolFor(c, PoolConfig{})
	if !ok {
		return
	}
	entries, err := pool.Entries()
	if err != nil {
		fail(c, err)
		return
	}
	active, _ := pool.Active()
	c.JSON(http.StatusOK, gin.H{"pool": pool.Name(), "entries": entries, "active": active})
}

func (h *handlers) addPoolEntry(c *gin.Context) {
	var req struct {
		Domain   string `json:"domain"`
		Zone     string `json:"zone"`
		RecordID string `json:"record_id"`
		Provider string `json:"provider"`
		Target   string `json:"target"`
		Proxied  bool   `json:"proxied"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "add-pool-entry", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"domain":"ws-a.example.com","zone":"<zone id>","target":"203.0.113.10"}`})
		return
	}
	pool, ok := h.poolFor(c, PoolConfig{})
	if !ok {
		return
	}
	entry := PoolEntry{
		Domain: req.Domain, Zone: req.Zone, RecordID: req.RecordID,
		Provider: req.Provider, Target: req.Target, Proxied: req.Proxied,
		State: PoolActive, CreatedAt: h.deps.now().UTC(),
	}
	if err := pool.Add(entry); err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.pool.add", req.Domain, "ok")
	c.JSON(http.StatusCreated, entry)
}

func (h *handlers) removePoolEntry(c *gin.Context) {
	pool, ok := h.poolFor(c, PoolConfig{})
	if !ok {
		return
	}
	domain := c.Query("domain")
	if strings.TrimSpace(domain) == "" {
		fail(c, &Error{Op: "remove-pool-entry", Kind: KindValidation,
			Message: "no domain was supplied", Remediation: "pass ?domain=<fqdn>"})
		return
	}
	if err := pool.Remove(domain); err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.pool.remove", domain, "ok")
	c.JSON(http.StatusOK, gin.H{"removed": NormalizeDomain(domain)})
}

func (h *handlers) checkPool(c *gin.Context) {
	pool, ok := h.poolFor(c, PoolConfig{})
	if !ok {
		return
	}
	report, err := pool.Check(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *handlers) rotatePool(c *gin.Context) {
	var req struct {
		Credential       string `json:"credential"`
		Zone             string `json:"zone"`
		Domain           string `json:"domain"`
		Template         string `json:"template"`
		Target           string `json:"target"`
		Proxied          bool   `json:"proxied"`
		TTL              int    `json:"ttl"`
		MinHealthy       int    `json:"min_healthy"`
		FailureThreshold int    `json:"failure_threshold"`
		DeleteRetired    bool   `json:"delete_retired"`
		Proto            string `json:"proto"`
		Node             string `json:"node"`
	}
	// A body is optional: rotating with no config just health-checks and
	// retires, which is a legitimate scheduled operation.
	_ = c.ShouldBindJSON(&req)

	cfg := PoolConfig{
		ZoneRef: req.Zone, Domain: req.Domain, Template: req.Template,
		Target: req.Target, Proxied: req.Proxied, TTL: req.TTL,
		MinHealthy: req.MinHealthy, FailureThreshold: req.FailureThreshold,
		DeleteRetired: req.DeleteRetired,
		Vars:          TemplateVars{Proto: req.Proto, Node: req.Node, Now: h.deps.now()},
	}
	if strings.TrimSpace(req.Credential) != "" {
		p, ok := h.provider(c, req.Credential)
		if !ok {
			return
		}
		cfg.Provider = p
	}
	pool, ok := h.poolFor(c, cfg)
	if !ok {
		return
	}
	result, err := pool.Rotate(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.pool.rotate", pool.Name(), "ok")
	c.JSON(http.StatusOK, result)
}

func (h *handlers) listCleanIPs(c *gin.Context) {
	if h.deps.CleanIPs == nil {
		fail(c, errNoCleanIPStore())
		return
	}
	sets, err := h.deps.CleanIPs.ListCleanIPSets()
	if err != nil {
		fail(c, wrapRepoError("list-clean-ips", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"sets": sets})
}

func (h *handlers) getCleanIPs(c *gin.Context) {
	if h.deps.CleanIPs == nil {
		fail(c, errNoCleanIPStore())
		return
	}
	maxAge := 24 * time.Hour
	if raw := c.Query("max_age"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			maxAge = d
		}
	}
	set, err := LoadFreshCleanIPs(h.deps.CleanIPs, c.Param("name"), maxAge, h.deps.now())
	if err != nil {
		if set != nil {
			// Stale but present: hand it back with the warning rather than
			// pretending nothing was scanned.
			e, _ := AsError(err)
			c.JSON(http.StatusOK, gin.H{"set": set, "stale": true, "warning": e.Message, "remediation": e.Remediation})
			return
		}
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"set": set, "stale": false})
}

func (h *handlers) scanCleanIPs(c *gin.Context) {
	if h.deps.CleanIPs == nil {
		fail(c, errNoCleanIPStore())
		return
	}
	var req struct {
		Name        string   `json:"name"`
		SNI         string   `json:"sni"`
		Port        int      `json:"port"`
		CIDRs       []string `json:"cidrs"`
		Addresses   []string `json:"addresses"`
		Samples     int      `json:"samples"`
		Concurrency int      `json:"concurrency"`
		Probes      int      `json:"probes"`
		Keep        int      `json:"keep"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "scan-clean-ips", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"sni":"ws.example.com","samples":256}`})
		return
	}
	job := ScanJob{
		Name: req.Name, Repo: h.deps.CleanIPs, Keep: req.Keep, Now: h.deps.Now,
		Config: ScanConfig{
			SNI: req.SNI, Port: req.Port, CIDRs: req.CIDRs, Addresses: req.Addresses,
			Samples: req.Samples, Concurrency: req.Concurrency, Probes: req.Probes,
		},
	}
	set, report, err := job.Run(c.Request.Context())
	if err != nil {
		if e, ok := AsError(err); ok && report != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"set": set, "report": report, "error": e.Message, "remediation": e.Remediation,
			})
			return
		}
		fail(c, err)
		return
	}
	h.deps.audit(c, "dns.cleanip.scan", set.SNI, "ok")
	c.JSON(http.StatusOK, gin.H{"set": set, "report": report})
}

func errNoCleanIPStore() error {
	return &Error{Op: "clean-ips", Kind: KindNotImplemented,
		Message:     "no clean-IP storage is configured",
		Remediation: "wire Deps.CleanIPs (see dns.NewGormStore) when mounting the DNS routes"}
}

func (h *handlers) provision(c *gin.Context) {
	var req struct {
		Credential       string         `json:"credential"`
		Domain           string         `json:"domain"`
		IP               string         `json:"ip"`
		Node             string         `json:"node"`
		Region           string         `json:"region"`
		Template         string         `json:"template"`
		TTL              int            `json:"ttl"`
		Protocols        []ProtocolPlan `json:"protocols"`
		Challenge        ChallengeType  `json:"challenge"`
		SkipDNS          bool           `json:"skip_dns"`
		SkipSettings     bool           `json:"skip_settings"`
		SkipPreflight    bool           `json:"skip_preflight"`
		SkipTrafficProof bool           `json:"skip_traffic_proof"`
		Scan             bool           `json:"scan"`
		ScanSamples      int            `json:"scan_samples"`
		// PropagationWaitSeconds bounds the propagation wait; -1 disables it.
		PropagationWaitSeconds int `json:"propagation_wait_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &Error{Op: "provision", Kind: KindValidation,
			Message:     "could not parse the request body: " + err.Error(),
			Remediation: `send {"credential":"<id>","domain":"example.com","ip":"203.0.113.10","node":"fra1"}`})
		return
	}
	cfg := WizardConfig{
		Domain: req.Domain, OriginIP: req.IP, Node: req.Node, Region: req.Region,
		Template: req.Template, TTL: req.TTL, Protocols: req.Protocols,
		Challenge: req.Challenge, SkipDNS: req.SkipDNS, SkipSettings: req.SkipSettings,
		SkipPreflight: req.SkipPreflight, SkipTrafficProof: req.SkipTrafficProof,
		Resolver: h.deps.resolver(), CleanIPs: h.deps.CleanIPs, Now: h.deps.Now,
		Preflight: h.deps.Preflight,
	}
	switch {
	case req.PropagationWaitSeconds < 0:
		cfg.DNSPropagationWait = -1
	case req.PropagationWaitSeconds > 0:
		cfg.DNSPropagationWait = time.Duration(req.PropagationWaitSeconds) * time.Second
	}
	if req.Scan {
		cfg.Scan = &ScanConfig{Samples: req.ScanSamples}
	}
	if !req.SkipDNS {
		p, ok := h.provider(c, req.Credential)
		if !ok {
			return
		}
		cfg.Provider = p
	}
	report, err := Run(c.Request.Context(), cfg)
	if err != nil {
		fail(c, err)
		return
	}
	result := "ok"
	status := http.StatusOK
	if !report.OK {
		result, status = "failed", http.StatusUnprocessableEntity
	}
	h.deps.audit(c, "dns.provision", req.Domain, result)
	c.JSON(status, report)
}
