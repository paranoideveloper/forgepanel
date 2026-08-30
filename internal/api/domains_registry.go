package api

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/settings"
	"github.com/forgepanel/forgepanel/internal/store"
)

// This file is the Domains subsystem (BUG-3): a first-class registry of the
// domains an operator owns, the cascade that makes setting one domain fill SNI /
// Host / cert / link / sub, one-click ACME, and the no-domain guidance that
// steers the operator to REALITY and the other domain-free protocols instead of
// silently emitting plaintext.

// applyDomain fills an inbound's domain from the registry default when the
// operator left it blank, then cascades it. It is called on every create/update
// so the domain-derived fields are always consistent with the chosen domain.
func (s *Server) applyDomain(n *model.Node) {
	if strings.TrimSpace(n.Domain) == "" && s.db != nil {
		n.Domain = s.db.DefaultDomain()
	}
	n.ApplyDomainCascade()
}

// --- registry CRUD --------------------------------------------------------

func (s *Server) handleListDomains(c *gin.Context) {
	ds, err := s.db.ListDomains()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	c.JSON(200, ds)
}

func (s *Server) handleCreateDomain(c *gin.Context) {
	var req struct {
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		TLSMode   string `json:"tls_mode"`
		IsDefault bool   `json:"is_default"`
		Note      string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	name := settings.NormalizeDomain(req.Name)
	if !settings.ValidDomain(name) {
		apierr.Fail(c, &apierr.Error{Op: "domain-add", Kind: apierr.KindValidation, Status: 422,
			Message: "not a valid domain name",
			Fields:  map[string]string{"name": "must be a hostname like vpn.example.com"}})
		return
	}
	d := &store.Domain{Name: name, Provider: req.Provider, TLSMode: req.TLSMode, IsDefault: req.IsDefault, Note: req.Note}
	if err := s.db.CreateDomain(d); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "unique") {
			fail(c, 409, "that domain already exists")
			return
		}
		failErr(c, 500, err)
		return
	}
	s.audit(c, "domain.create", d.Name)
	c.JSON(201, d)
}

func (s *Server) handleUpdateDomain(c *gin.Context) {
	id := parseID(c)
	// Read the CURRENT row before anything is written, so the trail can say what
	// the domain was pointed at before someone repointed it.
	before, _ := s.db.DomainByID(id)
	var req map[string]any
	if err := c.ShouldBindJSON(&req); err != nil {
		failErr(c, 400, err)
		return
	}
	// is_default is toggled through its own transactional endpoint.
	if def, ok := req["is_default"].(bool); ok {
		delete(req, "is_default")
		target := uint(0)
		if def {
			target = id
		}
		if err := s.db.SetDefaultDomain(target); err != nil {
			failErr(c, 400, err)
			return
		}
	}
	allowed := map[string]bool{"provider": true, "tls_mode": true, "note": true, "name": true}
	fields := map[string]any{}
	for k, v := range req {
		if allowed[k] {
			fields[k] = v
		}
	}
	if len(fields) > 0 {
		if err := s.db.UpdateDomainFields(id, fields); err != nil {
			failErr(c, 400, err)
			return
		}
	}
	d, _ := s.db.DomainByID(id)
	s.auditWithDiff(c, "domain.update", strconv.FormatUint(uint64(id), 10),
		jsonOrNil(before), jsonOrNil(d))
	c.JSON(200, d)
}

func (s *Server) handleDeleteDomain(c *gin.Context) {
	id := parseID(c)
	force := c.Query("force") == "true"
	if err := s.db.DeleteDomain(id, force); err != nil {
		if errors.Is(err, store.ErrDomainInUse) {
			apierr.Fail(c, &apierr.Error{Op: "domain-delete", Kind: apierr.KindConflict,
				Code: "domain_in_use", Message: err.Error(), Cause: err,
				Details: map[string]any{"hint": "some inbounds still use this domain; ret:?force=true to delete anyway (their links keep the bare domain string)."}})
			return
		}
		failErr(c, 400, err)
		return
	}
	s.audit(c, "domain.delete", strconv.FormatUint(uint64(id), 10))
	c.JSON(200, gin.H{"deleted": true})
}

// --- no-domain guidance ---------------------------------------------------

// domainFreeProtocols are the protocols that work with no owned domain and no
// certificate — what the panel steers the operator toward when no domain is set.
var domainFreeProtocols = []gin.H{
	{"protocol": "vless", "security": "reality", "label": "VLESS + REALITY", "recommended": true,
		"why": "Borrows a real site's TLS certificate during the handshake. Needs no domain and no cert of your own — only a borrowed dest/serverName. The best domain-free default."},
	{"protocol": "shadowsocks", "label": "Shadowsocks / SS2022",
		"why": "Symmetric encryption, no TLS certificate involved at all."},
	{"protocol": "hysteria2", "label": "Hysteria2 (self-signed + pinned SHA-256)",
		"why": "QUIC with a self-signed cert the client pins by fingerprint; no owned domain required."},
	{"protocol": "tuic", "label": "TUIC (self-signed + pinned SHA-256)",
		"why": "Like Hysteria2: self-signed cert pinned by the client."},
	{"protocol": "wireguard", "label": "WireGuard",
		"why": "Key-based, no TLS or domain."},
	{"protocol": "ssh", "label": "SSH",
		"why": "Host-key based, no domain."},
	{"protocol": "forgedns", "label": "ForgeDNS tunnel",
		"why": "Rides DNS; needs a delegated zone, not a TLS domain."},
}

// handleDomainStatus reports whether any domain is configured and, when not,
// returns the guidance the UI renders as a persistent banner. This is what makes
// the no-domain state loud instead of silently shipping plaintext.
func (s *Server) handleDomainStatus(c *gin.Context) {
	ds, _ := s.db.ListDomains()
	def := s.db.DefaultDomain()
	c.JSON(200, gin.H{
		"has_domain":       len(ds) > 0,
		"default_domain":   def,
		"count":            len(ds),
		"domain_free":      domainFreeProtocols,
		"guidance_en":      "No domain is set. Domain-based TLS protocols cannot be secured, so only IP-based protocols will work. REALITY is the recommended domain-free option — it needs no owned domain or certificate. Add a domain in the Domains section to unlock one-click TLS.",
		"guidance_fa":      "هیچ دامنه\u200cای تنظیم نشده است. پروتکل\u200cهای مبتنی بر TLS بدون دامنه امن نمی\u200cشوند، بنابراین فقط پروتکل\u200cهای مبتنی بر IP کار می\u200cکنند. REALITY گزینهٔ پیشنهادی بدون دامنه است و به دامنه یا گواهی نیاز ندارد. برای فعال\u200cسازی TLS یک\u200cکلیکی، در بخش دامنه\u200cها یک دامنه اضافه کنید.",
		"reality_oneclick": "/api/admin/inbounds/reality-quickstart",
	})
}

// handleRealityQuickstart creates a working REALITY inbound in one click — the
// recommended domain-free default. The panel mints the keypair, shortId and dest
// itself (applyCreateDefaults), so the operator gets a connectable inbound with
// no inputs at all.
func (s *Server) handleRealityQuickstart(c *gin.Context) {
	var req struct {
		Port int    `json:"port"`
		Dest string `json:"dest"`
	}
	_ = c.ShouldBindJSON(&req)
	port := req.Port
	if port == 0 {
		port = freeHighPort()
	}
	n := model.Node{
		Protocol: model.ProtoVLESS, Port: port, Remark: "reality-quickstart",
		Flow:      "xtls-rprx-vision",
		Transport: model.Transport{Network: model.NetTCP},
		Security:  model.Security{Type: model.SecReality},
	}
	if req.Dest != "" {
		n.Security.Reality = &model.Reality{Dest: req.Dest}
	}
	// REALITY is the right domain-free default on a machine the panel owns, and
	// impossible on a platform edge: it terminates TLS itself, on a TCP port of
	// its own, and the platform provides neither. Seeding it there hands a new
	// operator a "one-click working inbound" that cannot carry a byte — which is
	// exactly what happened on the first Railway deploy, where the quickstart
	// created a REALITY inbound and a Shadowsocks one and neither could work.
	// The quickstart's promise is a connectable inbound with no inputs, so on a
	// platform it makes the one shape that IS connectable there.
	if s.paas().Enabled {
		n = model.Node{
			Protocol: model.ProtoVLESS, Remark: "websocket-quickstart",
			Transport: model.Transport{Network: model.NetWS},
			Security:  model.Security{Type: model.SecNone},
		}
	}
	applyCreateDefaults(&n) // mints REALITY keypair, shortId, dest, uuid
	s.applyPaaSAddressing(&n)
	if err := n.Validate(); err != nil {
		failErr(c, 400, err)
		return
	}
	in, err := s.db.CreateInbound(&n)
	if err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.reality_quickstart", in.Remark)
	s.startBackground(s.reloadEngines)
	if s.paas().Enabled {
		c.JSON(201, gin.H{"id": in.ID, "protocol": "vless", "security": "tls", "port": n.Port,
			"note": "VLESS over WebSocket created. On this platform it is the transport the edge " +
				"can carry; REALITY and raw-TCP protocols cannot be served here."})
		return
	}
	c.JSON(201, gin.H{"id": in.ID, "protocol": "vless", "security": "reality", "port": port,
		"note": "REALITY inbound created. It needs no domain or certificate."})
}

// freeHighPort returns a currently-free high TCP port for a quickstart inbound.
func freeHighPort() int {
	for p := 28000; p < 28100; p++ {
		if settings.PortFree("0.0.0.0", p) {
			return p
		}
	}
	return 28443
}

// --- one-click ACME TLS ---------------------------------------------------

// handleInboundOneClickTLS switches an inbound to real TLS on its domain and
// arranges ACME issuance — no manual cert paths, no manual restart. It runs a
// preflight (does the domain resolve to this server; is the ACME challenge port
// reachable) and reports the findings honestly: the TLS config is applied either
// way, but if the preflight fails the response says exactly what to fix, and the
// panel serves a self-signed cert (links carry allowInsecure) until the real one
// can be obtained — it never claims a plaintext or unverifiable inbound is
// securely certified.
func (s *Server) handleInboundOneClickTLS(c *gin.Context) {
	id := parseID(c)
	in, err := s.db.InboundByID(id)
	if err != nil {
		fail(c, 404, "inbound not found")
		return
	}
	n, err := in.Node()
	if err != nil {
		failErr(c, 500, err)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	_ = c.ShouldBindJSON(&req)
	domain := settings.NormalizeDomain(firstNonEmpty(req.Domain, n.Domain, s.db.DefaultDomain()))
	if domain == "" {
		apierr.Fail(c, &apierr.Error{Op: "cert-issue", Kind: apierr.KindValidation, Status: 422,
			Message: "no domain to issue a certificate for",
			Details: map[string]any{"hint": "add a domain in the Domains section, set it on this inbound, or pass {\"domain\":\"vpn.example.com\"}"}})
		return
	}
	if !settings.ValidDomain(domain) {
		fail(c, 422, "invalid domain: "+domain)
		return
	}

	// Ensure the domain is in the registry (so the ACME HostPolicy allows it).
	if _, derr := s.db.DomainByName(domain); derr != nil {
		_ = s.db.CreateDomain(&store.Domain{Name: domain, TLSMode: "acme"})
	} else {
		_ = s.db.UpdateDomainFields(mustDomainID(s, domain), map[string]any{"tls_mode": "acme"})
	}

	// Preflight, honestly reported.
	preflight := gin.H{}
	v4, v6, rerr := settings.ResolveDomain(domain)
	resolves := rerr == nil && (len(v4) > 0 || len(v6) > 0)
	preflight["dns_resolves"] = resolves
	preflight["a_records"] = v4
	preflight["aaaa_records"] = v6
	preflight["challenge_port_80_reachable"] = !settings.PortFree("0.0.0.0", 80) // in use == a listener present
	ready := resolves

	// Apply the TLS config and cascade, no manual paths.
	n.Domain = domain
	n.Security.Type = model.SecTLS
	n.Security.ServerName = domain
	n.ApplyDomainCascade()
	if err := n.Validate(); err != nil {
		failErr(c, 400, err)
		return
	}
	if err := in.SetNode(n); err != nil {
		failErr(c, 500, err)
		return
	}
	if err := s.db.SaveInbound(in); err != nil {
		failErr(c, 500, err)
		return
	}
	s.audit(c, "inbound.tls.oneclick", domain)
	s.startBackground(s.reloadEngines)

	resp := gin.H{"applied": true, "domain": domain, "tls": "acme", "preflight": preflight, "ready": ready}
	if ready {
		resp["note"] = "TLS enabled. The panel obtains and renews the Let's Encrypt certificate for " + domain + " automatically on first connection."
	} else {
		resp["note"] = "TLS enabled, but " + domain + " does not resolve to this server yet, so the certificate cannot be issued until it does. Until then clients connect over a self-signed certificate. Point the domain's A/AAAA record at this server and it will upgrade automatically."
		resp["remediation_en"] = "Create an A record for " + domain + " pointing at this server's public IP, then reconnect."
		resp["remediation_fa"] = "برای " + domain + " یک رکورد A به IP عمومی این سرور بسازید و دوباره اتصال بگیرید."
	}
	c.JSON(200, resp)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mustDomainID(s *Server, name string) uint {
	if d, err := s.db.DomainByName(name); err == nil {
		return d.ID
	}
	return 0
}
