package api

// Check the preset's prerequisites BEFORE it creates anything.
//
// The wizard's promise is that two inputs produce a working server. When one of
// its assumptions is wrong it used to find out halfway through: records created,
// inbounds created, and a warning explaining that the token could not do the one
// thing that mattered. The operator then fixed that, ran it again, and met the
// next problem.
//
// This asks every question up front and answers all of them at once, so a
// failing setup is one round of fixes rather than one per attempt. Nothing here
// writes.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/cdncheck"
	"github.com/forgepanel/forgepanel/internal/dns"
)

// preflightCheck is one prerequisite and its verdict.
type preflightCheck struct {
	// Name is what was checked, in the operator's terms.
	Name string `json:"name"`
	// OK is the verdict. Fatal marks the ones that make the wizard pointless
	// rather than merely degraded.
	OK    bool `json:"ok"`
	Fatal bool `json:"fatal,omitempty"`
	// Detail is what was found; Fix is what to do when OK is false.
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

func (s *Server) handlePresetPreflight(c *gin.Context) {
	var req struct {
		Domain    string `json:"domain"`
		CFToken   string `json:"cf_token"`
		AccountID string `json:"cf_account_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "invalid payload")
		return
	}
	domain := dns.NormalizeDomain(req.Domain)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	checks := []preflightCheck{}
	add := func(ch preflightCheck) { checks = append(checks, ch) }

	// 1. An address for clients to dial. Without it the REALITY inbounds have
	//    nothing to advertise and the DNS record has nothing to point at.
	ip := s.publicServerIP()
	add(preflightCheck{
		Name: "public IPv4", OK: ip != "", Fatal: true,
		Detail: ip,
		Fix: "This server's public IPv4 could not be determined. Set it explicitly in the panel's " +
			"settings, or check that outbound HTTPS works so the address can be discovered.",
	})

	// Everything below is about Cloudflare. Without a domain the preset still
	// builds the direct (REALITY, Shadowsocks) inbounds, so this is not fatal.
	if domain == "" {
		add(preflightCheck{
			Name: "domain", OK: false,
			Detail: "none given",
			Fix: "Without a domain the CDN-fronted inbounds are skipped and you get the direct ones " +
				"(REALITY, Shadowsocks) only. Add a domain to get the CDN half.",
		})
		s.respondPreflight(c, checks)
		return
	}
	add(preflightCheck{Name: "domain", OK: true, Detail: domain})

	if strings.TrimSpace(req.CFToken) == "" {
		add(preflightCheck{
			Name: "Cloudflare token", OK: false,
			Detail: "none given",
			Fix: "Without a token the DNS record must be created by hand. Supply one with Zone → DNS → Edit " +
				"to have the wizard do it.",
		})
		s.respondPreflight(c, checks)
		return
	}

	prov, err := dns.NewCloudflare(dns.Credentials{"api_token": req.CFToken, "account_id": req.AccountID})
	if err != nil {
		add(preflightCheck{Name: "Cloudflare token", OK: false, Fatal: true, Detail: err.Error(),
			Fix: "The token could not be used at all. Check it was pasted whole."})
		s.respondPreflight(c, checks)
		return
	}

	// 2. Is the token real, and what may it do?
	id, err := prov.VerifyCredentials(ctx)
	if err != nil {
		add(preflightCheck{Name: "Cloudflare token", OK: false, Fatal: true, Detail: err.Error(),
			Fix: "Cloudflare rejected the token. Create one with the Zone → DNS → Edit permission on this zone."})
		s.respondPreflight(c, checks)
		return
	}
	add(preflightCheck{Name: "Cloudflare token", OK: true,
		Detail: "valid" + statusSuffix(id)})

	// 3. Does the zone exist for this token? A token scoped to a different zone
	//    verifies fine and then cannot see this domain, which reads as "the
	//    token is wrong" when it is the SCOPE that is wrong.
	zone, err := prov.FindZone(ctx, domain)
	if err != nil || zone == nil {
		detail := "not found"
		if err != nil {
			detail = err.Error()
		}
		add(preflightCheck{Name: "zone", OK: false, Fatal: true, Detail: detail,
			Fix: "This token cannot see a zone for " + domain + ". Either the domain is not on this " +
				"Cloudflare account, or the token is scoped to different zones."})
		s.respondPreflight(c, checks)
		return
	}
	add(preflightCheck{Name: "zone", OK: true, Detail: zone.Name})

	// 4. The setting that decides whether the CDN inbounds can work at all.
	//
	//    Cloudflare speaks HTTPS to the origin on every proxied HTTPS port, and
	//    the preset puts its CDN inbounds on 2096/2087/2083. On Flexible the
	//    edge speaks plain HTTP to the origin, so those inbounds answer 525 —
	//    measured on a live zone, and invisible from the origin, which serves
	//    them perfectly when tested directly.
	// GetZoneSettings is on the Cloudflare implementation rather than the
	// Provider interface, because no other provider has the concept.
	var settings map[string]string
	var serr error
	if cf, ok := prov.(*dns.Cloudflare); ok {
		settings, serr = cf.GetZoneSettings(ctx, zone.ID)
	}
	switch {
	case serr != nil:
		add(preflightCheck{Name: "zone SSL mode", OK: false, Detail: serr.Error(),
			Fix: "Could not read the zone's SSL mode. Check it is Full — Flexible cannot carry the " +
				"CDN inbounds, which sit on ports other than 443."})
	case settings["ssl"] == "flexible":
		add(preflightCheck{Name: "zone SSL mode", OK: false, Fatal: true, Detail: "flexible",
			Fix: "Set the zone's SSL mode to Full. On Flexible, Cloudflare speaks plain HTTP to the " +
				"origin, and every CDN inbound answers 525 — while the origin serves them correctly " +
				"when you test it directly, which is what makes this so hard to spot."})
	case settings["ssl"] == "off":
		add(preflightCheck{Name: "zone SSL mode", OK: false, Fatal: true, Detail: "off",
			Fix: "The zone has TLS turned off entirely. Set the SSL mode to Full."})
	case settings["ssl"] == "strict" || settings["ssl"] == "full_strict":
		add(preflightCheck{Name: "zone SSL mode", OK: false, Detail: settings["ssl"],
			Fix: "Full (Strict) requires a publicly-signed certificate on the origin; the preset " +
				"provisions a self-signed one, which answers 526. Use Full, or install a real " +
				"certificate for the CDN hostname."})
	default:
		add(preflightCheck{Name: "zone SSL mode", OK: true, Detail: settings["ssl"]})
	}

	// 5. WebSockets: two of the CDN inbounds are WS, and the setting is off on
	//    some plans.
	if v, ok := settings["websockets"]; ok && v != "on" {
		add(preflightCheck{Name: "WebSockets", OK: false, Detail: v,
			Fix: "Turn WebSockets on for the zone, or the WS inbounds will not upgrade."})
	} else {
		add(preflightCheck{Name: "WebSockets", OK: true, Detail: "on"})
	}

	// 6. The ports the CDN half needs must be ones Cloudflare actually proxies.
	//    A mismatch here means a record that looks perfect and carries nothing.
	bad := []string{}
	for _, p := range wizardCDNPorts() {
		if !cdncheck.PortIsProxied(p) {
			bad = append(bad, strconv.Itoa(p))
		}
	}
	if len(bad) > 0 {
		add(preflightCheck{Name: "CDN ports", OK: false, Fatal: true,
			Detail: "not proxied: " + strings.Join(bad, ", "),
			Fix:    "Cloudflare proxies HTTPS only on 443, 2053, 2083, 2087, 2096 and 8443."})
	} else {
		add(preflightCheck{Name: "CDN ports", OK: true, Detail: "all proxied by Cloudflare"})
	}

	s.respondPreflight(c, checks)
}

// respondPreflight summarises so the caller does not have to.
func (s *Server) respondPreflight(c *gin.Context, checks []preflightCheck) {
	blocking := 0
	problems := 0
	for _, ch := range checks {
		if ch.OK {
			continue
		}
		problems++
		if ch.Fatal {
			blocking++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"checks": checks,
		// ready means the wizard will produce something that works. Problems
		// that are not fatal reduce what it can build rather than break it.
		"ready":    blocking == 0,
		"problems": problems,
		"blocking": blocking,
	})
}

func statusSuffix(id *dns.Identity) string {
	if id == nil || id.Status == "" {
		return ""
	}
	return " (" + id.Status + ")"
}

// wizardCDNPorts is the ports the CDN plans use, read from the plan table so the
// two cannot disagree.
func wizardCDNPorts() []int {
	var out []int
	for _, p := range wizardPresetPlans() {
		if p.cdn {
			out = append(out, p.port)
		}
	}
	return out
}
