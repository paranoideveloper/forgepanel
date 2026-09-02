package api

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/forgepanel/forgepanel/internal/apierr"
	"github.com/forgepanel/forgepanel/internal/cdncheck"
	"github.com/forgepanel/forgepanel/internal/core"
	"github.com/forgepanel/forgepanel/internal/deploy"
	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/firewall"
	"github.com/forgepanel/forgepanel/internal/protocol/keygen"
	"github.com/forgepanel/forgepanel/internal/protocol/model"
)

// The Preset Wizard turns a couple of inputs (a domain + a Cloudflare API token)
// into a whole working multi-protocol server: it creates one inbound per config
// family the operator's clients expect — REALITY-Vision, REALITY-XHTTP, the
// CDN-frontable TLS transports, VMess-over-WS, Shadowsocks-2022 and the "Brutal"
// REALITY variant — each already wired (keys minted, ports chosen and opened,
// SNIs set, Cloudflare records + edge TLS provisioned) so none of them need the
// manual firewall / cert / DNS steps that usually break a hand-built server.
//
// The design mirrors what actually works in Iran:
//   - REALITY inbounds dial the server DIRECTLY (raw IP) and borrow a rotation of
//     real SNIs — no certificate, no CDN.
//   - The CDN-frontable transports (WS/XHTTP/gRPC over TLS, VMess-WS) sit behind
//     Cloudflare on a proxied sub-domain: Cloudflare terminates the edge TLS, so
//     the client sees a valid cert while the origin only needs a self-signed one.
//   - Shadowsocks-2022 is a raw AEAD tunnel, direct to the IP.

// borrowedSNIs is the REALITY steal-site rotation — a mix of Iranian domestic
// sites (which stay reachable inside Iran) and global sites, exactly the set the
// operator's sample configs use.
// borrowedSNIs are the server names REALITY inbounds advertise.
//
// EVERY entry here must be a site the realityDest below can actually complete a
// TLS handshake for. REALITY does not terminate the client's handshake: it
// relays the ClientHello to dest, and dest answers with a certificate for the
// SNI the client asked for. If dest cannot serve that SNI, the handshake fails
// and the client sees a TLS error — the inbound looks broken even though the
// panel, the key pair and the config are all correct.
//
// This list previously carried snapp.ir and www.digikala.com. Measured on a
// live server (client in France, REALITY inbound in the Netherlands), those two
// failed on every port while the other nine passed, and the correlation was
// exact: they are the only two NOT hosted on Cloudflare (snapp.ir is on
// AliDNS), so www.cloudflare.com cannot answer for them. 28 of 34 variants
// carried traffic; all 6 failures were those two names.
//
// Keep this list and realityDest consistent. Changing dest to a non-Cloudflare
// site means revisiting every entry here.
var borrowedSNIs = []string{
	"www.cloudflare.com", "aparat.ir",
	"discord.com", "chatgpt.com", "gitlab.com", "hcaptcha.com",
	"nobat.com", "taskulu.com", "akharinkhabar.com",
}

// realityDest is the site the REALITY handshake actually forwards to. It must
// serve TLS 1.3 + HTTP/2 and not be domestically blocked; Cloudflare's own site
// is the safe default.
const realityDest = "www.cloudflare.com:443"

// presetPlan is one inbound the wizard will create.
type presetPlan struct {
	remark string
	port   int
	cdn    bool // true → proxied Cloudflare sub-domain, edge TLS
	// needs is the deployment capability this plan requires, empty when it works
	// anywhere. A UDP protocol on a platform that routes no UDP is an inbound
	// the panel would create, enable, and never serve — which is the state this
	// audit spent its time removing, not adding more of.
	needs deploy.Capability
	build func(p *presetPlan, w *presetWizardCtx) *model.Node
}

// presetWizardCtx carries the shared state every plan reads.
type presetWizardCtx struct {
	domain   string         // e.g. example.org
	cdnHost  string         // e.g. edge-<rand>.example.org (proxied)
	serverIP string         // the box's public IPv4
	reality  *model.Reality // ONE keypair shared by every REALITY inbound
}

// tlsName is the certificate name the direct TLS inbounds present.
//
// The panel's own domain when there is one — that certificate is real and
// already renewed — falling back to the server address, where the engine's
// self-signed certificate is what a client accepts with allowInsecure.
func (w *presetWizardCtx) tlsName() string {
	if w.domain != "" {
		return w.domain
	}
	return w.serverIP
}

// wizardPresetPlans is the catalogue, in creation order. Ports avoid the panel
// (80/2053), SSH (22) and the xray control port; the CDN ones sit on Cloudflare
// origin-pull ports so a proxied record reaches them.
func wizardPresetPlans() []presetPlan {
	reality := func(remark string, port int, xhttp bool) presetPlan {
		return presetPlan{remark: remark, port: port, cdn: false, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			n := &model.Node{
				Protocol: model.ProtoVLESS, Port: p.port, Remark: p.remark,
				Security: model.Security{Type: model.SecReality, Fingerprint: "chrome",
					ServerName: borrowedSNIs[0], Reality: cloneReality(w.reality)},
			}
			n.Security.Reality.ServerNames = append([]string{}, borrowedSNIs...)
			if xhttp {
				n.Transport = model.Transport{Network: model.NetXHTTP, Path: "/aux", XHTTPMode: "auto"}
			} else {
				n.Transport = model.Transport{Network: model.NetTCP}
				n.Flow = "xtls-rprx-vision"
			}
			return n
		}}
	}
	cdn := func(remark string, port int, proto model.Protocol, tr model.Transport) presetPlan {
		return presetPlan{remark: remark, port: port, cdn: true, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			return &model.Node{
				Protocol: proto, Port: p.port, Remark: p.remark,
				Domain:    w.cdnHost, // cascades to SNI + Host + cert selection
				Transport: tr,
				Security:  model.Security{Type: model.SecTLS, ServerName: w.cdnHost, Fingerprint: "chrome"},
			}
		}}
	}
	ws := func(path string) model.Transport { return model.Transport{Network: model.NetWS, Path: path} }
	xh := func(path string) model.Transport {
		return model.Transport{Network: model.NetXHTTP, Path: path, XHTTPMode: "auto"}
	}

	// Ports are chosen to never collide: the panel owns 80/2053, ssh 22, xray
	// control 28000. REALITY dials the box directly, so its ports are free
	// choices (443/8443/8444). The CDN inbounds MUST sit on Cloudflare origin-pull
	// HTTPS ports (443/2053/2083/2087/2096/8443) minus the ones already taken, so
	// a proxied record reaches them: 2096, 2087, 2083.
	return []presetPlan{
		reality("Vision · REALITY", 443, false),
		reality("XHTTP · REALITY", 8443, true),
		{remark: "Brutal · REALITY", port: 8444, cdn: false, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			n := &model.Node{Protocol: model.ProtoVLESS, Port: p.port, Remark: p.remark,
				Flow: "xtls-rprx-vision", Transport: model.Transport{Network: model.NetTCP},
				Security: model.Security{Type: model.SecReality, Fingerprint: "chrome",
					ServerName: borrowedSNIs[0], Reality: cloneReality(w.reality)}}
			n.Security.Reality.ServerNames = append([]string{}, borrowedSNIs...)
			return n
		}},
		cdn("VLESS · WS · TLS (CDN)", 2096, model.ProtoVLESS, ws("/wsv")),
		cdn("VLESS · XHTTP · TLS (CDN)", 2087, model.ProtoVLESS, xh("/xhv")),
		cdn("VMess · WS · TLS (CDN)", 2083, model.ProtoVMess, ws("/vm")),
		// --- UDP / QUIC ------------------------------------------------------
		//
		// Nothing above this line is UDP, and in a network that throttles or
		// blocks long-lived TCP these are often the only things that move. They
		// need a routed UDP port, so they are gated: on a platform that gives
		// the container one HTTP port, creating them would produce an inbound
		// that is enabled, listening, and unreachable.
		{remark: "Hysteria2", port: 8446, cdn: false, needs: deploy.UDP, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			// Password and the obfuscation secret are minted by
			// applyCreateDefaults; a self-signed certificate is injected by the
			// engine, which is what Hysteria2 clients expect with insecure=1 on
			// a server that has no domain of its own.
			// No transport network is set: these protocols are UDP by nature, the
			// model has no NetUDP, and the renderer keys on
			// Protocol.IsQUICBased(). The inbounds already running on a live
			// panel carry the default transport, so this matches what works.
			return &model.Node{Protocol: model.ProtoHysteria2, Port: p.port, Remark: p.remark,
				Security: model.Security{Type: model.SecTLS, ServerName: w.tlsName()}}
		}},
		{remark: "TUIC v5", port: 8447, cdn: false, needs: deploy.UDP, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			return &model.Node{Protocol: model.ProtoTUIC, Port: p.port, Remark: p.remark,
				Security: model.Security{Type: model.SecTLS, ServerName: w.tlsName()}}
		}},

		// --- TLS camouflage, direct -----------------------------------------
		//
		// Neither of these fronts through a CDN: AnyTLS and ShadowTLS both do
		// their own TLS, and an edge that terminates first destroys what they
		// are for.
		{remark: "AnyTLS", port: 8448, cdn: false, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			return &model.Node{Protocol: model.ProtoAnyTLS, Port: p.port, Remark: p.remark,
				Transport: model.Transport{Network: model.NetTCP},
				Security:  model.Security{Type: model.SecTLS, ServerName: w.tlsName()}}
		}},
		{remark: "ShadowTLS · Shadowsocks-2022", port: 8449, cdn: false, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			// ShadowTLS is camouflage, not a proxy: applyCreateDefaults mints the
			// inner Shadowsocks credentials so the pair is a complete tunnel.
			// The handshake host must be a real TLS site, which is what the
			// REALITY dest already is.
			return &model.Node{Protocol: model.ProtoShadowTLS, Port: p.port, Remark: p.remark,
				Transport: model.Transport{Network: model.NetTCP},
				ShadowTLS: &model.ShadowTLSOptions{HandshakeHost: hostOf(realityDest), HandshakePort: 443},
			}
		}},

		// --- WireGuard family -------------------------------------------------
		//
		// A different family entirely: no TLS, no HTTP, and the client format is
		// a FILE rather than a link. Both are UDP.
		{remark: "WireGuard", port: 8450, cdn: false, needs: deploy.UDP, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			// Both keypairs and the tunnel addresses come from
			// applyCreateDefaults, so the exported wg-quick config is complete.
			return &model.Node{Protocol: model.ProtoWireGuard, Port: p.port, Remark: p.remark}
		}},
		{remark: "AmneziaWG", port: 8451, cdn: false, needs: deploy.UDP, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			// The obfuscation parameters (Jc/Jmin/Jmax/S1/S2/H1-H4) are defaulted
			// by applyCreateDefaults. A host without the amneziawg kernel module
			// does not fail the wizard: the adapter reports it and the other
			// inbounds are unaffected.
			return &model.Node{Protocol: model.ProtoAmneziaWG, Port: p.port, Remark: p.remark}
		}},

		{remark: "Shadowsocks-2022", port: 8388, cdn: false, build: func(p *presetPlan, w *presetWizardCtx) *model.Node {
			// Leave Password blank: applyCreateDefaults mints a correctly-encoded
			// SS-2022 PSK (std base64, exact key size) via keygen.SS2022PSK. A
			// hand-rolled password would be wrong-length/URL-base64 and xray then
			// rejects the WHOLE config, taking every other inbound down with it.
			return &model.Node{Protocol: model.ProtoShadowsocks, Port: p.port,
				Remark: p.remark, Method: model.SS2022AES128,
				Transport: model.Transport{Network: model.NetTCP}, Security: model.Security{Type: model.SecNone}}
		}},
	}
}

// verifyCDNInbounds asks Cloudflare whether it can actually reach each
// CDN-fronted inbound, after the engines have been reloaded.
//
// It runs the checks concurrently and bounded: this is on the wizard's response
// path, and a serial walk of several ports with a 20-second ceiling each would
// make a successful setup look like a hang.
func (s *Server) verifyCDNInbounds(ctx context.Context, host string, plans []presetPlan) []cdncheck.Result {
	if strings.TrimSpace(host) == "" {
		return nil
	}
	// The cores were reloaded a moment ago in the background; without a beat to
	// bind, every check reports 521 and blames the operator for a race this
	// function started.
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var (
		mu   sync.Mutex
		out  []cdncheck.Result
		wg   sync.WaitGroup
	)
	for i := range plans {
		p := plans[i]
		if !p.cdn {
			continue
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			r := cdncheck.Check(ctx, host, port)
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(p.port)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func cloneReality(r *model.Reality) *model.Reality {
	c := *r
	return &c
}

// handlePresetWizard is the one-shot endpoint: create the whole catalogue.
func (s *Server) handlePresetWizard(c *gin.Context) {
	var req struct {
		Domain    string `json:"domain"`
		CFToken   string `json:"cf_token"`
		AccountID string `json:"cf_account_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, 400, "invalid payload")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	serverIP := s.publicServerIP()
	if serverIP == "" {
		fail(c, 500, "could not determine this server's public IPv4")
		return
	}

	// One REALITY keypair + shortId shared by every REALITY inbound, so all of
	// them present the same pbk/sid (a client can move between them freely).
	kp, err := keygen.RealityKeys()
	if err != nil {
		fail(c, 500, "reality keygen: "+err.Error())
		return
	}
	sid, _ := keygen.ShortID(8)

	wctx := &presetWizardCtx{
		domain:   domain,
		serverIP: serverIP,
		reality:  &model.Reality{PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, ShortID: sid, Dest: realityDest},
	}

	// A single proxied Cloudflare sub-domain fronts every CDN inbound.
	warnings := []string{}
	if domain != "" {
		label, _ := keygen.ShortID(4)
		wctx.cdnHost = "edge-" + label + "." + domain
		if req.CFToken != "" {
			if err := s.wizardCreateCFRecord(req.CFToken, req.AccountID, domain, wctx.cdnHost, serverIP); err != nil {
				// err.Error() on a *dns.Error is three lines: the message, the
				// missing token permission, and the fix. The wizard renders each
				// warning as one <p>, so HTML collapsed all three into a run-on
				// sentence and the one actionable part — "tick Zone → DNS → Edit"
				// — was buried mid-line. Rebuild it from the typed fields.
				warnings = append(warnings, cfWizardWarning(err, wctx.cdnHost, serverIP))
			}
		} else {
			warnings = append(warnings, "no Cloudflare token given — create an A record "+wctx.cdnHost+" → "+serverIP+" (proxied) so the CDN configs resolve")
		}
	} else {
		warnings = append(warnings, "no domain given — the CDN (WS/XHTTP/gRPC/VMess-TLS) inbounds were created but need a domain pointed at this server to be reachable")
	}

	plans := wizardPresetPlans()
	surface := s.deploySurface()
	created := []gin.H{}
	ports := []int{}
	for i := range plans {
		p := &plans[i]
		// Skip CDN inbounds when there is no domain to front them.
		if p.cdn && wctx.cdnHost == "" {
			continue
		}
		// Skip what this deployment cannot carry. Creating a UDP inbound on a
		// platform that routes no UDP produces something enabled, listening and
		// unreachable — the exact state this panel has spent a release removing.
		if p.needs != "" && !surface.Allows(p.needs) {
			warnings = append(warnings, fmt.Sprintf("%s was not created: %s",
				p.remark, surface.Why[p.needs]))
			continue
		}
		// An engine that is not installed will not serve what we are about to
		// create. The inbound is still created — the operator may be about to
		// install the tooling — but reporting a bare "created" for a port that
		// will never open is the failure this audit is here to remove.
		if eng := model.EngineFor(protocolOf(p, wctx)); eng == "amneziawg" {
			if ok, why := core.AmneziaWGReady(); !ok {
				warnings = append(warnings, fmt.Sprintf(
					"%s was created but this server cannot serve it yet: %s", p.remark, why))
			}
		}
		n := p.build(p, wctx)
		applyCreateDefaults(n)
		if err := n.Validate(); err != nil {
			warnings = append(warnings, p.remark+": "+err.Error())
			continue
		}
		in, err := s.db.CreateInbound(n)
		if err != nil {
			warnings = append(warnings, p.remark+": "+err.Error())
			continue
		}
		ports = append(ports, p.port)
		created = append(created, gin.H{"id": in.ID, "remark": p.remark, "port": p.port, "cdn": p.cdn})
	}

	// Open every port we bound, and reload the engines once.
	firewall.EnsureOpen(append(ports, 80, 443))
	s.startBackground(s.reloadEngines)

	// Turn on the config fan-out that gives the subscription its breadth: SNI
	// rotation is on by default, and if the operator has no clean-IP list yet,
	// seed one of known Cloudflare edges (Iran-reachable first) and enable
	// clean-IP fronting so the CDN inbounds are offered through many addresses —
	// the same shape as the sample configs' 28-IP fan-out. Never clobber a list
	// the operator already set.
	if s.knobs().String("sub_clean_ips") == "" {
		if err := s.knobs().SetAll(map[string]string{
			"sub_clean_ips":     "188.114.96.3,188.114.97.3,speed.cloudflare.com,cf.090227.xyz,104.17.148.22,cdn.anycast.eu.org",
			"sub_front_cleanip": "true",
		}); err != nil {
			// Reported rather than dropped: the wizard's whole promise is that
			// what it says it turned on IS on, and a seed list that silently
			// failed to save leaves clean-IP fronting enabled against nothing.
			warnings = append(warnings, "could not seed the clean-IP list: "+err.Error())
		}
	}
	s.audit(c, "wizard.preset", fmt.Sprintf("%d inbounds", len(created)))

	// A certificate the CDN will accept.
	//
	// The panel resolves a certificate per SNI, so the CDN inbounds will serve a
	// real one as soon as it exists; without it they present the build-wide
	// self-signed cert and Cloudflare answers 526 on a Full (Strict) zone. The
	// token that just created the DNS record is exactly what DNS-01 needs.
	if wctx.cdnHost != "" && req.CFToken != "" {
		if note := s.issueCDNCertificate(wctx.cdnHost, req.CFToken, req.AccountID); note != "" {
			warnings = append(warnings, note)
		}
	}

	// Verify the CDN half instead of announcing it.
	//
	// A CDN-fronted inbound fails in a way the operator cannot see from here:
	// the port answers perfectly when tested directly on the origin, and every
	// client gets a Cloudflare error page. Measured on a live zone — a
	// plain-HTTP origin on a proxied port answers 200 locally and 525 through
	// the edge. The wizard used to create the record, create the inbound, report
	// success, and have no idea.
	//
	// Cloudflare's own 5xx codes say precisely which thing is wrong, so this
	// asks the edge and passes the answer on with the fix attached.
	checks := s.verifyCDNInbounds(c.Request.Context(), wctx.cdnHost, plans)
	for _, ch := range checks {
		if ch.Problem != "" {
			warnings = append(warnings, fmt.Sprintf("%s:%d — %s. %s", ch.Host, ch.Port, ch.Problem, ch.Fix))
		}
	}

	c.JSON(201, gin.H{
		"created":     created,
		"count":       len(created),
		"server_ipv4": serverIP,
		"reality":     gin.H{"public_key": kp.PublicKey, "short_id": sid, "server_names": borrowedSNIs},
		"cdn_host":    wctx.cdnHost,
		"cdn_checks":  checks,
		"warnings":    warnings,
		"note":        "Inbounds created and applied. REALITY dials the IP directly; CDN inbounds front through the Cloudflare sub-domain.",
	})
}

// wizardCreateCFRecord adds a proxied A record for the CDN host via the operator's
// Cloudflare token, so the CDN inbounds resolve and get an edge certificate.
func (s *Server) wizardCreateCFRecord(token, accountID, zone, host, ip string) error {
	prov, err := dns.NewCloudflare(dns.Credentials{"api_token": token, "account_id": accountID})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	z, err := prov.FindZone(ctx, zone)
	if err != nil {
		return err
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("bad server IP %q", ip)
	}
	_, err = prov.CreateRecord(ctx, z.Ref(), dns.Record{
		Type: dns.TypeA, Name: host, Content: ip, Proxied: true, TTL: 1,
		Comment: "ForgePanel preset wizard",
	})
	return err
}

// cfWizardWarning renders a failed Cloudflare record creation as one legible
// warning line.
//
// The wizard's warnings are plain strings rendered as a single <p> each, so a
// multi-line err.Error() arrives with its newlines collapsed to spaces. That is
// where the useful half of a *dns.Error goes to die: the missing token
// permission and the fix become the tail of a run-on sentence. Reading the typed
// fields back out puts the required scope first, where it is the first thing the
// operator sees.
func cfWizardWarning(err error, host, ip string) string {
	e := apierr.From(err)
	var b strings.Builder
	b.WriteString("Cloudflare DNS: ")
	b.WriteString(e.Message)
	if e.MissingScope != "" {
		b.WriteString(" — the API token is missing the permission ")
		b.WriteString(e.MissingScope)
	} else if e.Remediation != "" {
		b.WriteString(" — ")
		b.WriteString(e.Remediation)
	}
	b.WriteString(". Or create an A record ")
	b.WriteString(host)
	b.WriteString(" → ")
	b.WriteString(ip)
	b.WriteString(" (proxied) manually.")
	return b.String()
}

// protocolOf reports the protocol a plan builds, without committing to the node
// (building is cheap and has no side effects, so this stays honest even as
// plans grow conditional).
func protocolOf(p *presetPlan, w *presetWizardCtx) model.Protocol {
	n := p.build(p, w)
	if n == nil {
		return ""
	}
	return n.Protocol
}
