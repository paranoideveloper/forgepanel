package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

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
	build  func(p *presetPlan, w *presetWizardCtx) *model.Node
}

// presetWizardCtx carries the shared state every plan reads.
type presetWizardCtx struct {
	domain   string         // e.g. anonymous.observer
	cdnHost  string         // e.g. edge-<rand>.anonymous.observer (proxied)
	serverIP string         // the box's public IPv4
	reality  *model.Reality // ONE keypair shared by every REALITY inbound
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
		c.JSON(400, gin.H{"error": "invalid payload"})
		return
	}
	domain := strings.TrimSpace(strings.ToLower(req.Domain))
	serverIP := s.publicServerIP()
	if serverIP == "" {
		c.JSON(500, gin.H{"error": "could not determine this server's public IPv4"})
		return
	}

	// One REALITY keypair + shortId shared by every REALITY inbound, so all of
	// them present the same pbk/sid (a client can move between them freely).
	kp, err := keygen.RealityKeys()
	if err != nil {
		c.JSON(500, gin.H{"error": "reality keygen: " + err.Error()})
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
				warnings = append(warnings, "Cloudflare DNS: "+err.Error()+" — create an A record "+wctx.cdnHost+" → "+serverIP+" (proxied) manually")
			}
		} else {
			warnings = append(warnings, "no Cloudflare token given — create an A record "+wctx.cdnHost+" → "+serverIP+" (proxied) so the CDN configs resolve")
		}
	} else {
		warnings = append(warnings, "no domain given — the CDN (WS/XHTTP/gRPC/VMess-TLS) inbounds were created but need a domain pointed at this server to be reachable")
	}

	plans := wizardPresetPlans()
	created := []gin.H{}
	ports := []int{}
	for i := range plans {
		p := &plans[i]
		// Skip CDN inbounds when there is no domain to front them.
		if p.cdn && wctx.cdnHost == "" {
			continue
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
	if s.db.GetSetting("sub_clean_ips") == "" {
		_ = s.db.SetSetting("sub_clean_ips",
			"188.114.96.3,188.114.97.3,speed.cloudflare.com,cf.090227.xyz,104.17.148.22,cdn.anycast.eu.org")
		_ = s.db.SetSetting("sub_front_cleanip", "1")
	}
	s.audit(c, "wizard.preset", fmt.Sprintf("%d inbounds", len(created)))

	c.JSON(201, gin.H{
		"created":     created,
		"count":       len(created),
		"server_ipv4": serverIP,
		"reality":     gin.H{"public_key": kp.PublicKey, "short_id": sid, "server_names": borrowedSNIs},
		"cdn_host":    wctx.cdnHost,
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
