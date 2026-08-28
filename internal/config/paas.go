package config

import (
	"os"
	"strconv"
	"strings"
)

// PaaS mode: ForgePanel behind a platform edge (Railway, Render, Fly, Koyeb,
// Heroku) instead of on a machine it owns.
//
// Such a platform hands the container ONE plain-HTTP port and terminates TLS
// itself at :443 on a hostname it assigns. That inverts three assumptions the
// panel is otherwise built on, and each one is a way the panel breaks there:
//
//   - It always serves TLS. Behind an edge that already terminated TLS, an
//     HTTPS listener answers the platform's plaintext proxy request with a
//     handshake and every page load fails.
//   - It binds every inbound on the address the client dials. Here the client
//     dials the platform's hostname on :443 and the container can only bind
//     loopback on its own assigned port, so a literal bind is either a refused
//     address or a port nothing routes to.
//   - It reaches each inbound on its own port. Here there is exactly one port,
//     shared with the panel itself, and inbounds are separated by URL path.
//
// This type carries what the platform decided so the rest of the panel can ask
// rather than guess. Enabled false means a normal install and nothing changes.
type PaaS struct {
	// Enabled turns the whole mode on. It is set by FORGEPANEL_PAAS, or
	// inferred from a platform's own identifying variable.
	Enabled bool
	// Platform names what was detected ("railway", "render", …) for the banner
	// and the diagnostics page. It is descriptive only.
	Platform string
	// Domain is the public hostname the platform serves the container on. It is
	// what a client link and the panel URL must say, and it is NOT what the
	// container binds.
	Domain string
	// Port is the plain-HTTP port the platform routes to inside the container.
	Port int
	// PublicPort is the port the outside world connects to — 443, because the
	// edge terminates TLS there. Links and the panel URL use this, never Port.
	PublicPort int
}

// paasPort is the port to bind when a platform did not name one. Railway,
// Render and Fly all inject PORT; Heroku always does. 8080 is the convention
// for the ones that do not.
const paasPort = 8080

// DetectPaaS resolves PaaS mode from the environment.
//
// FORGEPANEL_PAAS is authoritative in both directions: "1" forces the mode on
// (for a platform not listed here, or a hand-rolled reverse proxy), and "0"
// forces it off even on a platform that would otherwise be detected. Without
// it, a platform is recognised by the variable it injects into every container.
//
// Detection is deliberately keyed on the platform's OWN variable and never on
// PORT alone. PORT is a common variable that plenty of ordinary hosts set for
// unrelated reasons, and treating it as the signal would silently drop a normal
// install's TLS.
func DetectPaaS() PaaS {
	p := PaaS{PublicPort: 443}
	switch {
	case os.Getenv("RAILWAY_PUBLIC_DOMAIN") != "" || os.Getenv("RAILWAY_ENVIRONMENT") != "":
		p.Enabled, p.Platform = true, "railway"
		p.Domain = firstEnv("RAILWAY_PUBLIC_DOMAIN", "RAILWAY_STATIC_URL")
	case os.Getenv("RENDER_EXTERNAL_HOSTNAME") != "":
		p.Enabled, p.Platform = true, "render"
		p.Domain = os.Getenv("RENDER_EXTERNAL_HOSTNAME")
	case os.Getenv("FLY_APP_NAME") != "":
		p.Enabled, p.Platform = true, "fly"
		p.Domain = os.Getenv("FLY_APP_NAME") + ".fly.dev"
	case os.Getenv("KOYEB_PUBLIC_DOMAIN") != "":
		p.Enabled, p.Platform = true, "koyeb"
		p.Domain = os.Getenv("KOYEB_PUBLIC_DOMAIN")
	}
	if v := os.Getenv("FORGEPANEL_PAAS"); v != "" {
		if envBool("FORGEPANEL_PAAS") {
			p.Enabled = true
			if p.Platform == "" {
				p.Platform = "generic"
			}
		} else {
			return PaaS{PublicPort: 443}
		}
	}
	if !p.Enabled {
		return p
	}
	// An operator-set domain wins over the platform's assigned hostname: it is
	// how a custom domain attached at the platform's edge reaches the links.
	if d := envStr("FORGEPANEL_DOMAIN", ""); d != "" {
		p.Domain = d
	}
	p.Domain = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p.Domain, "https://"), "http://"), "/")
	p.Port = envInt("PORT", envInt("FORGEPANEL_PANEL_PORT", paasPort))
	if n := envInt("FORGEPANEL_PUBLIC_PORT", 0); n > 0 {
		p.PublicPort = n
	}
	return p
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// PaaS returns the detected platform configuration. The zero value (Enabled
// false) is a normal install.
func (c *Config) PaaS() PaaS { return c.paas }

// applyPaaS overrides the persisted panel address with what the platform
// dictates.
//
// These are applied on EVERY start, not just first boot, and they deliberately
// override panel.json — which is the opposite of how every other environment
// variable here behaves. The reason is ownership: on a normal install the
// operator owns the address and the panel must not fight their saved choice,
// but on a platform the address is not the operator's to choose. The port is
// assigned per deploy and can change between them, the hostname is the
// platform's, and TLS happens at an edge the container cannot see. A persisted
// port from an earlier deploy would bind a port nothing routes to, and the
// panel would come up perfectly and be unreachable.
func (p *PaaS) applyPaaS(panel *PanelSettings) {
	if !p.Enabled {
		return
	}
	panel.BindAddress = "0.0.0.0"
	panel.Port = p.Port
	if p.Domain != "" {
		panel.Domain = p.Domain
	}
	// The edge holds the certificate. Asking for one here would start an ACME
	// challenge for a hostname that resolves to the platform, not to us, and
	// serving TLS would break the plaintext proxy request the edge sends.
	panel.HTTPSEnabled = false
	panel.ACME.Enabled = false
}

// PublicPortString renders the ":port" suffix a URL needs, empty for 443.
func (p PaaS) PublicPortString() string {
	if p.PublicPort == 0 || p.PublicPort == 443 {
		return ""
	}
	return ":" + strconv.Itoa(p.PublicPort)
}
