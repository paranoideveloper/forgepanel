package config

import (
	"os"
	"path/filepath"
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
	// TCPPorts and UDPPorts are ports the platform routes to this container
	// DIRECTLY, in addition to the one HTTP port — raw, without terminating
	// anything. Fly does this when a service block declares them and a
	// dedicated IPv4 is allocated; Railway, Render and Koyeb do not do it at
	// all.
	//
	// They are declared by the operator rather than detected, because nothing
	// in the container's environment reports either fact. That cuts both ways
	// and the wrong way is worse: a port listed here but not actually routed
	// produces an inbound the panel offers and no client can reach, which is
	// harder to diagnose than the refusal it replaced.
	TCPPorts []int
	UDPPorts []int
	// CDNFronted is set when the platform serves every deployment through a CDN
	// that PARSES WebSocket traffic rather than passing the upgraded socket
	// through. Render does, with Cloudflare, for every deploy.
	//
	// It decides which transports can be offered at all, and the distinction is
	// finer than "is there a proxy in front": ws and xhttp are ordinary HTTP and
	// go through untouched, while two transports do not produce WebSocket frames
	// and are dropped —
	//
	//   httpupgrade never performs a WebSocket handshake (no Sec-WebSocket-Key),
	//   so the CDN answers 101 and then relays nothing;
	//   brook completes a valid handshake and then writes RAW bytes, not frames.
	//
	// Both were measured working through the same panel with no CDN in front, so
	// this is a property of the edge, not of the panel.
	CDNFronted bool
	// UDPBindHost is the address a UDP inbound must bind, when the platform
	// demands a particular one. Fly routes UDP only to `fly-global-services`
	// and refuses to rewrite the port; binding 0.0.0.0 there silently receives
	// nothing. Empty means the ordinary wildcard bind.
	UDPBindHost string
}

// RoutesTCP reports whether the platform routes raw TCP to this port.
func (p PaaS) RoutesTCP(port int) bool { return containsPort(p.TCPPorts, port) }

// RoutesUDP reports whether the platform routes UDP to this port.
func (p PaaS) RoutesUDP(port int) bool { return containsPort(p.UDPPorts, port) }

func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// parsePorts reads a comma-separated port list, dropping anything that is not a
// usable port rather than failing the whole boot: one typo in an env var must
// not stop a panel from starting, and the ports it did understand are still
// correct.
func parsePorts(raw string) []int {
	var out []int
	for _, f := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, n)
	}
	return out
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
		// Every Render deployment is served through Cloudflare — its own
		// response headers say so — and Cloudflare relays WebSocket frames
		// rather than the upgraded socket.
		p.CDNFronted = true
	case os.Getenv("FLY_APP_NAME") != "":
		p.Enabled, p.Platform = true, "fly"
		p.Domain = os.Getenv("FLY_APP_NAME") + ".fly.dev"
		// Fly routes UDP only to this name and will not rewrite the port. An
		// app that binds 0.0.0.0 there receives nothing at all, with no error
		// anywhere to say why.
		p.UDPBindHost = "fly-global-services"
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
	// Extra routed ports. Declared, never inferred — see the field comments.
	p.TCPPorts = parsePorts(os.Getenv("FORGEPANEL_PAAS_TCP_PORTS"))
	p.UDPPorts = parsePorts(os.Getenv("FORGEPANEL_PAAS_UDP_PORTS"))
	if h := envStr("FORGEPANEL_PAAS_UDP_BIND", ""); h != "" {
		p.UDPBindHost = h
	}
	// Both directions, for a custom domain that puts a CDN in front of a
	// platform that has none — or takes one away.
	if v := os.Getenv("FORGEPANEL_PAAS_CDN"); v != "" {
		p.CDNFronted = envBool("FORGEPANEL_PAAS_CDN")
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
//
// CDNFronted here is only what DETECTION assumed. What was actually observed in
// front of the panel is learned from live traffic and applied by the API layer
// — Config is marshalled by value, so it cannot hold the atomic that needs.
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
	switch {
	case p.Domain != "":
		panel.Domain = p.Domain
	case panel.Domain != "":
		// The platform did not inject a hostname, but one is stored: either the
		// operator typed it into the panel's own address settings, or the panel
		// learned it from a request that arrived through the edge.
		//
		// This is not a corner case. A Railway service has no hostname until
		// somebody clicks "Generate Domain", and RAILWAY_PUBLIC_DOMAIN does not
		// reach a container that has not restarted since. So the ordinary
		// sequence — deploy, then generate a domain — leaves the panel serving
		// happily on a public URL while believing it has no address at all, and
		// every link it writes is unusable. Trusting what is stored closes that
		// window without the operator having to know any of it.
		p.Domain = panel.Domain
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

// SavePanelSettings persists panel settings to a data directory. It exists so
// the API layer can record a setting it discovered at runtime — the public
// hostname a platform failed to inject — without reaching into this package's
// file layout.
func SavePanelSettings(dataDir string, p *PanelSettings) error {
	return savePanel(filepath.Join(dataDir, "panel.json"), p)
}

// WithPaaSForTest builds a Config carrying a chosen PaaS description.
//
// The field is unexported so nothing outside this package can pretend the
// environment is something it is not at runtime — DetectPaaS reads the
// platform's own variables and is the only writer. Tests need to describe a
// Railway or Fly deployment without setting process-wide environment variables,
// which leak between parallel tests and are exactly the kind of shared state
// that makes one test's failure depend on another's ordering.
func WithPaaSForTest(p PaaS) *Config {
	return &Config{paas: p}
}
