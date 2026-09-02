// Package deploy answers one question: given where this panel is actually
// running, which of its controls can do anything?
//
// The panel grew up assuming a VPS it owns — its own ports, its own TLS, its own
// systemd, its own DNS. Deployed on Railway or Render, roughly a third of the UI
// is controls for things the platform owns and the panel cannot touch. Showing
// them is worse than hiding them: an operator sets a port that will never be
// routed, requests a certificate for a domain the platform already terminates,
// or tunes a sysctl inside a container that has no permission to change it, and
// each of those fails somewhere far from the switch they flipped.
//
// So the surface is computed rather than assumed, and the frontend REMOVES what
// is not applicable instead of disabling it. A disabled control still says "this
// exists and you are not allowed" — which is the wrong message when the truth is
// "the platform does this for you, and better".
package deploy

import (
	"sort"

	"github.com/forgepanel/forgepanel/internal/config"
)

// Capability is one thing the environment either permits or does not.
type Capability string

const (
	// OwnTLS: the panel terminates TLS itself, so certificates, ACME and the
	// domain-to-certificate flow are its business. False wherever the platform
	// terminates at its edge — every certificate control is then decoration.
	OwnTLS Capability = "own_tls"

	// ArbitraryPorts: the panel can listen on ports it chooses. False on
	// platforms that route exactly one HTTP port to the container, where a port
	// field offers a choice that is silently ignored.
	ArbitraryPorts Capability = "arbitrary_ports"

	// RawTCP / UDP: the platform passes bytes through without terminating TLS,
	// and routes datagrams. REALITY needs the first; Hysteria2 and TUIC need the
	// second. Fly can do both, once the ports are declared.
	RawTCP Capability = "raw_tcp"
	UDP    Capability = "udp"

	// OwnDomain: DNS records and custom domains are the panel's to manage.
	OwnDomain Capability = "own_domain"

	// SystemServices: systemd, sysctl, firewall — anything that assumes a host
	// rather than a container.
	SystemServices Capability = "system_services"

	// PersistentDisk: state survives a restart. Without it a downloaded core is
	// re-downloaded on every boot, which is why the PaaS image bakes them.
	PersistentDisk Capability = "persistent_disk"

	// RemoteNodes: this panel can enrol and supervise other servers.
	RemoteNodes Capability = "remote_nodes"
)

// Surface describes the deployment to anything that needs to adapt to it.
type Surface struct {
	// Kind is "vps" or "paas".
	Kind string `json:"kind"`
	// Platform names the host: railway, render, fly, koyeb, generic, or "" on a
	// plain server.
	Platform string `json:"platform"`
	// Domain the platform assigned, when it assigned one.
	Domain string `json:"domain,omitempty"`
	// CDNFronted reports a CDN between clients and this panel that the operator
	// did not put there.
	CDNFronted bool `json:"cdn_fronted"`

	// Can holds the verdict per capability.
	Can map[Capability]bool `json:"can"`
	// Why explains each FALSE, in the operator's terms, so a missing section is
	// explicable rather than mysterious.
	Why map[Capability]string `json:"why,omitempty"`
}

// Allows reports whether the environment permits a capability.
func (s Surface) Allows(c Capability) bool { return s.Can[c] }

// Hidden lists the capabilities that are unavailable, sorted, for tests and for
// anything that wants to explain the shape of the UI.
func (s Surface) Hidden() []Capability {
	var out []Capability
	for c, ok := range s.Can {
		if !ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Describe computes the surface for a deployment.
func Describe(pa config.PaaS) Surface {
	s := Surface{
		Kind:       "vps",
		Platform:   pa.Platform,
		Domain:     pa.Domain,
		CDNFronted: pa.CDNFronted,
		Can:        map[Capability]bool{},
		Why:        map[Capability]string{},
	}

	if !pa.Enabled {
		// A server the operator owns: everything is theirs to configure.
		for _, c := range All() {
			s.Can[c] = true
		}
		return s
	}

	s.Kind = "paas"
	platform := pa.Platform
	if platform == "" {
		platform = "this platform"
	}

	// What every managed platform takes over.
	s.deny(OwnTLS, platform+" terminates TLS at its own edge and issues the certificate, "+
		"so the panel has nothing to request, renew or install")
	s.deny(ArbitraryPorts, platform+" routes one public port to this container; a port chosen here "+
		"would never be reached")
	s.deny(SystemServices, "this is a container, not a host: there is no systemd to manage, "+
		"and sysctl changes are not permitted inside it")
	s.deny(OwnDomain, platform+" owns the hostname. Attach a custom domain in its dashboard and the "+
		"panel will use it")

	// Raw TCP and UDP are declared per platform, never inferred: listing a port
	// the platform does not actually route makes the panel offer an inbound that
	// cannot be reached, which is worse than refusing it.
	if len(pa.TCPPorts) > 0 {
		s.Can[RawTCP] = true
	} else {
		s.deny(RawTCP, "no raw TCP port is routed here, so protocols that do their own TLS "+
			"(REALITY) cannot be reached. On Fly, allocate a dedicated IPv4 and set "+
			"FORGEPANEL_PAAS_TCP_PORTS")
	}
	if len(pa.UDPPorts) > 0 {
		s.Can[UDP] = true
	} else {
		s.deny(UDP, "no UDP port is routed here, so Hysteria2, TUIC and QUIC cannot be reached. "+
			"On Fly, allocate a dedicated IPv4 and set FORGEPANEL_PAAS_UDP_PORTS")
	}

	// A platform deploy usually has no volume. Fly is the exception when one is
	// mounted, but the panel cannot tell from inside, so this stays pessimistic:
	// claiming persistence that is not there loses data, claiming none that is
	// there costs a re-download.
	s.deny(PersistentDisk, "a platform container starts from the image each time, so anything "+
		"downloaded at runtime is downloaded again on every restart")

	// Enrolling other servers works fine from a container.
	s.Can[RemoteNodes] = true
	return s
}

func (s Surface) deny(c Capability, why string) {
	s.Can[c] = false
	s.Why[c] = why
}

// All is every capability, so a caller can iterate without knowing the list.
func All() []Capability {
	return []Capability{
		OwnTLS, ArbitraryPorts, RawTCP, UDP, OwnDomain,
		SystemServices, PersistentDisk, RemoteNodes,
	}
}

// Sections maps a UI section to the capability that justifies it. A section
// whose capability is unavailable is removed, not disabled.
//
// The ids are the frontend's tab ids; a test compares them against the sidebar
// so a rename cannot silently orphan an entry here.
func Sections() map[string]Capability {
	return map[string]Capability{
		"certs":   OwnTLS,
		"domains": OwnDomain,
		"system":  SystemServices,
		"nodes":   RemoteNodes,
	}
}

// SettingRequires maps a settings key to the capability it needs. Keys absent
// from this map apply everywhere.
func SettingRequires() map[string]Capability {
	return map[string]Capability{
		// Tuning the kernel's congestion control needs a kernel to tune.
		"net_tune_bbr": SystemServices,
		// The platform assigns the hostname; a public address typed here would
		// disagree with the one clients actually reach.
		"public_address": OwnDomain,
		// Pinning a core version means downloading it, which a container without
		// a volume redoes on every boot — the PaaS image bakes the cores instead.
		"core_version_":      PersistentDisk,
		"core_version_prev_": PersistentDisk,
	}
}
