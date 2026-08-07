// Package settings owns validation and atomic application of operator-editable
// panel settings. Both the authenticated web API and the root-only local CLI
// use this package so they cannot drift on domain, port, HTTPS, or rollback
// behaviour.
package settings

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/forgepanel/forgepanel/internal/config"
)

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Change holds only explicitly requested fields. A nil pointer means leave the
// stored value intact, making this safe for partial web and CLI updates.
type Change struct {
	Domain       *string
	Port         *int
	BindAddress  *string
	HTTPSEnabled *bool
	ACMEEmail    *string
	VerifyDNS    bool
}

// Result describes the persisted effective configuration. RestartRequired is
// true for changes that replace the listener rather than just metadata.
type Result struct {
	Old             config.PanelSettings
	New             config.PanelSettings
	RestartRequired bool
}

// Service applies changes to one loaded panel configuration.
type Service struct {
	Config *config.Config
	Lookup func(string) ([]net.IP, error)
	PortOK func(string, int) bool
	IPv4   func() string
	IPv6   func() string
}

func New(cfg *config.Config) *Service {
	return &Service{
		Config: cfg,
		Lookup: net.LookupIP,
		PortOK: PortFree,
		IPv4:   outboundIP4,
		IPv6:   outboundIP6,
	}
}

// NormalizeDomain strips a URL wrapper, port, path, and trailing dot before
// validating a DNS hostname.
func NormalizeDomain(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err == nil && u.Host != "" {
		s = u.Hostname()
	}
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	return s
}

func ValidDomain(domain string) bool { return domainRE.MatchString(domain) }

func ValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 || strings.ContainsAny(email, "\r\n") {
		return email == ""
	}
	at := strings.LastIndexByte(email, '@')
	return at > 0 && at < len(email)-1 && !strings.ContainsAny(email[:at], " \t") && ValidDomain(strings.ToLower(email[at+1:]))
}

// PortFree verifies that the exact TCP listener requested by the panel can be
// opened. An empty or wildcard address is tested as all IPv4 interfaces.
func PortFree(bindAddress string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	addr := strings.TrimSpace(bindAddress)
	if addr == "" || addr == "0.0.0.0" {
		addr = ""
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	return ln.Close() == nil
}

// ResolveDomain returns normalized A and AAAA records without making any claim
// about which address belongs to the current machine.
func ResolveDomain(domain string) (v4, v6 []string, err error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6, nil
}

func outboundIP(network, target string) string {
	c, err := net.Dial(network, target)
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

func outboundIP4() string { return outboundIP("udp4", "1.1.1.1:53") }
func outboundIP6() string { return outboundIP("udp6", "[2606:4700:4700::1111]:53") }

// Apply validates and atomically persists a settings transition. It records a
// rollback snapshot before writing, but deliberately does not restart the
// service: the caller knows whether it is the web process or a local system
// manager and can make that choice safely.
func (s *Service) Apply(change Change) (*Result, error) {
	if s == nil || s.Config == nil {
		return nil, fmt.Errorf("settings: configuration is required")
	}
	release, err := config.LockSettings(s.Config.DataDir)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.Config.ReloadPanel(); err != nil {
		return nil, err
	}

	p := s.Config.Panel()
	old := config.ClonePanel(p)
	restart := false

	if change.Domain != nil {
		domain := NormalizeDomain(*change.Domain)
		if domain != "" && !ValidDomain(domain) {
			return nil, fmt.Errorf("settings: invalid domain")
		}
		if domain != "" && change.VerifyDNS {
			if err := s.verifyDNS(domain); err != nil {
				return nil, err
			}
		}
		if domain != p.Domain {
			// The :80 ACME HTTP-01 helper is started at boot only when a domain is
			// configured, and the public URL and login banner are derived from it,
			// so a domain change needs a restart to take full effect.
			restart = true
		}
		p.Domain = domain
		if domain == "" {
			p.HTTPSEnabled = false
			p.ACME.Enabled = false
		}
	}
	if change.BindAddress != nil {
		bind := strings.TrimSpace(*change.BindAddress)
		if bind != "" && net.ParseIP(bind) == nil {
			return nil, fmt.Errorf("settings: bind address must be an IP address")
		}
		if bind != p.BindAddress {
			p.BindAddress = bind
			restart = true
		}
	}
	if change.Port != nil {
		if *change.Port < 1 || *change.Port > 65535 {
			return nil, fmt.Errorf("settings: panel port must be in 1..65535")
		}
		if *change.Port != p.Port {
			if !s.PortOK(p.BindAddress, *change.Port) {
				return nil, fmt.Errorf("settings: port %d is already in use", *change.Port)
			}
			p.Port = *change.Port
			restart = true
		}
	}
	if change.HTTPSEnabled != nil {
		if *change.HTTPSEnabled && p.Domain == "" {
			return nil, fmt.Errorf("settings: a domain is required to enable HTTPS")
		}
		if *change.HTTPSEnabled != p.HTTPSEnabled {
			restart = true
		}
		p.HTTPSEnabled = *change.HTTPSEnabled
		p.ACME.Enabled = *change.HTTPSEnabled
	}
	if change.ACMEEmail != nil {
		email := strings.TrimSpace(*change.ACMEEmail)
		if !ValidEmail(email) {
			return nil, fmt.Errorf("settings: invalid ACME email")
		}
		p.ACME.Email = email
	}

	if err := s.Config.WriteRollback(&old); err != nil {
		return nil, err
	}
	if err := s.Config.SavePanel(); err != nil {
		*s.Config.Panel() = old
		return nil, err
	}
	return &Result{Old: old, New: config.ClonePanel(s.Config.Panel()), RestartRequired: restart}, nil
}

func (s *Service) verifyDNS(domain string) error {
	ips, err := s.Lookup(domain)
	if err != nil {
		return fmt.Errorf("settings: domain does not resolve: %w", err)
	}
	my4, my6 := s.IPv4(), s.IPv6()
	for _, ip := range ips {
		if ip.String() == my4 || (my6 != "" && ip.String() == my6) {
			return nil
		}
	}
	return fmt.Errorf("settings: domain does not point to this server")
}
