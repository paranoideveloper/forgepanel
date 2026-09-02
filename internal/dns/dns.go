// Package dns is the ForgePanel domain & DNS automation layer (spec §5). It
// drives a DNS provider's API directly so an operator goes from a bare domain
// to a verified, TLS-enabled, traffic-proven inbound set without ever opening
// the provider's dashboard.
//
// The layer is provider-abstracted (see Provider) with Cloudflare implemented
// deepest — records, orange-cloud proxying, zone settings and precise
// permission-scope diagnostics — plus full ArvanCloud and deSEC backends. Every
// remote call is plain net/http against the documented REST endpoints; there is
// no vendor SDK dependency.
//
// The pieces layer up:
//
//	Provider        raw zone/record CRUD, per-provider
//	ResolveZone     parent-zone resolution + NS delegation detection
//	NameTemplate    {proto}-{node}-{rand} subdomain generation, bulk creation
//	Preflight       ACME readiness: public resolution, challenge reachability,
//	                rate-limit headroom — each with concrete remediation
//	Pool            health-checked domain rotation pool, self-healing
//	Scan            two-phase (TCP + TLS 1.3) clean-IP scanner
//	Wizard          the end-to-end orchestration used by `forgectl provision`
package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RecordType is a DNS RR type this layer can manage.
type RecordType string

// Record types supported across every provider in this package.
const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeSRV   RecordType = "SRV"
	TypeMX    RecordType = "MX"
	TypeCAA   RecordType = "CAA"
)

// DefaultTTL is the TTL used when a caller does not pick one. 120s keeps a
// rotation pool responsive without tripping provider minimums that matter
// (Cloudflare accepts 60+, Arvan 120+; deSEC clamps up to its zone minimum).
const DefaultTTL = 120

// SupportedTypes lists every RR type the package can create.
func SupportedTypes() []RecordType {
	return []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeTXT, TypeNS, TypeSRV, TypeMX, TypeCAA}
}

// NormalizeType upper-cases and validates an RR type.
func NormalizeType(t string) (RecordType, error) {
	up := RecordType(strings.ToUpper(strings.TrimSpace(t)))
	for _, known := range SupportedTypes() {
		if up == known {
			return up, nil
		}
	}
	return "", &Error{Kind: KindValidation, Op: "normalize-type",
		Message:     fmt.Sprintf("unsupported record type %q", t),
		Remediation: "use one of " + joinTypes(SupportedTypes()),
	}
}

func joinTypes(types []RecordType) string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, string(t))
	}
	return strings.Join(out, ", ")
}

// SRVData carries the parts of an SRV record that do not fit in Content.
type SRVData struct {
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

// Record is a provider-neutral DNS record. Name is always the fully-qualified
// name (no trailing dot); providers that store a relative sub-name convert on
// the way in and out.
type Record struct {
	ID      string     `json:"id,omitempty"`
	Type    RecordType `json:"type"`
	Name    string     `json:"name"`
	Content string     `json:"content,omitempty"`
	TTL     int        `json:"ttl,omitempty"`
	// Proxied is the CDN orange-cloud flag. Providers without a CDN ignore it
	// on read and reject a true value on write with a KindUnsupported error.
	Proxied  bool     `json:"proxied"`
	Priority int      `json:"priority,omitempty"`
	SRV      *SRVData `json:"srv,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

// Validate checks a record is well-formed before it is sent to a provider, so
// an obvious mistake surfaces as a local validation error rather than an opaque
// provider rejection.
func (r Record) Validate() error {
	if _, err := NormalizeType(string(r.Type)); err != nil {
		return err
	}
	if strings.TrimSpace(r.Name) == "" {
		return &Error{Kind: KindValidation, Op: "validate-record", Message: "record name is empty",
			Remediation: "set the fully-qualified record name, e.g. ws-node1.example.com"}
	}
	if err := ValidateFQDN(r.Name); err != nil {
		return err
	}
	switch r.Type {
	case TypeA:
		ip := net.ParseIP(strings.TrimSpace(r.Content))
		if ip == nil || ip.To4() == nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("A record %s needs an IPv4 address, got %q", r.Name, r.Content),
				Remediation: "use an IPv4 literal such as 203.0.113.10, or switch the record type to AAAA"}
		}
	case TypeAAAA:
		ip := net.ParseIP(strings.TrimSpace(r.Content))
		if ip == nil || ip.To4() != nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("AAAA record %s needs an IPv6 address, got %q", r.Name, r.Content),
				Remediation: "use an IPv6 literal such as 2606:4700::1111, or switch the record type to A"}
		}
	case TypeCNAME, TypeNS:
		if err := validateHostnameTarget(r.Content); err != nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("%s record %s needs a hostname target, got %q", r.Type, r.Name, r.Content),
				Remediation: "point it at a hostname such as edge.example.com"}
		}
	case TypeSRV:
		if r.SRV == nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("SRV record %s is missing its priority/weight/port/target data", r.Name),
				Remediation: "populate the srv object with priority, weight, port and target"}
		}
		if r.SRV.Port <= 0 || r.SRV.Port > 65535 {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("SRV record %s has out-of-range port %d", r.Name, r.SRV.Port),
				Remediation: "use a port between 1 and 65535"}
		}
		if err := validateHostnameTarget(r.SRV.Target); err != nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("SRV record %s has an invalid target %q", r.Name, r.SRV.Target),
				Remediation: "point the SRV target at a hostname such as edge.example.com"}
		}
	case TypeTXT:
		if strings.TrimSpace(r.Content) == "" {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("TXT record %s has empty content", r.Name),
				Remediation: "set the TXT value"}
		}
	case TypeMX:
		if err := validateHostnameTarget(r.Content); err != nil {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("MX record %s needs a mail host target, got %q", r.Name, r.Content),
				Remediation: "point it at a hostname such as mail.example.com"}
		}
	case TypeCAA:
		if strings.TrimSpace(r.Content) == "" {
			return &Error{Kind: KindValidation, Op: "validate-record",
				Message:     fmt.Sprintf("CAA record %s has empty content", r.Name),
				Remediation: `set the CAA value, e.g. 0 issue "letsencrypt.org"`}
		}
	}
	if r.TTL < 0 {
		return &Error{Kind: KindValidation, Op: "validate-record",
			Message: fmt.Sprintf("record %s has negative TTL %d", r.Name, r.TTL), Remediation: "use 0 for automatic, or a positive number of seconds"}
	}
	return nil
}

// Zone is a provider-neutral hosted zone.
type Zone struct {
	// ID is the provider's zone handle. Cloudflare uses an opaque id, Arvan and
	// deSEC address zones by name; Ref() returns whichever the provider needs.
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Provider    string   `json:"provider"`
	NameServers []string `json:"name_servers,omitempty"`
	Paused      bool     `json:"paused,omitempty"`
	MinimumTTL  int      `json:"minimum_ttl,omitempty"`
}

// Ref is the handle to pass back into Provider record calls.
func (z Zone) Ref() string {
	if strings.TrimSpace(z.ID) != "" {
		return z.ID
	}
	return z.Name
}

// Active reports whether the provider considers the zone live. Providers that
// do not expose a status (deSEC) report an empty status, which counts as active
// because the zone would not be listed otherwise.
func (z Zone) Active() bool {
	s := strings.ToLower(strings.TrimSpace(z.Status))
	return s == "" || s == "active"
}

// Identity is what a credential turns out to be once verified.
type Identity struct {
	Provider  string   `json:"provider"`
	TokenID   string   `json:"token_id,omitempty"`
	AccountID string   `json:"account_id,omitempty"`
	Status    string   `json:"status,omitempty"`
	ExpiresOn string   `json:"expires_on,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

// NormalizeDomain lower-cases a domain and strips whitespace and the root dot.
func NormalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ValidateFQDN checks a name is a syntactically usable DNS name. It is
// deliberately strict about the things that silently break TLS and ACME later:
// label length, total length, and the leading/trailing hyphen rule.
func ValidateFQDN(name string) error {
	n := NormalizeDomain(name)
	if n == "" {
		return &Error{Kind: KindValidation, Op: "validate-fqdn", Message: "domain is empty",
			Remediation: "pass a domain such as example.com"}
	}
	if len(n) > 253 {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("domain %q is %d characters, over the 253 limit", n, len(n)),
			Remediation: "shorten the label prefix or use a shorter parent domain"}
	}
	if !strings.Contains(n, ".") {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("domain %q has no dot, so it is not a fully-qualified name", n),
			Remediation: "use a fully-qualified name such as node.example.com"}
	}
	for _, label := range strings.Split(n, ".") {
		if err := validateLabel(label, n); err != nil {
			return err
		}
	}
	return nil
}

// validateHostnameTarget is ValidateFQDN plus a rejection of IP literals. A
// CNAME, NS, MX or SRV target must be a name: "1.2.3.4" satisfies the label
// rules but is meaningless as a target, and providers reject it with an error
// far less specific than this one.
func validateHostnameTarget(target string) error {
	t := NormalizeDomain(target)
	if err := ValidateFQDN(t); err != nil {
		return err
	}
	if net.ParseIP(t) != nil {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("%q is an IP address, not a hostname", t),
			Remediation: "a CNAME/NS/MX/SRV target must be a name; use an A or AAAA record to point a name at an address"}
	}
	return nil
}

func validateLabel(label, full string) error {
	if label == "" {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("domain %q has an empty label", full),
			Remediation: "remove the doubled or trailing dot"}
	}
	if len(label) > 63 {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("label %q in %q is %d characters, over the 63 limit", label, full, len(label)),
			Remediation: "shorten the label; a naming template with a long {node} value is the usual cause"}
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return &Error{Kind: KindValidation, Op: "validate-fqdn",
			Message:     fmt.Sprintf("label %q in %q starts or ends with a hyphen", label, full),
			Remediation: "hyphens are only allowed between alphanumerics"}
	}
	// A leading underscore is legal for service names such as _acme-challenge
	// and _grpc._tcp, so it is permitted in the first position only.
	body := label
	if strings.HasPrefix(body, "_") {
		body = body[1:]
		if body == "" {
			return &Error{Kind: KindValidation, Op: "validate-fqdn",
				Message: fmt.Sprintf("label %q in %q is only an underscore", label, full), Remediation: "name the service, e.g. _acme-challenge"}
		}
	}
	for _, r := range body {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return &Error{Kind: KindValidation, Op: "validate-fqdn",
				Message:     fmt.Sprintf("label %q in %q contains %q, which is not a letter, digit or hyphen", label, full, string(r)),
				Remediation: "DNS labels accept a-z, 0-9 and '-'; punycode an internationalised name before passing it in"}
		}
	}
	return nil
}

// SplitHost splits a "host" or "host:port" into its parts, defaulting the port.
func SplitHost(hostport string, defaultPort int) (string, int) {
	hostport = strings.TrimSpace(hostport)
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return NormalizeDomain(hostport), defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		port = defaultPort
	}
	return NormalizeDomain(host), port
}
