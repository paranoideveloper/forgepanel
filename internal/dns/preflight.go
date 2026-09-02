package dns

import (
	"context"
	"fmt"
	"net/http"

	"github.com/forgepanel/forgepanel/internal/netegress"
	"sort"
	"strings"
	"time"
)

// ChallengeType is the ACME challenge a preflight is checking readiness for.
type ChallengeType string

// Supported challenge types.
const (
	ChallengeHTTP01 ChallengeType = "http-01"
	ChallengeDNS01  ChallengeType = "dns-01"
)

// CheckStatus is a preflight check outcome.
type CheckStatus string

// Check outcomes. Warn means issuance will probably work but something is not
// as the panel would have set it; fail means issuance cannot succeed.
const (
	StatusPass CheckStatus = "pass"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
)

// Check is one preflight finding. Remediation is the point of the whole
// exercise: never hand back a raw resolver or HTTP error.
type Check struct {
	Name        string      `json:"name"`
	Status      CheckStatus `json:"status"`
	Detail      string      `json:"detail"`
	Remediation string      `json:"remediation,omitempty"`
	Elapsed     string      `json:"elapsed,omitempty"`
}

// PreflightReport is the full readiness verdict for one domain.
type PreflightReport struct {
	Domain    string        `json:"domain"`
	Challenge ChallengeType `json:"challenge"`
	OK        bool          `json:"ok"`
	Checks    []Check       `json:"checks"`
	// ResolvedIPs is what public DNS currently answers for the domain.
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
	CheckedAt   string   `json:"checked_at"`
}

// Failures returns the checks that block issuance.
func (r PreflightReport) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			out = append(out, c)
		}
	}
	return out
}

// Err returns a KindPreflight error summarising the failures, or nil.
func (r PreflightReport) Err() error {
	fails := r.Failures()
	if len(fails) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(fails))
	rems := make([]string, 0, len(fails))
	for _, f := range fails {
		msgs = append(msgs, f.Name+": "+f.Detail)
		if f.Remediation != "" {
			rems = append(rems, f.Remediation)
		}
	}
	return &Error{Op: "acme-preflight", Kind: KindPreflight,
		Message:     fmt.Sprintf("%s is not ready for an ACME %s challenge — %s", r.Domain, r.Challenge, strings.Join(msgs, "; ")),
		Remediation: strings.Join(rems, " "),
	}
}

// LetsEncryptDirectory is the production ACME directory.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// crtShTemplate is the certificate-transparency query used for rate-limit
// headroom. %s is the registrable domain.
const crtShTemplate = "https://crt.sh/?q=%%25.%s&output=json&exclude=expired"

// LERateLimitCertsPerWeek is Let's Encrypt's certificates-per-registered-domain
// limit over a rolling seven days.
const LERateLimitCertsPerWeek = 50

// LERateLimitDuplicates is Let's Encrypt's duplicate-certificate limit (same
// exact set of names) over a rolling seven days.
const LERateLimitDuplicates = 5

// Preflight runs ACME readiness checks. Every network dependency is injectable
// so the whole thing is testable without touching the internet.
type Preflight struct {
	Resolver Resolver
	HTTP     *http.Client
	// ACMEDirectoryURL is probed for reachability; empty uses Let's Encrypt.
	ACMEDirectoryURL string
	// CertLogURL is a fmt template taking the registrable domain, used for
	// rate-limit headroom. Empty uses crt.sh. Set to "-" to skip the check.
	CertLogURL string
	// Now is injectable for deterministic timestamps.
	Now func() time.Time
	// HTTPChallengePort is the port an http-01 challenge would be served on.
	HTTPChallengePort int
}

// PreflightInput describes what to check.
type PreflightInput struct {
	Domain string
	// ExpectIP is the address the domain should resolve to. Empty skips the
	// match check but still requires the name to resolve.
	ExpectIP string
	// Zone, when supplied, lets the check compare public NS records against the
	// provider's assigned nameservers and report a delegation problem exactly.
	Zone *Zone
	// Resolution, when supplied, carries an already-computed delegation verdict
	// so the check does not repeat the work.
	Resolution *ZoneResolution
	Challenge  ChallengeType
	// Proxied is true when the record is behind a CDN, which changes what a
	// resolved-IP mismatch means.
	Proxied bool
}

func (p Preflight) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p Preflight) httpClient() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return netegress.Client(15 * time.Second)
}

func (p Preflight) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return NewResolver()
}

// Run executes every check and returns a report. It never returns an error for
// a failed check — the report carries the verdict; an error means the input was
// unusable.
func (p Preflight) Run(ctx context.Context, in PreflightInput) (*PreflightReport, error) {
	domain := NormalizeDomain(in.Domain)
	if err := ValidateFQDN(domain); err != nil {
		return nil, err
	}
	challenge := in.Challenge
	if challenge == "" {
		challenge = ChallengeDNS01
	}
	report := &PreflightReport{
		Domain: domain, Challenge: challenge,
		CheckedAt: p.now().UTC().Format(time.RFC3339),
	}

	report.Checks = append(report.Checks, p.checkZone(in, domain))
	resolveCheck, ips := p.checkPublicResolution(ctx, in, domain)
	report.ResolvedIPs = ips
	report.Checks = append(report.Checks, resolveCheck)
	report.Checks = append(report.Checks, p.checkDelegation(ctx, in, domain))

	switch challenge {
	case ChallengeHTTP01:
		report.Checks = append(report.Checks, p.checkHTTPChallengePath(ctx, domain))
	default:
		report.Checks = append(report.Checks, p.checkDNSChallengePath(ctx, domain))
	}

	report.Checks = append(report.Checks, p.checkACMEReachable(ctx))
	report.Checks = append(report.Checks, p.checkRateLimitHeadroom(ctx, domain))

	report.OK = len(report.Failures()) == 0
	return report, nil
}

func (p Preflight) checkZone(in PreflightInput, domain string) Check {
	c := Check{Name: "zone-active"}
	zone := in.Zone
	if zone == nil && in.Resolution != nil {
		zone = &in.Resolution.Zone
	}
	if zone == nil {
		c.Status = StatusWarn
		c.Detail = "no provider zone was supplied, so zone status could not be checked"
		c.Remediation = "run the check through the wizard (or pass --domain) so the owning zone is resolved first"
		return c
	}
	if !zone.Active() {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("zone %s is in status %q at %s", zone.Name, zone.Status, zone.Provider)
		c.Remediation = fmt.Sprintf("the zone is not serving yet. At the registrar, set the domain's nameservers to %s, then wait for the provider to mark the zone active (usually minutes, up to 24h). Nothing else in this list can pass until it does.",
			strings.Join(zone.NameServers, " and "))
		return c
	}
	c.Status = StatusPass
	c.Detail = fmt.Sprintf("zone %s is active at %s", zone.Name, zone.Provider)
	return c
}

func (p Preflight) checkPublicResolution(ctx context.Context, in PreflightInput, domain string) (Check, []string) {
	c := Check{Name: "public-resolution"}
	start := p.now()
	ips, err := p.resolver().LookupIP(ctx, domain)
	c.Elapsed = p.now().Sub(start).Round(time.Millisecond).String()
	if err != nil {
		if IsNXDOMAIN(err) {
			c.Status = StatusFail
			c.Detail = fmt.Sprintf("%s does not exist in public DNS (NXDOMAIN)", domain)
			c.Remediation = fmt.Sprintf("the A/AAAA record for %s has not been created, or it was created in a zone that is not authoritative for this name. Create the record and re-run; if it exists at the provider, the name is delegated elsewhere — see the ns-delegation check.", domain)
			return c, nil
		}
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("could not resolve %s: %v", domain, err)
		c.Remediation = "the recursive resolvers were unreachable rather than the name being missing. Check this host's outbound UDP/TCP 53 to 1.1.1.1 and 8.8.8.8, or configure resolvers the host can reach."
		return c, nil
	}
	if len(ips) == 0 {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s resolved to no addresses", domain)
		c.Remediation = "the name exists but has no A or AAAA record. Create one pointing at the server, then re-run."
		return c, nil
	}
	sort.Strings(ips)
	if in.ExpectIP == "" {
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("%s resolves to %s", domain, strings.Join(ips, ", "))
		return c, ips
	}
	for _, ip := range ips {
		if ip == in.ExpectIP {
			c.Status = StatusPass
			c.Detail = fmt.Sprintf("%s resolves to %s, which includes the expected %s", domain, strings.Join(ips, ", "), in.ExpectIP)
			return c, ips
		}
	}
	if in.Proxied {
		// Behind a CDN the record deliberately does not resolve to the origin;
		// that is the whole point, so this is informational.
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("%s resolves to CDN edge addresses %s rather than the origin %s, which is expected for a proxied record",
			domain, strings.Join(ips, ", "), in.ExpectIP)
		return c, ips
	}
	c.Status = StatusFail
	c.Detail = fmt.Sprintf("%s resolves to %s but the server is %s", domain, strings.Join(ips, ", "), in.ExpectIP)
	c.Remediation = fmt.Sprintf("an old record is still published, or a stale cache is answering. Update the A record to %s and wait for the previous TTL to expire. If the record is correct at the provider, another zone is answering for this name — see the ns-delegation check.", in.ExpectIP)
	return c, ips
}

func (p Preflight) checkDelegation(ctx context.Context, in PreflightInput, domain string) Check {
	c := Check{Name: "ns-delegation"}
	if in.Resolution != nil && in.Resolution.Delegated {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s is delegated to %s, away from zone %s",
			in.Resolution.DelegationPoint, strings.Join(in.Resolution.DelegatedTo, ", "), in.Resolution.Zone.Name)
		c.Remediation = in.Resolution.ACMENote
		return c
	}
	zone := in.Zone
	if zone == nil && in.Resolution != nil {
		zone = &in.Resolution.Zone
	}
	if zone == nil || len(zone.NameServers) == 0 {
		c.Status = StatusWarn
		c.Detail = "the provider did not report assigned nameservers, so delegation could not be verified"
		c.Remediation = "verify by hand that the registrar's nameservers match the provider's, then re-run"
		return c
	}
	actual, err := p.resolver().LookupNS(ctx, zone.Name)
	if err != nil || len(actual) == 0 {
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("could not read public NS records for %s", zone.Name)
		c.Remediation = "the delegation could not be confirmed. If issuance fails, check the registrar's nameserver settings first."
		return c
	}
	want, have := lowerSet(zone.NameServers), lowerSet(actual)
	missing := make([]string, 0)
	for ns := range want {
		if !have[ns] {
			missing = append(missing, ns)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("public DNS delegates %s to %s, but %s assigned %s",
			zone.Name, strings.Join(sortedSet(have), ", "), zone.Provider, strings.Join(sortedSet(want), ", "))
		c.Remediation = fmt.Sprintf("update the nameservers at the REGISTRAR (where the domain was bought) to %s. This is not a DNS record inside the provider's DNS table — changing records there will not fix it. Propagation takes minutes to 24 hours.",
			strings.Join(sortedSet(want), " and "))
		return c
	}
	c.Status = StatusPass
	c.Detail = fmt.Sprintf("%s is delegated to %s as assigned", zone.Name, strings.Join(sortedSet(want), ", "))
	return c
}
