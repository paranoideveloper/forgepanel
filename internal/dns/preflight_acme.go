package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// checkHTTPChallengePath proves the ACME server's request would land somewhere.
// Any HTTP response — including the 404 an un-primed challenge path returns —
// proves reachability; only a connection failure is disqualifying.
func (p Preflight) checkHTTPChallengePath(ctx context.Context, domain string) Check {
	c := Check{Name: "challenge-path"}
	port := p.HTTPChallengePort
	if port == 0 {
		port = 80
	}
	probe, err := RandomLabel(16)
	if err != nil {
		probe = "forgepanel-preflight"
	}
	host := domain
	if port != 80 {
		host = fmt.Sprintf("%s:%d", domain, port)
	}
	target := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", host, probe)
	start := p.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		c.Status = StatusFail
		c.Detail = "could not build the challenge probe request: " + err.Error()
		return c
	}
	resp, err := p.httpClient().Do(req)
	c.Elapsed = p.now().Sub(start).Round(time.Millisecond).String()
	if err != nil {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("could not reach %s: %v", target, err)
		c.Remediation = fmt.Sprintf("an http-01 challenge needs inbound TCP %d open to the whole internet and reaching this server. Open port %d in the host firewall and any cloud security group, stop whatever else is bound to it, and make sure the record is NOT behind a CDN proxy that blocks port %d. If port %d cannot be opened, use a dns-01 challenge instead (--challenge dns-01), which needs no inbound ports.",
			port, port, port, port)
		return c
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	c.Status = StatusPass
	c.Detail = fmt.Sprintf("%s answered HTTP %d, so the ACME server's request would reach this host", target, resp.StatusCode)
	if resp.StatusCode >= 500 {
		c.Status = StatusWarn
		c.Remediation = fmt.Sprintf("the path is reachable but returned HTTP %d. The challenge will still be served once ACME primes it, but check whatever is handling port %d.", resp.StatusCode, port)
	}
	return c
}

// checkDNSChallengePath confirms the _acme-challenge name is inside a zone that
// answers, which is what a dns-01 challenge needs. NXDOMAIN is the correct
// answer for a name that has no TXT yet, so it counts as reachable; SERVFAIL or
// a timeout does not.
func (p Preflight) checkDNSChallengePath(ctx context.Context, domain string) Check {
	c := Check{Name: "challenge-path"}
	name := "_acme-challenge." + domain
	start := p.now()
	_, err := p.resolver().LookupTXT(ctx, name)
	c.Elapsed = p.now().Sub(start).Round(time.Millisecond).String()
	if err == nil || IsNXDOMAIN(err) {
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("%s is inside an answering zone, so a dns-01 TXT record published there will be visible", name)
		return c
	}
	c.Status = StatusFail
	c.Detail = fmt.Sprintf("querying TXT %s failed with %v (not NXDOMAIN, which would be fine)", name, err)
	c.Remediation = fmt.Sprintf("the authoritative servers for %s are not answering cleanly, so a published challenge TXT would not be seen. Confirm the zone is active at the provider and that the registrar's nameserver delegation is complete, then re-run. A SERVFAIL here usually means a broken DNSSEC chain: if DNSSEC was enabled at the registrar for a zone that no longer signs, remove the DS record.", domain)
	return c
}

// checkACMEReachable proves the CA's directory endpoint answers from this host.
func (p Preflight) checkACMEReachable(ctx context.Context) Check {
	c := Check{Name: "acme-directory"}
	dir := p.ACMEDirectoryURL
	if dir == "" {
		dir = LetsEncryptDirectory
	}
	start := p.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dir, nil)
	if err != nil {
		c.Status = StatusFail
		c.Detail = "could not build the directory request: " + err.Error()
		return c
	}
	resp, err := p.httpClient().Do(req)
	c.Elapsed = p.now().Sub(start).Round(time.Millisecond).String()
	if err != nil {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("could not reach the ACME directory at %s: %v", dir, err)
		c.Remediation = "issuance happens from this host, so it needs outbound HTTPS to the CA. Check egress firewall rules, DNS resolution, and any HTTP proxy. If this server is in a network that blocks the CA, issue the certificate elsewhere and import it with `forgectl cert import`."
		return c
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("the ACME directory at %s answered HTTP %d", dir, resp.StatusCode)
		c.Remediation = "the CA is not serving its directory to this host. Check https://letsencrypt.status.io, and confirm no proxy is intercepting the request."
		return c
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil || payload["newOrder"] == nil {
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%s answered HTTP 200 but the body is not an ACME directory", dir)
		c.Remediation = "something is intercepting HTTPS to the CA (a captive portal or TLS-inspecting proxy). Issuance will likely fail; bypass the interception for the CA's hostname."
		return c
	}
	c.Status = StatusPass
	c.Detail = fmt.Sprintf("the ACME directory at %s is reachable and well-formed", dir)
	return c
}

// crtShEntry is the subset of crt.sh's JSON the headroom check reads.
type crtShEntry struct {
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	IssuerName string `json:"issuer_name"`
}

// checkRateLimitHeadroom counts recent certificates for the registrable domain
// against Let's Encrypt's 50-per-week limit. A count it cannot obtain is a
// warning, never a failure — an unreachable CT log must not block provisioning.
func (p Preflight) checkRateLimitHeadroom(ctx context.Context, domain string) Check {
	c := Check{Name: "rate-limit-headroom"}
	if strings.TrimSpace(p.CertLogURL) == "-" {
		c.Status = StatusPass
		c.Detail = "rate-limit headroom check skipped by configuration"
		return c
	}
	registrable := registrableDomain(domain)
	tmpl := p.CertLogURL
	if tmpl == "" {
		tmpl = crtShTemplate
	}
	target := fmt.Sprintf(tmpl, registrable)
	start := p.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		c.Status = StatusWarn
		c.Detail = "could not build the certificate-transparency query: " + err.Error()
		return c
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient().Do(req)
	c.Elapsed = p.now().Sub(start).Round(time.Millisecond).String()
	if err != nil {
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("could not query the certificate transparency log for %s: %v", registrable, err)
		c.Remediation = fmt.Sprintf("headroom is unknown, which is not itself a problem. If issuance fails with \"too many certificates already issued\", you have hit the limit of %d certificates per registered domain per week — wait for the oldest to age out of the seven-day window, or add the name to an existing certificate instead of requesting a new one.", LERateLimitCertsPerWeek)
		return c
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		c.Status = StatusWarn
		c.Detail = "the certificate transparency log rate-limited the headroom query"
		c.Remediation = "retry in a minute; this does not affect issuance itself."
		return c
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("the certificate transparency log answered HTTP %d", resp.StatusCode)
		return c
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		c.Status = StatusWarn
		c.Detail = "could not decode the certificate transparency response"
		return c
	}
	cutoff := p.now().UTC().Add(-7 * 24 * time.Hour)
	recent := 0
	exact := 0
	for _, e := range entries {
		t, err := parseCTTime(e.NotBefore)
		if err != nil || t.Before(cutoff) {
			continue
		}
		recent++
		for _, name := range strings.Split(e.NameValue, "\n") {
			if NormalizeDomain(name) == domain {
				exact++
				break
			}
		}
	}
	remaining := LERateLimitCertsPerWeek - recent
	switch {
	case remaining <= 0:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%d certificates were issued for %s in the last 7 days, at or over the limit of %d", recent, registrable, LERateLimitCertsPerWeek)
		c.Remediation = fmt.Sprintf("Let's Encrypt will refuse a new certificate for %s until the oldest of those ages out of the rolling seven-day window. Options now: reuse an existing certificate, put the extra names on one certificate as SANs, or switch the CA (--acme-directory) to one without this limit.", registrable)
	case exact >= LERateLimitDuplicates:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%d certificates covering exactly %s were issued in the last 7 days, at the duplicate-certificate limit of %d", exact, domain, LERateLimitDuplicates)
		c.Remediation = fmt.Sprintf("Let's Encrypt caps identical name sets at %d per week. Reuse the certificate already on disk instead of re-issuing, or add another name to the request so the set is no longer a duplicate.", LERateLimitDuplicates)
	case remaining <= 5:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%d of %d weekly certificates are already used for %s — %d left", recent, LERateLimitCertsPerWeek, registrable, remaining)
		c.Remediation = "headroom is nearly gone. Avoid re-running provisioning repeatedly against this domain; each successful run consumes one certificate."
	default:
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("%d of %d weekly certificates used for %s — %d left", recent, LERateLimitCertsPerWeek, registrable, remaining)
	}
	return c
}

func parseCTTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", value)
}

// registrableDomain returns the eTLD+1 a rate limit is counted against.
func registrableDomain(domain string) string {
	candidates := ZoneCandidates(domain)
	if len(candidates) == 0 {
		return NormalizeDomain(domain)
	}
	return candidates[len(candidates)-1]
}

// FormatReport renders a report as aligned operator-facing text.
func FormatReport(r *PreflightReport) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	verdict := "READY"
	if !r.OK {
		verdict = "NOT READY"
	}
	fmt.Fprintf(&b, "ACME preflight for %s (%s): %s\n", r.Domain, r.Challenge, verdict)
	width := 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	for _, c := range r.Checks {
		mark := map[CheckStatus]string{StatusPass: "ok  ", StatusWarn: "warn", StatusFail: "FAIL"}[c.Status]
		fmt.Fprintf(&b, "  [%s] %-*s  %s\n", mark, width, c.Name, c.Detail)
		if c.Remediation != "" && c.Status != StatusPass {
			fmt.Fprintf(&b, "         %*s  fix: %s\n", width, "", c.Remediation)
		}
	}
	return b.String()
}
