package dns

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ZoneResolution is the answer to "which zone do I write node.example.com into,
// and will ACME work there?".
type ZoneResolution struct {
	// Domain is the fully-qualified name the caller asked about.
	Domain string `json:"domain"`
	// Zone is the owning zone found at the provider.
	Zone Zone `json:"zone"`
	// RecordName is the name to create inside Zone — the same as Domain, kept
	// explicit because providers differ on relative vs absolute naming.
	RecordName string `json:"record_name"`
	// Subname is Domain relative to the zone ("node", or "" for the apex).
	Subname string `json:"subname"`
	// Apex is true when Domain is the zone itself.
	Apex bool `json:"apex"`
	// Delegated is true when the domain (or a parent between it and the zone)
	// has its own NS records pointing away from the zone's nameservers, so
	// records written into Zone will never be served for Domain.
	Delegated bool `json:"delegated"`
	// DelegatedTo lists the nameservers the delegation points at.
	DelegatedTo []string `json:"delegated_to,omitempty"`
	// DelegationPoint is the exact name carrying the NS records.
	DelegationPoint string `json:"delegation_point,omitempty"`
	// ACMENote explains the consequence of the delegation for certificate
	// issuance. Empty when there is nothing to warn about.
	ACMENote string `json:"acme_note,omitempty"`
	// Candidates is every parent name that was probed, longest first.
	Candidates []string `json:"candidates,omitempty"`
}

// ZoneCandidates returns the parent-name chain for a domain, longest first and
// stopping at the public suffix. For "a.b.example.co.uk" that is
// ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"] — never "co.uk",
// which nobody can own.
func ZoneCandidates(domain string) []string {
	d := NormalizeDomain(domain)
	if d == "" || !strings.Contains(d, ".") {
		return nil
	}
	suffix, _ := publicsuffix.PublicSuffix(d)
	suffix = NormalizeDomain(suffix)
	labels := strings.Split(d, ".")
	var out []string
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		// Never propose the public suffix itself (or anything shorter) as a zone.
		if suffix != "" && len(candidate) <= len(suffix) {
			break
		}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		// Domains under an unknown suffix (a private TLD in a lab) still get the
		// registrable-looking candidate so the resolution is usable.
		if len(labels) >= 2 {
			out = append(out, strings.Join(labels[len(labels)-2:], "."))
		}
	}
	return out
}

// ResolveZone finds the provider zone that owns domain, walking up the parent
// chain. Provisioning team.example.com works through the example.com zone; this
// is the function that makes that true.
//
// When a resolver is supplied it additionally detects NS delegation between the
// zone apex and the domain and fills in the ACME consequence, because a
// delegated subdomain is the single most common reason a perfectly correct
// record produces a failing certificate.
func ResolveZone(ctx context.Context, p Provider, res Resolver, domain string) (*ZoneResolution, error) {
	d := NormalizeDomain(domain)
	if err := ValidateFQDN(d); err != nil {
		return nil, err
	}
	candidates := ZoneCandidates(d)
	if len(candidates) == 0 {
		return nil, &Error{Provider: p.Name(), Op: "resolve-zone", Kind: KindValidation,
			Message:     fmt.Sprintf("%q has no registrable parent domain", d),
			Remediation: "pass a domain you own, such as example.com or node.example.com"}
	}

	var inactive *Zone
	var lastErr error
	var found *Zone
	for _, candidate := range candidates {
		zone, err := p.FindZone(ctx, candidate)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			// An auth or permission failure is fatal: walking further up would
			// just repeat it with a less useful message.
			if KindOf(err) == KindAuth || KindOf(err) == KindPermission {
				return nil, err
			}
			lastErr = err
			continue
		}
		if zone == nil {
			continue
		}
		if zone.Active() {
			found = zone
			break
		}
		if inactive == nil {
			cp := *zone
			inactive = &cp
		}
	}
	if found == nil {
		found = inactive
	}
	if found == nil {
		msg := fmt.Sprintf("no %s zone owns %q", p.Name(), d)
		rem := fmt.Sprintf("the panel looked for %s. Add the registrable domain as a zone at your provider, "+
			"or widen the credential so it can see that zone.", strings.Join(candidates, ", then "))
		if lastErr != nil {
			return nil, &Error{Provider: p.Name(), Op: "resolve-zone", Kind: KindNotFound,
				Message: msg, Remediation: rem, Cause: lastErr}
		}
		return nil, &Error{Provider: p.Name(), Op: "resolve-zone", Kind: KindNotFound, Message: msg, Remediation: rem}
	}

	out := &ZoneResolution{
		Domain: d, Zone: *found, RecordName: d, Candidates: candidates,
		Apex: d == found.Name,
	}
	out.Subname = Subname(d, found.Name)
	if !found.Active() {
		out.ACMENote = fmt.Sprintf("zone %s is in status %q, not active. Records can be written but public DNS will not serve them, "+
			"so ACME will fail. Point the registrar's nameservers at %s and wait for the zone to go active.",
			found.Name, found.Status, strings.Join(found.NameServers, ", "))
	}

	if res != nil {
		detectDelegation(ctx, res, out)
	}
	return out, nil
}

// Subname returns domain relative to zone: "node" for node.example.com in
// example.com, "" for the apex.
func Subname(domain, zone string) string {
	d, z := NormalizeDomain(domain), NormalizeDomain(zone)
	if d == z {
		return ""
	}
	return strings.TrimSuffix(d, "."+z)
}

// detectDelegation walks from the zone apex down to the domain looking for a
// name that carries its own NS records. Anything found there overrides the
// zone's own answers for everything at or below it.
func detectDelegation(ctx context.Context, res Resolver, out *ZoneResolution) {
	if out.Apex {
		return
	}
	zoneNS := lowerSet(out.Zone.NameServers)
	labels := strings.Split(Subname(out.Domain, out.Zone.Name), ".")
	// Probe from the shallowest child of the apex down to the domain itself.
	for i := len(labels) - 1; i >= 0; i-- {
		name := strings.Join(labels[i:], ".") + "." + out.Zone.Name
		ns, err := res.LookupNS(ctx, name)
		if err != nil || len(ns) == 0 {
			continue
		}
		actual := lowerSet(ns)
		if len(zoneNS) > 0 && sameNameservers(actual, zoneNS) {
			// The child answers with the zone's own nameservers, which is just
			// the zone serving itself — not a delegation.
			continue
		}
		out.Delegated = true
		out.DelegationPoint = name
		out.DelegatedTo = sortedSet(actual)
		out.ACMENote = fmt.Sprintf(
			"%s is delegated away from zone %s to %s. Records the panel writes into %s will NOT be served for %s, "+
				"so a DNS-01 challenge published in %s can never be seen and issuance will fail with \"NXDOMAIN looking up TXT for _acme-challenge.%s\". "+
				"Either remove the NS delegation at %s, or add %s as its own zone at the provider and use a credential scoped to it, "+
				"or switch that host to an HTTP-01 challenge on port 80.",
			name, out.Zone.Name, strings.Join(sortedSet(actual), ", "), out.Zone.Name, out.Domain,
			out.Zone.Name, out.Domain, name, name)
		return
	}
}

func lowerSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		v = NormalizeDomain(v)
		if v != "" {
			out[v] = true
		}
	}
	return out
}

func sameNameservers(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// Insertion sort keeps this dependency-free and the sets are tiny.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
