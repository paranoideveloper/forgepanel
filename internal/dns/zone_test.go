package dns

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestZoneCandidatesStopsAtThePublicSuffix(t *testing.T) {
	cases := []struct {
		domain string
		want   []string
	}{
		{"example.com", []string{"example.com"}},
		{"ws.example.com", []string{"ws.example.com", "example.com"}},
		{"a.b.example.com", []string{"a.b.example.com", "b.example.com", "example.com"}},
		// A multi-label public suffix must not be proposed as a zone.
		{"node.example.co.uk", []string{"node.example.co.uk", "example.co.uk"}},
		{"example.co.uk", []string{"example.co.uk"}},
	}
	for _, tc := range cases {
		got := ZoneCandidates(tc.domain)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ZoneCandidates(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
	if got := ZoneCandidates("localhost"); got != nil {
		t.Errorf("expected no candidates for a single-label name, got %v", got)
	}
}

// The headline behaviour: provisioning team.example.com works through the
// example.com zone.
func TestResolveZoneWalksUpToTheOwningZone(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	res, err := ResolveZone(context.Background(), m.client(), nil, "team.example.com")
	requireNoError(t, err)

	if res.Zone.Name != "example.com" {
		t.Fatalf("expected the parent zone, got %q", res.Zone.Name)
	}
	if res.Subname != "team" {
		t.Fatalf("expected subname %q, got %q", "team", res.Subname)
	}
	if res.RecordName != "team.example.com" {
		t.Fatalf("expected the record name to stay fully qualified, got %q", res.RecordName)
	}
	if res.Apex {
		t.Fatal("a subdomain is not the apex")
	}
	// It must have tried the deeper name first.
	if len(res.Candidates) != 2 || res.Candidates[0] != "team.example.com" {
		t.Fatalf("unexpected candidate chain: %v", res.Candidates)
	}
}

func TestResolveZoneApex(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	res, err := ResolveZone(context.Background(), m.client(), nil, "example.com")
	requireNoError(t, err)
	if !res.Apex || res.Subname != "" {
		t.Fatalf("expected an apex resolution, got %+v", res)
	}
}

// A zone that exists deeper wins over its parent, because a delegated
// sub-zone's own credential is the correct place to write.
func TestResolveZonePrefersTheDeepestZone(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	m.addZone("zone2", "team.example.com", "active")
	res, err := ResolveZone(context.Background(), m.client(), nil, "ws.team.example.com")
	requireNoError(t, err)
	if res.Zone.Name != "team.example.com" {
		t.Fatalf("expected the deeper zone to win, got %q", res.Zone.Name)
	}
}

func TestResolveZoneReportsPendingZone(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "pending")
	res, err := ResolveZone(context.Background(), m.client(), nil, "ws.example.com")
	requireNoError(t, err)
	if res.Zone.Active() {
		t.Fatal("a pending zone is not active")
	}
	requireContains(t, res.ACMENote, "not active", "pending-zone note")
	requireContains(t, res.ACMENote, "registrar", "pending-zone note names where to fix it")
}

func TestResolveZoneNotFoundListsWhatItTried(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "other.test", "active")
	_, err := ResolveZone(context.Background(), m.client(), nil, "ws.example.com")
	e := requireKind(t, err, KindNotFound)
	requireContains(t, e.Remediation, "ws.example.com", "not-found remediation lists candidates")
	requireContains(t, e.Remediation, "example.com", "not-found remediation lists candidates")
}

// A permission failure while walking must surface immediately rather than
// degrading into a misleading "zone not found".
func TestResolveZoneSurfacesPermissionFailure(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active")
	m.Deny["GET /zones"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}
	_, err := ResolveZone(context.Background(), m.client(), nil, "ws.example.com")
	e := requireKind(t, err, KindPermission)
	if e.MissingScope != ScopeZoneRead {
		t.Fatalf("expected the zone-read scope to be named, got %q", e.MissingScope)
	}
}

// NS delegation between the zone apex and the target is the classic reason a
// perfectly correct record produces a failing certificate; the resolution must
// spell out the ACME consequence.
func TestResolveZoneDetectsDelegationAndExplainsACME(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active", "amy.ns.cloudflare.com", "bob.ns.cloudflare.com")
	res := newFakeResolver()
	res.NS["team.example.com"] = []string{"ns1.otherdns.net", "ns2.otherdns.net"}

	out, err := ResolveZone(context.Background(), m.client(), res, "ws.team.example.com")
	requireNoError(t, err)

	if !out.Delegated {
		t.Fatal("expected the delegation to be detected")
	}
	if out.DelegationPoint != "team.example.com" {
		t.Fatalf("expected the delegation point to be the delegated name, got %q", out.DelegationPoint)
	}
	if len(out.DelegatedTo) != 2 || out.DelegatedTo[0] != "ns1.otherdns.net" {
		t.Fatalf("unexpected delegation target: %v", out.DelegatedTo)
	}
	for _, needle := range []string{
		"will NOT be served",
		"NXDOMAIN looking up TXT for _acme-challenge.ws.team.example.com",
		"remove the NS delegation",
		"HTTP-01",
	} {
		requireContains(t, out.ACMENote, needle, "delegation ACME note")
	}
}

// A child answering with the zone's own nameservers is the zone serving itself,
// not a delegation — flagging it would be a false alarm on every zone.
func TestResolveZoneIgnoresSelfDelegation(t *testing.T) {
	m := newCFMock(t)
	m.addZone("zone1", "example.com", "active", "amy.ns.cloudflare.com", "bob.ns.cloudflare.com")
	res := newFakeResolver()
	res.NS["team.example.com"] = []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}

	out, err := ResolveZone(context.Background(), m.client(), res, "ws.team.example.com")
	requireNoError(t, err)
	if out.Delegated {
		t.Fatalf("the zone's own nameservers are not a delegation: %+v", out)
	}
}

func TestSubname(t *testing.T) {
	cases := []struct{ domain, zone, want string }{
		{"example.com", "example.com", ""},
		{"ws.example.com", "example.com", "ws"},
		{"a.b.example.com", "example.com", "a.b"},
		{"WS.Example.COM", "example.com", "ws"},
	}
	for _, tc := range cases {
		if got := Subname(tc.domain, tc.zone); got != tc.want {
			t.Errorf("Subname(%q,%q) = %q, want %q", tc.domain, tc.zone, got, tc.want)
		}
	}
}

func TestValidateFQDN(t *testing.T) {
	requireNoError(t, ValidateFQDN("ws-node1.example.com"))
	requireNoError(t, ValidateFQDN("_acme-challenge.example.com"))
	requireNoError(t, ValidateFQDN("_grpc._tcp.example.com"))

	cases := []struct{ name, needle string }{
		{"", "domain is empty"},
		{"localhost", "no dot"},
		{"-bad.example.com", "starts or ends with a hyphen"},
		{"bad-.example.com", "starts or ends with a hyphen"},
		{"exa mple.example.com", "not a letter, digit or hyphen"},
		{strings.Repeat("a", 64) + ".example.com", "over the 63"},
	}
	for _, tc := range cases {
		err := ValidateFQDN(tc.name)
		e := requireKind(t, err, KindValidation)
		requireContains(t, e.Message, tc.needle, "ValidateFQDN("+tc.name+")")
	}
}

func TestRecordValidate(t *testing.T) {
	cases := []struct {
		name   string
		rec    Record
		needle string
	}{
		{"A with IPv6", Record{Type: TypeA, Name: "a.example.com", Content: "2606:4700::1"}, "needs an IPv4"},
		{"AAAA with IPv4", Record{Type: TypeAAAA, Name: "a.example.com", Content: "203.0.113.1"}, "needs an IPv6"},
		{"CNAME to an IP", Record{Type: TypeCNAME, Name: "a.example.com", Content: "203.0.113.1"}, "needs a hostname target"},
		{"SRV without data", Record{Type: TypeSRV, Name: "_x._tcp.example.com"}, "missing its priority"},
		{"SRV bad port", Record{Type: TypeSRV, Name: "_x._tcp.example.com", SRV: &SRVData{Port: 0, Target: "e.example.com"}}, "out-of-range port"},
		{"empty TXT", Record{Type: TypeTXT, Name: "a.example.com"}, "empty content"},
		{"unknown type", Record{Type: "WEIRD", Name: "a.example.com"}, "unsupported record type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := requireKind(t, tc.rec.Validate(), KindValidation)
			requireContains(t, e.Message, tc.needle, tc.name)
		})
	}
	requireNoError(t, Record{Type: TypeA, Name: "a.example.com", Content: "203.0.113.1"}.Validate())
}

func TestZoneRefPrefersIDThenName(t *testing.T) {
	if got := (Zone{ID: "abc", Name: "example.com"}).Ref(); got != "abc" {
		t.Fatalf("expected the id, got %q", got)
	}
	if got := (Zone{Name: "example.com"}).Ref(); got != "example.com" {
		t.Fatalf("expected the name as the fallback handle, got %q", got)
	}
}
