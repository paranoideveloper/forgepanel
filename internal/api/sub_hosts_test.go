package api

import (
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/protocol/model"
	"github.com/forgepanel/forgepanel/internal/store"
)

func wsNode() *model.Node {
	return &model.Node{
		Protocol: model.ProtoVLESS,
		Remark:   "de-1",
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{
			Network: model.NetWS, Path: "/origin", Host: "origin.example.com",
		},
		Security: model.Security{Type: model.SecTLS, ServerName: "origin.example.com"},
	}
}

func TestAnInboundWithNoHostsIsUnchanged(t *testing.T) {
	// This is opt-in per inbound. Every existing inbound must behave exactly as
	// it did — a new fan-out axis silently applied to a whole panel would change
	// what thousands of already-distributed subscriptions resolve to.
	n := wsNode()
	got := applyHosts(n, nil)
	if len(got) != 1 || got[0] != n {
		t.Fatalf("got %d node(s), want the original one untouched", len(got))
	}
	got = applyHosts(n, []store.InboundHost{{Label: "off", Enabled: false}})
	if len(got) != 1 || got[0] != n {
		t.Fatal("an inbound whose only endpoint is disabled did not fall back to itself")
	}
}

func TestOneEndpointPerEnabledHost(t *testing.T) {
	got := applyHosts(wsNode(), []store.InboundHost{
		{Label: "direct", Enabled: true},
		{Label: "parked", Enabled: false},
		{Label: "cdn", Enabled: true},
	})
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (the disabled one is parked, not published)", len(got))
	}
	if !strings.Contains(got[0].Remark, "direct") || !strings.Contains(got[1].Remark, "cdn") {
		t.Fatalf("remarks = %q, %q", got[0].Remark, got[1].Remark)
	}
}

func TestAnEndpointOverridesOnlyWhatItSets(t *testing.T) {
	// The property that makes a host cheap: a CDN endpoint that differs only in
	// port and Host header says exactly that and keeps following the inbound for
	// everything else — including the credentials, which is the whole reason
	// this beats creating the inbound twice.
	n := wsNode()
	got := applyHosts(n, []store.InboundHost{{
		Label: "cdn", Enabled: true,
		Port: 8443, HostHeader: "cdn.example.com",
	}})
	if len(got) != 1 {
		t.Fatal(len(got))
	}
	h := got[0]
	if h.Port != 8443 {
		t.Errorf("port = %d, want the override", h.Port)
	}
	if h.Transport.Host != "cdn.example.com" {
		t.Errorf("host = %q, want the override", h.Transport.Host)
	}
	// Everything not set must be inherited.
	if h.Address != n.Address {
		t.Errorf("address = %q, want the inbound's %q", h.Address, n.Address)
	}
	if h.Transport.Path != "/origin" {
		t.Errorf("path = %q, want the inbound's", h.Transport.Path)
	}
	if h.Security.ServerName != "origin.example.com" {
		t.Errorf("SNI = %q, want the inbound's", h.Security.ServerName)
	}
	if h.UUID != n.UUID {
		t.Error("the endpoint did not inherit the inbound's credentials, which is the point of a host")
	}
	// And the original must not be mutated: it is reused for every other host.
	if n.Port != 443 || n.Transport.Host != "origin.example.com" {
		t.Fatal("applying an endpoint mutated the inbound it was derived from")
	}
}

func TestDomainFrontingNeedsSNIAndHostToDiffer(t *testing.T) {
	// This is the entire point of separating them: the same string in the
	// ordinary case, deliberately different in the interesting one. A model that
	// carried only one field could not express it at all.
	got := applyHosts(wsNode(), []store.InboundHost{{
		Label: "fronted", Enabled: true,
		SNI: "allowed-front.example.net", HostHeader: "real-origin.example.com",
		AllowInsecure: true,
	}})
	h := got[0]
	if h.Security.ServerName != "allowed-front.example.net" {
		t.Errorf("SNI = %q", h.Security.ServerName)
	}
	if h.Transport.Host != "real-origin.example.com" {
		t.Errorf("Host = %q", h.Transport.Host)
	}
	if h.Security.ServerName == h.Transport.Host {
		t.Fatal("SNI and Host are the same; nothing is being fronted")
	}
	if !h.Security.AllowInsecure {
		t.Error("allow_insecure was not applied — the edge presents a certificate for the front, " +
			"not for the Host, so verification fails without it")
	}
}

func TestAnEndpointCanTurnTLSOff(t *testing.T) {
	// A plaintext-WS inbound behind a Host-aware CDN is a real deployment: the
	// inbound terminates no TLS and the client must still speak TLS to the edge
	// — or the reverse. Without an explicit "none" there is no way to say it,
	// because an empty string already means "inherit".
	got := applyHosts(wsNode(), []store.InboundHost{{Label: "plain", Enabled: true, Security: "none"}})
	if got[0].Security.Type != model.SecNone {
		t.Fatalf("security = %q, want none", got[0].Security.Type)
	}
	// And empty must still inherit rather than clearing it.
	got = applyHosts(wsNode(), []store.InboundHost{{Label: "inherit", Enabled: true}})
	if got[0].Security.Type != model.SecTLS {
		t.Fatalf("an endpoint with no security override cleared the inbound's TLS (got %q)", got[0].Security.Type)
	}
}

func TestAllowInsecureCanOnlyBeRelaxedPerEndpoint(t *testing.T) {
	// AllowInsecure is a bool, so "inherit" is indistinguishable from false.
	// Only ever ORing it in is the safe direction: an endpoint can relax
	// verification for itself and can never silently tighten it for an inbound
	// that had it on for a reason.
	n := wsNode()
	n.Security.AllowInsecure = true
	got := applyHosts(n, []store.InboundHost{{Label: "x", Enabled: true, AllowInsecure: false}})
	if !got[0].Security.AllowInsecure {
		t.Fatal("an endpoint silently tightened verification the inbound had deliberately relaxed")
	}
}

func TestAGRPCPathBecomesTheServiceName(t *testing.T) {
	// gRPC carries its route as the service name, not a path. Writing it to Path
	// would render an option the core ignores, so the endpoint would look
	// configured and route nowhere.
	n := wsNode()
	n.Transport = model.Transport{Network: model.NetGRPC, ServiceName: "origin"}
	got := applyHosts(n, []store.InboundHost{{Label: "cdn", Enabled: true, Path: "edge"}})
	if got[0].Transport.ServiceName != "edge" {
		t.Fatalf("service name = %q, want the override", got[0].Transport.ServiceName)
	}
	if got[0].Transport.Path != "" {
		t.Fatalf("path = %q; a gRPC transport has no path and the core ignores it", got[0].Transport.Path)
	}
}

func TestALPNIsSplitOnCommas(t *testing.T) {
	// A CDN that only speaks h2 needs this and the inbound does not.
	got := applyHosts(wsNode(), []store.InboundHost{{Label: "cdn", Enabled: true, ALPN: "h2, http/1.1"}})
	want := []string{"h2", "http/1.1"}
	if len(got[0].Security.ALPN) != len(want) {
		t.Fatalf("ALPN = %v, want %v", got[0].Security.ALPN, want)
	}
	for i := range want {
		if got[0].Security.ALPN[i] != want[i] {
			t.Fatalf("ALPN = %v, want %v", got[0].Security.ALPN, want)
		}
	}
}

func TestEndpointsAreNamedApart(t *testing.T) {
	// A client shows the remark and nothing else. Several entries with the same
	// name are unusable: the person cannot tell which route they just picked.
	got := applyHosts(wsNode(), []store.InboundHost{
		{Label: "direct", Enabled: true},
		{Label: "cdn", Enabled: true},
		{Enabled: true}, // no label at all
	})
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n.Remark] {
			t.Fatalf("two endpoints are both called %q", n.Remark)
		}
		seen[n.Remark] = true
	}
	// An explicit remark wins outright.
	got = applyHosts(wsNode(), []store.InboundHost{{Label: "cdn", Remark: "Germany via CDN", Enabled: true}})
	if got[0].Remark != "Germany via CDN" {
		t.Fatalf("remark = %q, want the operator's own", got[0].Remark)
	}
}

func TestAFingerprintTheCoreDoesNotKnowIsRejected(t *testing.T) {
	// Not a harmless typo: uTLS rejects an unknown profile and the inbound
	// refuses to start, so a bad endpoint would take a working listener down.
	if msg := (hostRequest{Fingerprint: "netscape"}).validate(); msg == "" {
		t.Fatal("an unknown uTLS fingerprint was accepted")
	}
	if msg := (hostRequest{Fingerprint: "Chrome"}).validate(); msg != "" {
		t.Fatalf("a valid fingerprint was rejected: %s", msg)
	}
	if msg := (hostRequest{}).validate(); msg != "" {
		t.Fatalf("an empty request was rejected: %s", msg)
	}
}

func TestASecurityModeTheModelCannotExpressIsRejected(t *testing.T) {
	if msg := (hostRequest{Security: "quic"}).validate(); msg == "" {
		t.Fatal(`security "quic" was accepted`)
	}
	for _, ok := range []string{"", "none", "tls", "reality", "TLS"} {
		if msg := (hostRequest{Security: ok}).validate(); msg != "" {
			t.Errorf("security %q was rejected: %s", ok, msg)
		}
	}
}

func TestAPortOutsideTheRangeIsRejected(t *testing.T) {
	bad := 70000
	if msg := (hostRequest{Port: &bad}).validate(); msg == "" {
		t.Fatal("port 70000 was accepted")
	}
	zero := 0
	if msg := (hostRequest{Port: &zero}).validate(); msg != "" {
		t.Fatalf("port 0 (inherit) was rejected: %s", msg)
	}
}

func TestASubscriptionPublishesEveryEndpointOfAnInbound(t *testing.T) {
	// End to end through the real subscription path, not just the expansion
	// helper: the query, the ordering, and the fan-out that runs after it.
	s := storeServer(t)

	in, err := s.db.CreateInbound(&model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.10", Port: 443,
		Remark: "de-1", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS, Path: "/origin", Host: "origin.example.com"},
		Security:  model.Security{Type: model.SecTLS, ServerName: "origin.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "alice", SubToken: "tok-hosts",
		UUID: "11111111-2222-3333-4444-555555555555", Status: store.StatusActive}
	if err := s.db.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.db.SetUserInbounds(u.ID, []uint{in.ID}, nil); err != nil {
		t.Fatal(err)
	}

	// Deliberately out of insertion order, to prove priority is what sorts them.
	for _, h := range []store.InboundHost{
		{InboundID: in.ID, Label: "cdn", Enabled: true, Priority: 2,
			Port: 8443, HostHeader: "cdn.example.com", SNI: "cdn.example.com"},
		{InboundID: in.ID, Label: "direct", Enabled: true, Priority: 1},
		{InboundID: in.ID, Label: "parked", Enabled: false, Priority: 0},
	} {
		host := h
		if err := s.db.CreateHost(&host); err != nil {
			t.Fatal(err)
		}
	}

	nodes := s.subscriptionNodes("tok-hosts", "")
	if len(nodes) != 2 {
		var got []string
		for _, n := range nodes {
			got = append(got, n.Remark)
		}
		t.Fatalf("the subscription has %d entries (%v), want 2 — the parked endpoint must not be published", len(nodes), got)
	}
	if !strings.Contains(nodes[0].Remark, "direct") {
		t.Errorf("first entry is %q; priority 1 should come first", nodes[0].Remark)
	}
	if nodes[1].Port != 8443 || nodes[1].Transport.Host != "cdn.example.com" {
		t.Errorf("the CDN entry did not carry its overrides: port=%d host=%q",
			nodes[1].Port, nodes[1].Transport.Host)
	}
	// Both must carry the USER's identity, not the inbound template's.
	for _, n := range nodes {
		if n.UUID != u.UUID {
			t.Fatalf("entry %q carries %q, want the user's UUID", n.Remark, n.UUID)
		}
	}
}

func TestDeletingAnInboundRemovesItsEndpoints(t *testing.T) {
	// An orphaned host row publishes nothing and would be inherited outright by
	// whatever inbound next takes that id — SQLite hands out the lowest free
	// rowid, which is the same mechanism that made the assignment leak worth
	// fixing in the first place.
	s := storeServer(t)
	in, err := s.db.CreateInbound(&model.Node{
		Protocol: model.ProtoVLESS, Address: "203.0.113.11", Port: 443,
		Remark: "temp", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: model.Transport{Network: model.NetWS},
		Security:  model.Security{Type: model.SecTLS},
	})
	if err != nil {
		t.Fatal(err)
	}
	host := store.InboundHost{InboundID: in.ID, Label: "cdn", Enabled: true}
	if err := s.db.CreateHost(&host); err != nil {
		t.Fatal(err)
	}
	if err := s.db.DeleteInbound(in.ID); err != nil {
		t.Fatal(err)
	}
	left, err := s.db.HostsForInbound(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("%d endpoint(s) outlived their inbound", len(left))
	}
}

func TestAnEndpointCreatedDisabledStaysDisabled(t *testing.T) {
	// GORM omits zero values on INSERT when a column declares a default, so an
	// endpoint created with Enabled:false was stored ENABLED — the same trap
	// that once put a live listener on a port nobody agreed to open.
	s := storeServer(t)
	h := store.InboundHost{InboundID: 1, Label: "parked", Enabled: false}
	if err := s.db.CreateHost(&h); err != nil {
		t.Fatal(err)
	}
	got, err := s.db.HostByID(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatal("an endpoint created disabled was stored as enabled, and is being published")
	}
}
