package dns

import (
	"context"
	"testing"
	"time"
)

func stepByName(t *testing.T, r *WizardReport, name string) Step {
	t.Helper()
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no step named %q in %+v", name, r.Steps)
	return Step{}
}

// wizardFixture wires a full run against a mock Cloudflare, a fake resolver and
// a real TLS listener, so the end-to-end path is exercised without touching the
// network.
type wizardFixture struct {
	cf     *cfMock
	res    *fakeResolver
	tls    *tlsTestServer
	now    time.Time
	config WizardConfig
}

func newWizardFixture(t *testing.T, protocols []ProtocolPlan) *wizardFixture {
	t.Helper()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	cf := newCFMock(t)
	cf.addZone("zone1", "example.com", "active", "amy.ns.cloudflare.com", "bob.ns.cloudflare.com")
	res := newFakeResolver()
	res.NS["example.com"] = []string{"amy.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	srv := newTLSTestServer(t, "example.com")

	f := &wizardFixture{cf: cf, res: res, tls: srv, now: now}
	f.config = WizardConfig{
		Provider: cf.client(), Domain: "example.com", OriginIP: "203.0.113.10",
		Template: "{proto}-{node}", Node: "fra1", Protocols: protocols,
		Resolver: res, Now: fixedNow(now), Sleep: func(time.Duration) {},
		SkipPreflight:      true,
		DNSPropagationWait: -1,
		Prober: TLSProber{
			Port: srv.Port, Timeout: 3 * time.Second,
			DialContext: srv.dialer(), InsecureSkipVerify: true,
		},
	}
	return f
}

// resolveAll makes every hostname the wizard will create resolve to the origin,
// which is what lets propagation and preflight pass.
func (f *wizardFixture) resolveAll(hosts ...string) {
	for _, h := range hosts {
		f.res.IPs[h] = []string{"203.0.113.10"}
		f.res.TXT["_acme-challenge."+h] = nil
	}
}

func TestWizardEndToEnd(t *testing.T) {
	plans := []ProtocolPlan{
		{Proto: "ws", Port: 443, Proxied: true, TLS: true},
		{Proto: "reality", Port: 443, Proxied: false, TLS: true},
	}
	f := newWizardFixture(t, plans)
	f.resolveAll("ws-fra1.example.com", "reality-fra1.example.com")
	f.config.DNSPropagationWait = 5 * time.Second

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if !report.OK {
		t.Fatalf("expected the run to succeed, failures: %+v", report.Failures())
	}

	// Credential, zone, hostnames, records, settings, propagation, proof.
	if s := stepByName(t, report, "verify-credential"); s.Status != StepOK {
		t.Fatalf("credential step: %s %s", s.Status, s.Detail)
	}
	if s := stepByName(t, report, "resolve-zone"); s.Status != StepOK {
		t.Fatalf("zone step: %s %s", s.Status, s.Detail)
	}
	if s := stepByName(t, report, "create-records"); s.Status != StepOK {
		t.Fatalf("records step: %s %s", s.Status, s.Detail)
	}
	if s := stepByName(t, report, "zone-settings"); s.Status != StepOK {
		t.Fatalf("settings step: %s %s", s.Status, s.Detail)
	}
	if s := stepByName(t, report, "dns-propagation"); s.Status != StepOK {
		t.Fatalf("propagation step: %s %s", s.Status, s.Detail)
	}
	if s := stepByName(t, report, "traffic-proof"); s.Status != StepOK {
		t.Fatalf("proof step: %s %s", s.Status, s.Detail)
	}

	// Two records, with the proxy flag honoured per protocol.
	if len(f.cf.Records["zone1"]) != 2 {
		t.Fatalf("expected 2 records at the provider, got %d", len(f.cf.Records["zone1"]))
	}
	byProto := map[string]Endpoint{}
	for _, ep := range report.Endpoints {
		byProto[ep.Proto] = ep
	}
	if !byProto["ws"].Proxied {
		t.Fatal("the ws endpoint should be behind the CDN")
	}
	if byProto["reality"].Proxied {
		t.Fatal("a REALITY endpoint must never be proxied — the orange cloud breaks the handshake")
	}
	for proto, ep := range byProto {
		if !ep.Proven {
			t.Fatalf("%s endpoint was not proven: %s", proto, ep.ProofDetail)
		}
		if ep.RecordID == "" {
			t.Fatalf("%s endpoint has no record id", proto)
		}
		if ep.Action != "created" {
			t.Fatalf("%s endpoint should have been created, got %q", proto, ep.Action)
		}
	}

	// Edge settings must land on the values a TLS inbound behind a CDN needs.
	if f.cf.Settings["zone1"]["ssl"] != "strict" {
		t.Fatalf("expected Full (strict) origin pull, got %q", f.cf.Settings["zone1"]["ssl"])
	}
	if f.cf.Settings["zone1"]["websockets"] != "on" {
		t.Fatal("WebSockets must be on or a ws inbound behind the edge cannot upgrade")
	}
	if f.cf.Settings["zone1"]["grpc"] != "on" {
		t.Fatal("gRPC must be on or a grpc inbound behind the edge cannot carry traffic")
	}
}

// Re-running must be a no-op, not a pile of conflicts.
func TestWizardIsIdempotent(t *testing.T) {
	plans := []ProtocolPlan{{Proto: "ws", Port: 443, Proxied: true, TLS: true}}
	f := newWizardFixture(t, plans)
	f.resolveAll("ws-fra1.example.com")

	first, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if !first.OK {
		t.Fatalf("first run failed: %+v", first.Failures())
	}
	second, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if !second.OK {
		t.Fatalf("second run failed: %+v", second.Failures())
	}
	if second.Endpoints[0].Action != "unchanged" {
		t.Fatalf("re-running should change nothing, got %q", second.Endpoints[0].Action)
	}
	if len(f.cf.Records["zone1"]) != 1 {
		t.Fatalf("expected exactly one record after two runs, got %d", len(f.cf.Records["zone1"]))
	}
}

// A UDP protocol cannot be proven with a TCP handshake, and the report must say
// so rather than reporting a false failure.
func TestWizardSkipsUDPInTheTrafficProof(t *testing.T) {
	plans := []ProtocolPlan{
		{Proto: "ws", Port: 443, Proxied: true, TLS: true},
		{Proto: "hy2", Port: 8443, Proxied: false, TLS: true, UDP: true},
	}
	f := newWizardFixture(t, plans)
	f.resolveAll("ws-fra1.example.com", "hy2-fra1.example.com")

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if !report.OK {
		t.Fatalf("expected success, failures: %+v", report.Failures())
	}
	for _, ep := range report.Endpoints {
		if ep.Proto == "hy2" {
			if ep.Proven {
				t.Fatal("a UDP endpoint must not claim to be proven by a TCP probe")
			}
			requireContains(t, ep.ProofDetail, "UDP transport", "udp proof detail")
			requireContains(t, ep.ProofDetail, "verify with a real client", "udp proof detail")
		}
	}
	s := stepByName(t, report, "traffic-proof")
	requireContains(t, s.Detail, "1 UDP endpoint(s) not testable", "traffic proof counts UDP separately")
}
