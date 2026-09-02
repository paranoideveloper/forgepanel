package dns

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A bad credential must fail immediately, before anything is created.
func TestWizardStopsOnBadCredential(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	c := f.cf.client()
	c.Token = "wrong"
	f.config.Provider = c

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if report.OK {
		t.Fatal("expected the run to fail")
	}
	s := stepByName(t, report, "verify-credential")
	if s.Status != StepFailed {
		t.Fatalf("expected a credential failure, got %s", s.Status)
	}
	requireContains(t, s.Remediation, "api-tokens", "credential remediation")
	if len(report.Steps) != 1 {
		t.Fatalf("nothing should run after a credential failure, got %d steps", len(report.Steps))
	}
	if len(f.cf.Records["zone1"]) != 0 {
		t.Fatal("no records should be created after a credential failure")
	}
}

// A missing DNS-edit scope must surface as a step failure naming the scope,
// not as an opaque provider message.
func TestWizardReportsMissingScopeOnRecordCreation(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.cf.Deny["POST /zones/zone1/dns_records"] = cfMessage{Code: 9109, Message: "Unauthorized to access requested resource"}

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if report.OK {
		t.Fatal("expected the run to fail")
	}
	s := stepByName(t, report, "create-records")
	if s.Status != StepFailed {
		t.Fatalf("expected the record step to fail, got %s", s.Status)
	}
	requireContains(t, s.Detail, ScopeDNSEdit, "record step names the missing scope")
	requireContains(t, s.Remediation, "Zone Resources", "record step remediation")
}

// A delegated subdomain is a warning with the ACME consequence spelled out, not
// a hard stop: the records still get written.
func TestWizardWarnsOnDelegatedSubdomain(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.config.Domain = "team.example.com"
	f.res.NS["team.example.com"] = []string{"ns1.otherdns.net"}
	f.resolveAll("ws-fra1.team.example.com")

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "resolve-zone")
	if s.Status != StepWarn {
		t.Fatalf("expected a delegation warning, got %s: %s", s.Status, s.Detail)
	}
	requireContains(t, s.Remediation, "NXDOMAIN looking up TXT", "delegation ACME consequence")
	if s := stepByName(t, report, "create-records"); s.Status != StepOK {
		t.Fatalf("records should still be written, got %s: %s", s.Status, s.Detail)
	}
}

// Propagation that never completes is a warning with a realistic explanation,
// not a failure — DNS is eventually consistent.
func TestWizardPropagationTimeoutWarns(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.config.DNSPropagationWait = 100 * time.Millisecond
	f.config.PollInterval = 10 * time.Millisecond
	f.config.Now = time.Now // let the deadline actually elapse
	f.config.SkipTrafficProof = true

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "dns-propagation")
	if s.Status != StepWarn {
		t.Fatalf("expected a propagation warning, got %s: %s", s.Status, s.Detail)
	}
	requireContains(t, s.Remediation, "Re-run in a few minutes", "propagation remediation")
	requireContains(t, s.Remediation, "delegation warning", "propagation remediation points at the real cause")
	if !report.OK {
		t.Fatalf("a propagation warning must not fail the run: %+v", report.Failures())
	}
}

// Records appearing only after a few polls must be waited out.
func TestWizardWaitsForPropagation(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.resolveAll("ws-fra1.example.com")
	f.res.IPsAfter["ws-fra1.example.com"] = 3 // resolves on the third lookup
	f.config.DNSPropagationWait = 30 * time.Second
	f.config.PollInterval = time.Second

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "dns-propagation")
	if s.Status != StepOK {
		t.Fatalf("expected propagation to complete, got %s: %s", s.Status, s.Detail)
	}
	if f.res.Calls["ws-fra1.example.com"] < 3 {
		t.Fatalf("expected the wizard to poll until it resolved, got %d calls", f.res.Calls["ws-fra1.example.com"])
	}
}

// Nothing listening is a hard failure with actionable advice: this is the step
// that turns "the records are right" into "traffic actually works".
func TestWizardTrafficProofFailsWhenNothingListens(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.resolveAll("ws-fra1.example.com")
	f.config.Prober = TLSProber{Port: 1, Timeout: 250 * time.Millisecond}

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if report.OK {
		t.Fatal("expected the run to fail when no endpoint answers")
	}
	s := stepByName(t, report, "traffic-proof")
	if s.Status != StepFailed {
		t.Fatalf("expected a proof failure, got %s", s.Status)
	}
	requireContains(t, s.Remediation, "forgectl service start", "proof remediation")
	requireContains(t, s.Remediation, "firewall", "proof remediation")
}

// A verified clean edge address must become the dialled address while sni and
// host stay on the hostname — the whole point of the scan.
func TestWizardScanSetsTheDialledAddress(t *testing.T) {
	plans := []ProtocolPlan{
		{Proto: "ws", Port: 443, Proxied: true, TLS: true},
		{Proto: "reality", Port: 443, Proxied: false, TLS: true},
	}
	f := newWizardFixture(t, plans)
	f.resolveAll("ws-fra1.example.com", "reality-fra1.example.com")

	store := NewMemStore()
	f.config.CleanIPs = store
	f.config.Scan = &ScanConfig{
		Port: f.tls.Port, Probes: 1,
		Addresses:          []string{"104.16.0.1", "104.16.0.2"},
		DialContext:        f.tls.dialer(),
		InsecureSkipVerify: true,
	}

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if s := stepByName(t, report, "clean-ip-scan"); s.Status != StepOK {
		t.Fatalf("scan step: %s %s", s.Status, s.Detail)
	}
	if report.CleanIPs == nil || len(report.CleanIPs.IPs) != 2 {
		t.Fatalf("expected 2 clean addresses, got %+v", report.CleanIPs)
	}
	// The scan must have run against the proxied hostname, not the direct one.
	if report.CleanIPs.SNI != "ws-fra1.example.com" {
		t.Fatalf("the scan must target the proxied hostname, got %q", report.CleanIPs.SNI)
	}

	for _, ep := range report.Endpoints {
		switch ep.Proto {
		case "ws":
			if ep.Address == ep.Host {
				t.Fatal("a proxied endpoint should dial a clean edge address, not the hostname")
			}
			if !strings.HasPrefix(ep.Address, "104.16.0.") {
				t.Fatalf("unexpected dialled address %q", ep.Address)
			}
			if ep.Host != "ws-fra1.example.com" {
				t.Fatalf("the host (sni) must stay on the domain, got %q", ep.Host)
			}
		case "reality":
			if ep.Address != ep.Host {
				t.Fatalf("a direct endpoint dials its hostname, got %q", ep.Address)
			}
		}
	}

	// The working set must be persisted for later reuse.
	saved, err := store.LoadCleanIPs("ws-fra1.example.com")
	requireNoError(t, err)
	if saved == nil || len(saved.IPs) != 2 {
		t.Fatalf("expected the working set to be stored, got %+v", saved)
	}
}

// With no proxied hostname there is no edge to scan, and saying so is better
// than a confusing empty result.
func TestWizardScanSkippedWithoutProxiedHostname(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "reality", Port: 443, Proxied: false, TLS: true}})
	f.resolveAll("reality-fra1.example.com")
	f.config.Scan = &ScanConfig{Samples: 4}

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "clean-ip-scan")
	if s.Status != StepSkipped {
		t.Fatalf("expected the scan to be skipped, got %s: %s", s.Status, s.Detail)
	}
	requireContains(t, s.Remediation, "only applies to hostnames behind a CDN", "scan skip explanation")
}

// --skip-dns is the path for a provider with no backend: verify and prove
// hostnames that already exist.
func TestWizardSkipDNSStillProvesTraffic(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443, Hostname: "existing.example.com"}})
	f.resolveAll("existing.example.com")
	f.config.SkipDNS = true
	f.config.Provider = nil

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if !report.OK {
		t.Fatalf("expected success, failures: %+v", report.Failures())
	}
	for _, name := range []string{"verify-credential", "resolve-zone", "create-records", "zone-settings"} {
		if s := stepByName(t, report, name); s.Status != StepSkipped {
			t.Fatalf("step %q should be skipped, got %s", name, s.Status)
		}
	}
	if s := stepByName(t, report, "traffic-proof"); s.Status != StepOK {
		t.Fatalf("the proof must still run: %s %s", s.Status, s.Detail)
	}
	if report.Endpoints[0].Host != "existing.example.com" {
		t.Fatalf("an explicit hostname must be used verbatim, got %q", report.Endpoints[0].Host)
	}
}

func TestWizardRejectsBadOriginIP(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.config.OriginIP = "not-an-ip"
	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "create-records")
	if s.Status != StepFailed {
		t.Fatalf("expected a failure, got %s", s.Status)
	}
	requireContains(t, s.Remediation, "203.0.113.10", "bad IP remediation shows the shape")

	f.config.OriginIP = ""
	report, err = Run(context.Background(), f.config)
	requireNoError(t, err)
	s = stepByName(t, report, "create-records")
	requireContains(t, s.Remediation, "--ip", "missing IP remediation")
}

// An IPv6 origin must produce AAAA records, not a rejected A record.
func TestWizardUsesAAAAForIPv6Origin(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443}})
	f.config.OriginIP = "2606:4700::1111"
	f.config.SkipTrafficProof = true
	f.resolveAll("ws-fra1.example.com")

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if s := stepByName(t, report, "create-records"); s.Status != StepOK {
		t.Fatalf("records step: %s %s", s.Status, s.Detail)
	}
	for _, rec := range f.cf.Records["zone1"] {
		if rec.Type != "AAAA" {
			t.Fatalf("expected an AAAA record for an IPv6 origin, got %q", rec.Type)
		}
	}
}

// Two protocols must never collide onto one hostname; a template that would do
// that has to be rejected up front.
func TestWizardRejectsCollidingHostnames(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{
		{Proto: "ws", Port: 443}, {Proto: "grpc", Port: 443},
	})
	f.config.Template = "{node}" // no {proto}, so both render the same label

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	s := stepByName(t, report, "plan-hostnames")
	if s.Status != StepFailed {
		t.Fatalf("expected a hostname collision failure, got %s: %s", s.Status, s.Detail)
	}
	requireContains(t, s.Remediation, "add {rand} or {seq}", "collision remediation")
}

// A provider with no settings API must say what to do by hand, and must warn
// specifically about Flexible origin-pull, which silently breaks TLS inbounds.
func TestWizardExplainsMissingZoneSettingsSupport(t *testing.T) {
	m := newDesecMock(t)
	m.addDomain("example.com", 60)
	res := newFakeResolver()
	res.IPs["ws-fra1.example.com"] = []string{"203.0.113.10"}

	report, err := Run(context.Background(), WizardConfig{
		Provider: m.client(), Domain: "example.com", OriginIP: "203.0.113.10",
		Template: "{proto}-{node}", Node: "fra1",
		Protocols:          []ProtocolPlan{{Proto: "ws", Port: 443, TLS: true}},
		Resolver:           res,
		SkipPreflight:      true,
		SkipTrafficProof:   true,
		DNSPropagationWait: -1,
		Now:                fixedNow(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)),
	})
	requireNoError(t, err)
	if !report.OK {
		t.Fatalf("expected success, failures: %+v", report.Failures())
	}
	s := stepByName(t, report, "zone-settings")
	if s.Status != StepSkipped {
		t.Fatalf("expected the settings step to be skipped, got %s", s.Status)
	}
	requireContains(t, s.Remediation, "Flexible", "settings remediation warns about Flexible")
}

func TestWizardPreflightIntegration(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443, Proxied: false, TLS: true}})
	f.resolveAll("ws-fra1.example.com")
	f.config.SkipPreflight = false
	pf := newPreflight(t, f.res, f.now, nil)
	f.config.Preflight = &pf
	f.config.Challenge = ChallengeDNS01

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if s := stepByName(t, report, "acme-preflight"); s.Status != StepOK {
		t.Fatalf("preflight step: %s %s", s.Status, s.Detail)
	}
	if len(report.Preflight) != 1 || !report.Preflight[0].OK {
		t.Fatalf("expected one passing preflight report, got %+v", report.Preflight)
	}
}

func TestWizardPreflightFailureBlocksTheRun(t *testing.T) {
	f := newWizardFixture(t, []ProtocolPlan{{Proto: "ws", Port: 443, Proxied: false, TLS: true}})
	// Deliberately do NOT make the hostname resolve.
	f.config.SkipPreflight = false
	pf := newPreflight(t, f.res, f.now, nil)
	f.config.Preflight = &pf
	f.config.SkipTrafficProof = true

	report, err := Run(context.Background(), f.config)
	requireNoError(t, err)
	if report.OK {
		t.Fatal("expected the run to fail when a hostname is not ready for issuance")
	}
	s := stepByName(t, report, "acme-preflight")
	if s.Status != StepFailed {
		t.Fatalf("expected a preflight failure, got %s", s.Status)
	}
	requireContains(t, s.Remediation, "ws-fra1.example.com", "preflight remediation names the domain")
}

func TestDefaultProtocolPlansProxyDecisions(t *testing.T) {
	plans := DefaultProtocolPlans()
	byProto := map[string]ProtocolPlan{}
	for _, p := range plans {
		byProto[p.Proto] = p
	}
	// The CDN-friendly transports go behind the orange cloud.
	for _, proto := range []string{"ws", "xhttp", "grpc"} {
		if !byProto[proto].Proxied {
			t.Errorf("%s should be proxied: a CDN in front is the point of that transport", proto)
		}
	}
	// The handshake-sensitive ones must never be.
	for _, proto := range []string{"reality", "vision", "hy2"} {
		if byProto[proto].Proxied {
			t.Errorf("%s must not be proxied: the edge terminates TLS and breaks it", proto)
		}
	}
	if !byProto["hy2"].UDP {
		t.Error("hysteria2 is a UDP protocol and must be marked as such")
	}
}

func TestFormatWizardReport(t *testing.T) {
	report := &WizardReport{
		Domain: "example.com", OK: false, Duration: "1.2s",
		Steps: []Step{
			{Name: "verify-credential", Status: StepOK, Detail: "accepted"},
			{Name: "create-records", Status: StepFailed, Detail: "denied", Remediation: "add the scope"},
		},
		Endpoints: []Endpoint{
			{Proto: "ws", Host: "ws.example.com", Port: 443, Address: "104.16.0.1", Proxied: true, Proven: true},
			{Proto: "hy2", Host: "hy2.example.com", Port: 8443, Address: "hy2.example.com", ProofDetail: "UDP transport"},
		},
		CleanIPs: &CleanIPSet{SNI: "ws.example.com", IPs: []CleanIP{{IP: "104.16.0.1", AvgRTTMs: 12}}},
	}
	out := FormatWizardReport(report)
	for _, needle := range []string{
		"FAILED", "verify-credential", "fix: add the scope",
		"host=ws.example.com", "address=104.16.0.1", "proxied, proven",
		"UDP transport", "Clean addresses for ws.example.com",
	} {
		requireContains(t, out, needle, "formatted report")
	}
}
