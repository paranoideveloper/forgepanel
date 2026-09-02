package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/forgepanel/forgepanel/internal/dns"
)

func TestProvisionParseProtocols(t *testing.T) {
	plans, err := provisionParseProtocols("ws:443:proxied,reality:443:direct,hy2:8443:direct:udp,grpc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plans) != 4 {
		t.Fatalf("expected 4 plans, got %d", len(plans))
	}

	byProto := map[string]dns.ProtocolPlan{}
	for _, p := range plans {
		byProto[p.Proto] = p
	}
	if !byProto["ws"].Proxied || byProto["ws"].Port != 443 {
		t.Fatalf("unexpected ws plan: %+v", byProto["ws"])
	}
	if byProto["reality"].Proxied {
		t.Fatalf("reality must stay direct: %+v", byProto["reality"])
	}
	if byProto["hy2"].Port != 8443 || !byProto["hy2"].UDP {
		t.Fatalf("unexpected hy2 plan: %+v", byProto["hy2"])
	}
	// A bare name defaults to a proxy-less TLS inbound on 443.
	if byProto["grpc"].Port != 443 || byProto["grpc"].Proxied || !byProto["grpc"].TLS {
		t.Fatalf("unexpected grpc default: %+v", byProto["grpc"])
	}

	// An empty spec means "use the shipped default set".
	plans, err = provisionParseProtocols("  ")
	if err != nil || plans != nil {
		t.Fatalf("expected an empty spec to defer to the defaults, got %+v %v", plans, err)
	}
}

func TestProvisionParseProtocolsRejectsGarbage(t *testing.T) {
	cases := map[string]string{
		"ws:notaport": "unrecognised part",
		"ws:99999":    "unrecognised part",
		":443":        "has no name",
		",,":          "parsed to nothing",
	}
	for spec, needle := range cases {
		_, err := provisionParseProtocols(spec)
		if err == nil {
			t.Fatalf("expected %q to be rejected", spec)
		}
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("%q: expected the error to contain %q, got %v", spec, needle, err)
		}
	}
}

func TestProvisionCredentials(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	t.Setenv("CF_ACCOUNT_ID", "")

	creds, err := provisionCredentials("cloudflare", "tok", "acct", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Get("api_token") != "tok" || creds.Get("account_id") != "acct" {
		t.Fatalf("unexpected credentials: %+v", creds)
	}

	// The environment is the fallback when the flag is empty.
	t.Setenv("CF_API_TOKEN", "env-token")
	creds, err = provisionCredentials("cloudflare", "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Get("api_token") != "env-token" {
		t.Fatalf("expected the environment fallback, got %+v", creds)
	}

	creds, err = provisionCredentials("desec", "", "", "", "desec-tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Get("token") != "desec-tok" {
		t.Fatalf("unexpected deSEC credentials: %+v", creds)
	}

	creds, err = provisionCredentials("arvancloud", "", "", "arvan-key", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Get("api_key") != "arvan-key" {
		t.Fatalf("unexpected Arvan credentials: %+v", creds)
	}
}

// A missing Cloudflare token must name every scope the wizard needs, so the
// operator creates a working token on the first attempt.
func TestProvisionCredentialsMissingTokenListsTheScopes(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	_, err := provisionCredentials("cloudflare", "", "", "", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, needle := range []string{"--cf-token", "$CF_API_TOKEN", dns.ScopeZoneRead, dns.ScopeDNSEdit, dns.ScopeSettingsEdit, dns.ScopeSSLEdit} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("expected the error to mention %q, got: %v", needle, err)
		}
	}
}

// A provider with no backend must be refused up front with the manual path,
// not after the operator has typed a full command line.
func TestProvisionCredentialsRefusesUnimplementedProvider(t *testing.T) {
	_, err := provisionCredentials("godaddy", "", "", "", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, needle := range []string{"not available", "--skip-dns", "developer.godaddy.com", "cloudflare"} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("expected the error to mention %q, got: %v", needle, err)
		}
	}
}

func TestProvisionCredentialsUnknownProvider(t *testing.T) {
	_, err := provisionCredentials("route53", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "unknown DNS provider") {
		t.Fatalf("expected an unknown-provider error, got %v", err)
	}
}

func TestProvisionNodeNameDefaultsToTheShortHostname(t *testing.T) {
	if got := provisionNodeName("  fra1  "); got != "fra1" {
		t.Fatalf("an explicit node name wins, got %q", got)
	}
	got := provisionNodeName("")
	if got == "" {
		t.Fatal("expected a fallback node name")
	}
	if strings.Contains(got, ".") {
		t.Fatalf("expected the short hostname, got %q", got)
	}
}

func TestProvisionResolveIP(t *testing.T) {
	ctx := context.Background()
	got, err := provisionResolveIP(ctx, "203.0.113.10")
	if err != nil || got != "203.0.113.10" {
		t.Fatalf("an explicit IP must pass straight through, got %q %v", got, err)
	}
}

func TestProvisionResolverFlag(t *testing.T) {
	if r := provisionResolver(""); r == nil {
		t.Fatal("expected a default resolver")
	}
	r, ok := provisionResolver("9.9.9.9:53, 1.1.1.1:53").(*dns.NetResolver)
	if !ok {
		t.Fatal("expected a *dns.NetResolver")
	}
	if len(r.Servers) != 2 || r.Servers[0] != "9.9.9.9:53" {
		t.Fatalf("unexpected resolvers: %v", r.Servers)
	}
}

func TestProvisionRequiresDomain(t *testing.T) {
	err := cmdProvision([]string{"--cf-token", "tok"})
	if err == nil || !strings.Contains(err.Error(), "--domain is required") {
		t.Fatalf("expected the domain requirement, got %v", err)
	}
}

func TestProvisionHelpWorks(t *testing.T) {
	// --help exits the FlagSet with ErrHelp; the command must surface it rather
	// than crashing, and the usage text must be printed.
	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	runErr := cmdProvision([]string{"--help"})
	w.Close()
	os.Stderr = stderr

	buf := make([]byte, 16384)
	n, _ := r.Read(buf)
	out := string(buf[:n])

	if runErr == nil {
		t.Fatal("expected flag.ErrHelp to be returned")
	}
	for _, needle := range []string{
		"forgectl provision", "{proto}", "{rand}", "CF_API_TOKEN",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("expected the help text to mention %q", needle)
		}
	}
	// A custom Usage replaces flag's default, so the flag list has to be
	// printed explicitly — this is what catches it going missing again.
	for _, flagName := range []string{
		"-domain", "-cf-token", "-provider", "-protocols", "-template",
		"-skip-dns", "-scan", "-challenge", "-list-zones", "-json",
	} {
		if !strings.Contains(out, flagName) {
			t.Errorf("expected the flag list to include %q", flagName)
		}
	}
	// The provider default must name only backends that actually work.
	if !strings.Contains(out, "arvancloud, cloudflare, desec") {
		t.Errorf("expected the provider flag to list the implemented backends, got:\n%s", out)
	}
}

// cfProvisionMock is a minimal Cloudflare stand-in for the CLI end-to-end test.
func cfProvisionMock(t *testing.T) *httptest.Server {
	t.Helper()
	records := map[string]map[string]any{}
	next := 0
	envelope := func(w http.ResponseWriter, result any) {
		w.Header().Set("Content-Type", "application/json")
		raw, _ := json.Marshal(result)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "errors": []any{}, "messages": []any{},
			"result": json.RawMessage(raw),
			"result_info": map[string]int{
				"page": 1, "per_page": 50, "count": 1, "total_count": 1, "total_pages": 1,
			},
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/client/v4")
		switch {
		case strings.HasSuffix(path, "/tokens/verify"):
			envelope(w, map[string]any{"id": "tok", "status": "active"})
		case path == "/zones":
			name := r.URL.Query().Get("name")
			if name != "" && name != "example.com" {
				envelope(w, []any{})
				return
			}
			envelope(w, []map[string]any{{
				"id": "zone1", "name": "example.com", "status": "active",
				"name_servers": []string{"amy.ns.cloudflare.com"},
			}})
		case strings.Contains(path, "/dns_records"):
			switch r.Method {
			case http.MethodGet:
				out := []map[string]any{}
				wantName := r.URL.Query().Get("name")
				for _, rec := range records {
					if wantName == "" || rec["name"] == wantName {
						out = append(out, rec)
					}
				}
				envelope(w, out)
			case http.MethodPost:
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				next++
				body["id"] = "rec" + string(rune('0'+next))
				records[body["id"].(string)] = body
				envelope(w, body)
			default:
				envelope(w, map[string]any{"id": "rec1"})
			}
		case strings.Contains(path, "/settings/"):
			envelope(w, map[string]any{"id": "ssl", "value": "strict"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"errors":  []map[string]any{{"code": 7003, "message": "Could not route to " + path}},
			})
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// The command must run start to finish with no prompts and write a JSON report:
// bare domain in, provisioned and verified inbound set out.
func TestProvisionEndToEndNonInteractive(t *testing.T) {
	cf := cfProvisionMock(t)
	outPath := filepath.Join(t.TempDir(), "report.json")

	err := cmdProvision([]string{
		"--domain", "example.com",
		"--cf-token", "test-token",
		"--api-base", cf.URL + "/client/v4",
		"--ip", "203.0.113.10",
		"--node", "fra1",
		"--template", "{proto}-{node}",
		"--protocols", "ws:443:proxied,reality:443:direct",
		"--skip-preflight",
		"--skip-traffic-proof",
		"--propagation-wait", "0",
		"--out", outPath,
		"--json",
	})
	if err != nil {
		t.Fatalf("provisioning failed: %v", err)
	}

	blob, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("the --out report was not written: %v", err)
	}
	var report dns.WizardReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatalf("the report is not valid JSON: %v", err)
	}
	if !report.OK {
		t.Fatalf("expected a successful run, failures: %+v", report.Failures())
	}
	if report.Domain != "example.com" || report.Provider != "cloudflare" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if len(report.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(report.Endpoints))
	}
	byProto := map[string]dns.Endpoint{}
	for _, ep := range report.Endpoints {
		byProto[ep.Proto] = ep
	}
	if byProto["ws"].Host != "ws-fra1.example.com" || !byProto["ws"].Proxied {
		t.Fatalf("unexpected ws endpoint: %+v", byProto["ws"])
	}
	if byProto["reality"].Host != "reality-fra1.example.com" || byProto["reality"].Proxied {
		t.Fatalf("a REALITY endpoint must never be proxied: %+v", byProto["reality"])
	}
	if len(report.Records) != 2 {
		t.Fatalf("expected 2 records to be reported, got %d", len(report.Records))
	}
}

// --list-zones must work as a standalone, non-interactive query.
func TestProvisionListZones(t *testing.T) {
	cf := cfProvisionMock(t)
	if err := cmdProvision([]string{
		"--list-zones", "--cf-token", "test-token", "--api-base", cf.URL + "/client/v4",
	}); err != nil {
		t.Fatalf("--list-zones failed: %v", err)
	}
}

// A credential the provider rejects must surface as an error carrying the fix,
// with a non-zero exit path — never a silent success.
func TestProvisionSurfacesProviderErrors(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": 9109, "message": "Unauthorized to access requested resource"}},
		})
	}))
	t.Cleanup(dead.Close)

	err := cmdProvision([]string{
		"--domain", "example.com", "--cf-token", "test-token",
		"--api-base", dead.URL + "/client/v4", "--ip", "203.0.113.10",
		"--skip-preflight", "--skip-traffic-proof", "--propagation-wait", "0",
	})
	if err == nil {
		t.Fatal("expected an error when the credential is rejected")
	}
	if !strings.Contains(err.Error(), "failed step") {
		t.Fatalf("expected the failure to be reported, got %v", err)
	}
}

// The same flow, driven through the library with the mock wired in, proves the
// command's own plumbing produces a working WizardConfig.
func TestProvisionWizardConfigFromFlags(t *testing.T) {
	cf := cfProvisionMock(t)
	p, err := dns.NewCloudflare(dns.Credentials{
		"api_token": "test-token", "base_url": cf.URL + "/client/v4",
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	plans, err := provisionParseProtocols("ws:443:proxied,reality:443:direct")
	if err != nil {
		t.Fatalf("protocols: %v", err)
	}

	report, err := dns.Run(context.Background(), dns.WizardConfig{
		Provider: p, Domain: "example.com", OriginIP: "203.0.113.10",
		Node: provisionNodeName("fra1"), Template: "{proto}-{node}",
		Protocols:          plans,
		SkipPreflight:      true,
		SkipTrafficProof:   true,
		DNSPropagationWait: -1,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !report.OK {
		t.Fatalf("expected the run to succeed, failures: %+v", report.Failures())
	}
	if len(report.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(report.Endpoints))
	}
	text := dns.FormatWizardReport(report)
	for _, needle := range []string{"SUCCEEDED", "ws-fra1.example.com", "reality-fra1.example.com", "proxied", "direct"} {
		if !strings.Contains(text, needle) {
			t.Errorf("expected the formatted report to contain %q, got:\n%s", needle, text)
		}
	}
}
