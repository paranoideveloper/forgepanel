package main

// forgectl provision — the §5 domain & DNS automation wizard as a single
// non-interactive command. It takes an empty domain and a provider credential
// and leaves behind a verified, TLS-enabled, traffic-proven inbound set: zone
// resolved, records created, edge settings applied, ACME readiness checked,
// clean edge addresses scanned, and every endpoint dialled for real.
//
// There are no prompts anywhere in this path, by design — it is meant to run
// from an installer, a CI job or a cron entry as readily as from a shell.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/dns"
	"github.com/forgepanel/forgepanel/internal/netegress"
)

// provisionIPEchoURL reports this host's public address. Cloudflare's trace
// endpoint is used because it answers in a trivially parseable key=value form
// and is reachable from almost anywhere the panel runs.
const provisionIPEchoURL = "https://cloudflare.com/cdn-cgi/trace"

// cmdProvision implements `forgectl provision`.
//
// Wiring note for the panel: main.go's dispatch switch needs one line —
//
//	case "provision":
//	    err = cmdProvision(os.Args[2:])
//
// until then the command is reachable through the package's tests and by any
// caller that imports it.
func cmdProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	// A custom Usage replaces flag's default entirely, so the flag list has to
	// be printed explicitly or --help shows the prose and nothing else.
	fs.Usage = func() {
		provisionUsage()
		fs.PrintDefaults()
	}

	var (
		domain   = fs.String("domain", "", "domain to provision under, e.g. example.com (required)")
		provider = fs.String("provider", "cloudflare", "DNS provider: "+strings.Join(dns.ImplementedProviders(), ", "))

		cfToken    = fs.String("cf-token", "", "Cloudflare API token (or $CF_API_TOKEN)")
		cfAccount  = fs.String("cf-account", "", "Cloudflare account id (optional, or $CF_ACCOUNT_ID)")
		arvanKey   = fs.String("arvan-key", "", "ArvanCloud API key (or $ARVAN_API_KEY)")
		desecToken = fs.String("desec-token", "", "deSEC API token (or $DESEC_TOKEN)")
		apiBase    = fs.String("api-base", "", "override the provider's API root (for a proxy, a private endpoint, or testing)")

		ip       = fs.String("ip", "auto", `origin IP the records point at; "auto" detects this host's public address`)
		node     = fs.String("node", "", "node name for the {node} placeholder (default: this host's short hostname)")
		region   = fs.String("region", "", "region tag for the {region} placeholder")
		template = fs.String("template", dns.DefaultNameTemplate, "subdomain naming template")
		ttl      = fs.Int("ttl", dns.DefaultTTL, "TTL for created records")

		protocols = fs.String("protocols", "", "inbound set as proto[:port][:proxied|direct][:udp], comma-separated (default: the shipped set)")
		challenge = fs.String("challenge", string(dns.ChallengeDNS01), "ACME challenge to check readiness for: dns-01 or http-01")

		skipDNS     = fs.Bool("skip-dns", false, "do not create records; verify hostnames that already exist")
		skipSetting = fs.Bool("skip-settings", false, "do not touch zone/edge settings")
		skipPre     = fs.Bool("skip-preflight", false, "do not run ACME readiness checks")
		skipProof   = fs.Bool("skip-traffic-proof", false, "do not dial the endpoints at the end")

		scan        = fs.Bool("scan", false, "scan the CDN ranges for clean edge addresses")
		scanSNI     = fs.String("scan-sni", "", "hostname to scan against (default: the first proxied hostname)")
		scanSamples = fs.Int("scan-samples", 256, "how many addresses to sample")
		scanConc    = fs.Int("scan-concurrency", 64, "concurrent probes during a scan")
		scanProbes  = fs.Int("scan-probes", 3, "TLS handshakes per surviving address, which is what measures loss")
		scanKeep    = fs.Int("scan-keep", 10, "how many ranked addresses to keep")
		scanPort    = fs.Int("scan-port", 443, "port to scan")

		propagation = fs.Duration("propagation-wait", 45*time.Second, "how long to wait for records to appear in public DNS (0 disables)")
		resolvers   = fs.String("resolvers", "", "comma-separated recursive resolvers (default: 1.1.1.1:53,8.8.8.8:53)")
		timeout     = fs.Duration("timeout", 10*time.Minute, "overall deadline for the run")

		listZones = fs.Bool("list-zones", false, "list the zones the credential can see, then exit")
		asJSON    = fs.Bool("json", false, "emit the full report as JSON")
		out       = fs.String("out", "", "also write the JSON report to this file")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	creds, err := provisionCredentials(*provider, *cfToken, *cfAccount, *arvanKey, *desecToken)
	if err != nil {
		return err
	}
	// Every implemented provider reads base_url from its credentials, so one
	// flag redirects whichever backend was chosen.
	if base := strings.TrimSpace(*apiBase); base != "" {
		creds["base_url"] = base
	}
	p, err := dns.NewProvider(*provider, creds)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *listZones {
		zones, err := p.ListZones(ctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(zones)
		}
		if len(zones) == 0 {
			fmt.Println("the credential is valid but can see no zones — widen its Zone Resources at the provider")
			return nil
		}
		for _, z := range zones {
			fmt.Printf("%-40s %-10s %s\n", z.Name, z.Status, strings.Join(z.NameServers, ", "))
		}
		return nil
	}

	if strings.TrimSpace(*domain) == "" {
		fs.Usage()
		return fmt.Errorf("--domain is required")
	}

	originIP := strings.TrimSpace(*ip)
	if !*skipDNS {
		originIP, err = provisionResolveIP(ctx, originIP)
		if err != nil {
			return err
		}
	}

	plans, err := provisionParseProtocols(*protocols)
	if err != nil {
		return err
	}

	cfg := dns.WizardConfig{
		Provider: p, Domain: *domain, OriginIP: originIP,
		Template: *template, Node: provisionNodeName(*node), Region: *region,
		Protocols: plans, TTL: *ttl,
		Challenge:        dns.ChallengeType(strings.ToLower(strings.TrimSpace(*challenge))),
		SkipDNS:          *skipDNS,
		SkipSettings:     *skipSetting,
		SkipPreflight:    *skipPre,
		SkipTrafficProof: *skipProof,
		Resolver:         provisionResolver(*resolvers),
		CleanIPs:         dns.NewMemStore(),
	}
	if *propagation <= 0 {
		cfg.DNSPropagationWait = -1
	} else {
		cfg.DNSPropagationWait = *propagation
	}
	if *scan {
		cfg.Scan = &dns.ScanConfig{
			SNI: *scanSNI, Port: *scanPort, Samples: *scanSamples,
			Concurrency: *scanConc, Probes: *scanProbes, Keep: *scanKeep,
		}
	}

	report, err := dns.Run(ctx, cfg)
	if err != nil {
		return err
	}

	if strings.TrimSpace(*out) != "" {
		blob, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		if writeErr := os.WriteFile(*out, append(blob, '\n'), 0o600); writeErr != nil {
			return writeErr
		}
	}
	if *asJSON {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		fmt.Print(dns.FormatWizardReport(report))
	}
	if !report.OK {
		return fmt.Errorf("provisioning finished with %d failed step(s); see the report above", len(report.Failures()))
	}
	return nil
}

func provisionUsage() {
	fmt.Fprint(os.Stderr, `forgectl provision — domain & DNS automation wizard

Takes a bare domain to a verified, TLS-enabled, traffic-proven inbound set with
no prompts: verify credential → resolve owning zone → create hostnames →
configure the edge → wait for propagation → ACME readiness → clean-IP scan →
dial every endpoint for real.

Usage:
  forgectl provision --domain example.com --cf-token <token> [--cf-account <id>]
  forgectl provision --domain example.com --provider desec --desec-token <token>
  forgectl provision --list-zones --cf-token <token>

Examples:
  # Full run against Cloudflare, scanning for clean edge addresses.
  forgectl provision --domain example.com --cf-token $CF_API_TOKEN \
      --node fra1 --scan --json

  # Only these two inbounds, one behind the CDN and one direct.
  forgectl provision --domain example.com --cf-token $CF_API_TOKEN \
      --protocols 'ws:443:proxied,reality:443:direct'

  # Records already exist elsewhere; just verify and prove them.
  forgectl provision --domain example.com --skip-dns --provider cloudflare \
      --cf-token $CF_API_TOKEN

Credentials are read from flags first, then the environment:
  CF_API_TOKEN, CF_ACCOUNT_ID, ARVAN_API_KEY, DESEC_TOKEN

Naming template placeholders:
  {proto} {node} {region} {seq} {date} {rand} {rand:N}

Flags:
`)
	// The FlagSet prints its own defaults; this is called as fs.Usage so the
	// caller's PrintDefaults follows.
}

// provisionCredentials assembles the credential map for a provider from flags
// and the environment, and refuses a provider with no backend up front rather
// than after the operator has typed a full command line.
func provisionCredentials(provider, cfToken, cfAccount, arvanKey, desecToken string) (dns.Credentials, error) {
	name := strings.ToLower(strings.TrimSpace(provider))
	info, ok := dns.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q; use one of: %s", provider, strings.Join(dns.ImplementedProviders(), ", "))
	}
	if !info.Implemented {
		return nil, fmt.Errorf("the %s backend is not available in this build.\n"+
			"Create the records at %s, then re-run with --skip-dns to verify and prove them.\n"+
			"Implemented providers: %s", info.Title, info.TokenURL, strings.Join(dns.ImplementedProviders(), ", "))
	}

	creds := dns.Credentials{}
	switch name {
	case "cloudflare":
		token := firstNonEmpty(cfToken, os.Getenv("CF_API_TOKEN"), os.Getenv("CLOUDFLARE_API_TOKEN"))
		if token == "" {
			return nil, fmt.Errorf("--cf-token (or $CF_API_TOKEN) is required for Cloudflare.\n"+
				"Create one at %s with %s, %s, %s and %s, scoped to the zone",
				info.TokenURL, dns.ScopeZoneRead, dns.ScopeDNSEdit, dns.ScopeSettingsEdit, dns.ScopeSSLEdit)
		}
		creds["api_token"] = token
		if account := firstNonEmpty(cfAccount, os.Getenv("CF_ACCOUNT_ID"), os.Getenv("CLOUDFLARE_ACCOUNT_ID")); account != "" {
			creds["account_id"] = account
		}
	case "arvancloud":
		key := firstNonEmpty(arvanKey, os.Getenv("ARVAN_API_KEY"))
		if key == "" {
			return nil, fmt.Errorf("--arvan-key (or $ARVAN_API_KEY) is required for ArvanCloud; create one at %s", info.TokenURL)
		}
		creds["api_key"] = key
	case "desec":
		token := firstNonEmpty(desecToken, os.Getenv("DESEC_TOKEN"))
		if token == "" {
			return nil, fmt.Errorf("--desec-token (or $DESEC_TOKEN) is required for deSEC; create one at %s", info.TokenURL)
		}
		creds["token"] = token
	default:
		return nil, fmt.Errorf("no credential mapping for provider %q", name)
	}
	return creds, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// provisionResolveIP turns "auto" into this host's public address.
func provisionResolveIP(ctx context.Context, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value != "" && !strings.EqualFold(value, "auto") {
		return value, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provisionIPEchoURL, nil)
	if err != nil {
		return "", err
	}
	client := netegress.Client(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not detect this host's public IP (%v).\nPass it explicitly with --ip <address>", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", fmt.Errorf("could not read the IP detection response: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			detected := strings.TrimSpace(rest)
			if detected != "" {
				return detected, nil
			}
		}
	}
	return "", fmt.Errorf("could not parse a public IP out of %s.\nPass it explicitly with --ip <address>", provisionIPEchoURL)
}

// provisionNodeName defaults {node} to the host's short name so records are
// identifiable without the operator having to name every server twice.
func provisionNodeName(value string) string {
	if s := strings.TrimSpace(value); s != "" {
		return s
	}
	host, err := os.Hostname()
	if err != nil {
		return "node"
	}
	if idx := strings.IndexByte(host, '.'); idx > 0 {
		host = host[:idx]
	}
	if host == "" {
		return "node"
	}
	return host
}

// provisionParseProtocols parses the --protocols value.
//
// Each entry is proto[:port][:proxied|direct][:udp] — for example
// "ws:443:proxied,reality:443:direct,hy2:8443:direct:udp". An empty value uses
// the shipped default set.
func provisionParseProtocols(spec string) ([]dns.ProtocolPlan, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []dns.ProtocolPlan
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		plan := dns.ProtocolPlan{Proto: strings.ToLower(strings.TrimSpace(parts[0])), Port: 443, TLS: true}
		if plan.Proto == "" {
			return nil, fmt.Errorf("protocol entry %q has no name; use proto[:port][:proxied|direct][:udp]", entry)
		}
		for _, part := range parts[1:] {
			part = strings.ToLower(strings.TrimSpace(part))
			switch part {
			case "":
			case "proxied", "cdn", "orange":
				plan.Proxied = true
			case "direct", "gray", "grey":
				plan.Proxied = false
			case "udp":
				plan.UDP = true
			case "notls", "no-tls":
				plan.TLS = false
			default:
				port, err := strconv.Atoi(part)
				if err != nil || port <= 0 || port > 65535 {
					return nil, fmt.Errorf("protocol entry %q has an unrecognised part %q; expected a port, proxied, direct, udp or notls", entry, part)
				}
				plan.Port = port
			}
		}
		out = append(out, plan)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--protocols was set but parsed to nothing; use proto[:port][:proxied|direct][:udp]")
	}
	return out, nil
}

// provisionResolver builds the resolver from a comma-separated flag value.
func provisionResolver(spec string) dns.Resolver {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return dns.NewResolver()
	}
	var servers []string
	for _, s := range strings.Split(spec, ",") {
		if s = strings.TrimSpace(s); s != "" {
			servers = append(servers, s)
		}
	}
	return dns.NewResolver(servers...)
}
