package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Run executes the whole provisioning flow with no interaction: verify the
// credential, resolve the owning zone, create the hostnames, configure the
// edge, wait for propagation, check ACME readiness, scan for clean addresses
// and finally prove that traffic actually reaches each inbound.
//
// It returns a report even when steps fail; the error is non-nil only when the
// run could not be completed at all.
func Run(ctx context.Context, cfg WizardConfig) (*WizardReport, error) {
	started := cfg.now()
	domain := NormalizeDomain(cfg.Domain)
	if err := ValidateFQDN(domain); err != nil {
		return nil, err
	}
	report := &WizardReport{
		Domain: domain, StartedAt: started.UTC().Format(time.RFC3339),
	}
	if cfg.Provider != nil {
		report.Provider = cfg.Provider.Name()
	}
	protocols := cfg.Protocols
	if len(protocols) == 0 {
		protocols = DefaultProtocolPlans()
	}

	finish := func() (*WizardReport, error) {
		report.OK = len(report.Failures()) == 0
		report.Duration = cfg.now().Sub(started).Round(time.Millisecond).String()
		return report, nil
	}
	step := func(name string, fn func() Step) Step {
		start := cfg.now()
		s := fn()
		s.Name = name
		if s.Elapsed == "" {
			s.Elapsed = cfg.now().Sub(start).Round(time.Millisecond).String()
		}
		report.Steps = append(report.Steps, s)
		return s
	}

	// 1. Credential.
	if cfg.SkipDNS || cfg.Provider == nil {
		step("verify-credential", func() Step {
			return Step{Status: StepSkipped, Detail: "DNS provisioning is disabled (--skip-dns), so no credential was verified"}
		})
	} else {
		s := step("verify-credential", func() Step {
			ident, err := cfg.Provider.VerifyCredentials(ctx)
			if err != nil {
				return failStep(err)
			}
			report.Identity = ident
			return Step{Status: StepOK, Detail: fmt.Sprintf("%s credential accepted — %s", cfg.Provider.Name(), ident.Detail)}
		})
		if s.Status == StepFailed {
			return finish()
		}
	}

	// 2. Zone resolution and delegation.
	var zoneRef string
	if cfg.Provider != nil && !cfg.SkipDNS {
		s := step("resolve-zone", func() Step {
			res, err := ResolveZone(ctx, cfg.Provider, cfg.resolver(), domain)
			if err != nil {
				return failStep(err)
			}
			report.Zone = res
			zoneRef = res.Zone.Ref()
			detail := fmt.Sprintf("%s is owned by zone %s at %s", domain, res.Zone.Name, res.Zone.Provider)
			if res.Delegated {
				return Step{Status: StepWarn, Detail: detail + fmt.Sprintf(", but %s is delegated to %s",
					res.DelegationPoint, strings.Join(res.DelegatedTo, ", ")), Remediation: res.ACMENote}
			}
			if res.ACMENote != "" {
				return Step{Status: StepWarn, Detail: detail, Remediation: res.ACMENote}
			}
			return Step{Status: StepOK, Detail: detail}
		})
		if s.Status == StepFailed {
			return finish()
		}
	} else {
		step("resolve-zone", func() Step {
			return Step{Status: StepSkipped, Detail: "DNS provisioning is disabled, so the owning zone was not resolved"}
		})
	}

	// 3. Hostnames.
	endpoints, hostStep := planEndpoints(cfg, protocols, domain)
	report.Steps = append(report.Steps, hostStep)
	if hostStep.Status == StepFailed {
		return finish()
	}

	// 4. Records.
	if cfg.SkipDNS || cfg.Provider == nil {
		step("create-records", func() Step {
			return Step{Status: StepSkipped, Detail: "DNS provisioning is disabled; the hostnames are assumed to exist already"}
		})
	} else {
		step("create-records", func() Step {
			if strings.TrimSpace(cfg.OriginIP) == "" {
				return Step{Status: StepFailed, Detail: "no origin IP was supplied",
					Remediation: "pass --ip with this server's public address so the A records point somewhere"}
			}
			if net.ParseIP(cfg.OriginIP) == nil {
				return Step{Status: StepFailed, Detail: fmt.Sprintf("%q is not a valid IP address", cfg.OriginIP),
					Remediation: "pass --ip as a literal address such as 203.0.113.10"}
			}
			rtype := TypeA
			if net.ParseIP(cfg.OriginIP).To4() == nil {
				rtype = TypeAAAA
			}
			var firstErr error
			created, updated, unchanged := 0, 0, 0
			for i := range endpoints {
				ep := &endpoints[i]
				rec := Record{
					Type: rtype, Name: ep.Host, Content: cfg.OriginIP,
					TTL: cfg.TTL, Proxied: ep.Proxied,
					Comment: "forgepanel " + ep.Proto,
				}
				res, err := EnsureRecord(ctx, cfg.Provider, zoneRef, rec)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				report.Records = append(report.Records, *res)
				ep.RecordID = res.Record.ID
				ep.Action = res.Action
				switch res.Action {
				case "created":
					created++
				case "updated":
					updated++
				default:
					unchanged++
				}
			}
			if firstErr != nil {
				return failStep(firstErr)
			}
			return Step{Status: StepOK, Detail: fmt.Sprintf("%d record(s): %d created, %d updated, %d already correct",
				len(report.Records), created, updated, unchanged)}
		})
	}

	// 5. Zone settings.
	if cfg.SkipSettings || cfg.SkipDNS || cfg.Provider == nil {
		step("zone-settings", func() Step {
			return Step{Status: StepSkipped, Detail: "zone settings were not touched"}
		})
	} else if sc, ok := cfg.Provider.(ZoneSettingsController); !ok {
		step("zone-settings", func() Step {
			return Step{Status: StepSkipped,
				Detail: fmt.Sprintf("%s does not expose edge settings through its API", cfg.Provider.Name()),
				Remediation: "if this provider has a CDN, set origin-pull TLS to Full (strict) and enable WebSockets by hand in its dashboard; " +
					"a Flexible origin-pull mode will break every TLS inbound."}
		})
	} else {
		step("zone-settings", func() Step {
			want := cfg.Settings
			if want == nil {
				rec := RecommendedZoneSettings()
				want = &rec
			}
			results, err := sc.ApplyZoneSettings(ctx, zoneRef, *want)
			report.Settings = results
			applied, failed := 0, 0
			for _, r := range results {
				if r.Applied {
					applied++
				} else {
					failed++
				}
			}
			if err != nil {
				s := failStep(err)
				s.Detail = fmt.Sprintf("%d of %d settings applied — %s", applied, len(results), s.Detail)
				return s
			}
			if failed > 0 {
				return Step{Status: StepWarn,
					Detail:      fmt.Sprintf("%d of %d settings applied; %d were rejected by the zone's plan", applied, len(results), failed),
					Remediation: "see zone_settings in the report for the exact consequence of each rejected setting"}
			}
			return Step{Status: StepOK, Detail: fmt.Sprintf("%d edge setting(s) applied", applied)}
		})
	}

	// 6. Propagation.
	if cfg.SkipDNS || cfg.Provider == nil || cfg.DNSPropagationWait < 0 {
		step("dns-propagation", func() Step {
			return Step{Status: StepSkipped, Detail: "propagation wait skipped"}
		})
	} else {
		step("dns-propagation", func() Step {
			wait := cfg.DNSPropagationWait
			if wait == 0 {
				wait = 45 * time.Second
			}
			interval := cfg.PollInterval
			if interval == 0 {
				interval = 3 * time.Second
			}
			names := make([]string, 0, len(endpoints))
			for _, ep := range endpoints {
				names = append(names, ep.Host)
			}
			resolved, pending := waitForPropagation(ctx, cfg, names, wait, interval)
			if len(pending) == 0 {
				return Step{Status: StepOK, Detail: fmt.Sprintf("all %d hostname(s) resolve in public DNS", resolved)}
			}
			return Step{Status: StepWarn,
				Detail:      fmt.Sprintf("%d of %d hostname(s) resolve; still waiting on %s", resolved, len(names), strings.Join(pending, ", ")),
				Remediation: fmt.Sprintf("propagation can take longer than the %s the wizard waited. Re-run in a few minutes; if a name never appears, its record was written into a zone that is not authoritative for it — check the resolve-zone step for a delegation warning.", wait)}
		})
	}

	// 7. ACME readiness.
	if cfg.SkipPreflight {
		step("acme-preflight", func() Step {
			return Step{Status: StepSkipped, Detail: "ACME preflight skipped"}
		})
	} else {
		step("acme-preflight", func() Step {
			pf := Preflight{Resolver: cfg.resolver(), Now: cfg.Now}
			if cfg.Preflight != nil {
				pf = *cfg.Preflight
				if pf.Resolver == nil {
					pf.Resolver = cfg.resolver()
				}
			}
			challenge := cfg.Challenge
			if challenge == "" {
				challenge = ChallengeDNS01
			}
			failed := 0
			for _, ep := range endpoints {
				in := PreflightInput{
					Domain: ep.Host, ExpectIP: cfg.OriginIP, Resolution: report.Zone,
					Challenge: challenge, Proxied: ep.Proxied,
				}
				if report.Zone != nil {
					in.Zone = &report.Zone.Zone
				}
				rep, err := pf.Run(ctx, in)
				if err != nil {
					return failStep(err)
				}
				report.Preflight = append(report.Preflight, *rep)
				if !rep.OK {
					failed++
				}
			}
			if failed == 0 {
				return Step{Status: StepOK, Detail: fmt.Sprintf("all %d hostname(s) are ready for an ACME %s challenge", len(endpoints), challenge)}
			}
			return Step{Status: StepFailed,
				Detail:      fmt.Sprintf("%d of %d hostname(s) are not ready for certificate issuance", failed, len(endpoints)),
				Remediation: firstPreflightRemediation(report.Preflight)}
		})
	}

	// 8. Clean-IP scan.
	if cfg.Scan == nil {
		step("clean-ip-scan", func() Step {
			return Step{Status: StepSkipped, Detail: "no clean-IP scan was requested"}
		})
	} else {
		step("clean-ip-scan", func() Step {
			sc := *cfg.Scan
			if strings.TrimSpace(sc.SNI) == "" {
				// Scan against the first proxied hostname: an edge address is
				// only useful for a name the edge actually serves.
				for _, ep := range endpoints {
					if ep.Proxied {
						sc.SNI = ep.Host
						break
					}
				}
			}
			if strings.TrimSpace(sc.SNI) == "" {
				return Step{Status: StepSkipped,
					Detail:      "no proxied hostname exists, so there is no CDN edge to scan",
					Remediation: "clean-IP scanning only applies to hostnames behind a CDN; a direct or REALITY inbound is dialled by hostname or origin IP."}
			}
			repo := cfg.CleanIPs
			if repo == nil {
				repo = NewMemStore()
			}
			job := ScanJob{Name: sc.SNI, Config: sc, Repo: repo, Now: cfg.Now}
			set, scanReport, err := job.Run(ctx)
			report.CleanIPs = set
			if err != nil {
				s := failStep(err)
				s.Status = StepWarn // a thin scan is not fatal: the hostname still works
				return s
			}
			// A verified edge address becomes the dialled address while sni and
			// host stay on the domain.
			best := set.Best()
			for i := range endpoints {
				if endpoints[i].Proxied && best != "" {
					endpoints[i].Address = best
				}
			}
			return Step{Status: StepOK, Detail: fmt.Sprintf("%d clean address(es) verified for %s out of %d sampled (%d passed TCP)",
				len(set.IPs), set.SNI, scanReport.Sampled, scanReport.TCPPassed)}
		})
	}

	// 9. Traffic proof.
	if cfg.SkipTrafficProof {
		step("traffic-proof", func() Step {
			return Step{Status: StepSkipped, Detail: "connectivity proof skipped"}
		})
	} else {
		step("traffic-proof", func() Step {
			prober := cfg.Prober
			proven, unproven, skipped := 0, []string{}, 0
			for i := range endpoints {
				ep := &endpoints[i]
				if ep.UDPOnly {
					ep.ProofDetail = "UDP transport — a TCP handshake cannot prove it; verify with a real client"
					skipped++
					continue
				}
				p := prober
				if p == nil {
					p = TLSProber{Port: ep.Port}
				} else if tp, ok := p.(TLSProber); ok && tp.Port == 0 {
					tp.Port = ep.Port
					p = tp
				}
				target := ep.Host
				res := p.Probe(ctx, target)
				ep.Proven = res.OK
				ep.ProofDetail = res.Detail
				if res.OK {
					proven++
				} else {
					unproven = append(unproven, fmt.Sprintf("%s (%s)", ep.Host, res.Detail))
				}
			}
			switch {
			case len(unproven) == 0 && proven > 0:
				return Step{Status: StepOK, Detail: fmt.Sprintf("%d endpoint(s) carried a real TLS connection; %d UDP endpoint(s) not testable this way", proven, skipped)}
			case proven == 0 && len(unproven) > 0:
				return Step{Status: StepFailed,
					Detail: fmt.Sprintf("no endpoint accepted a connection: %s", strings.Join(unproven, "; ")),
					Remediation: "DNS is correct but nothing is listening. Start the engine (`forgectl service start`), confirm the inbound ports are open in the host firewall and the cloud security group, " +
						"and check the certificate is installed for these hostnames."}
			case len(unproven) > 0:
				return Step{Status: StepWarn,
					Detail:      fmt.Sprintf("%d of %d endpoint(s) proven; failed: %s", proven, proven+len(unproven), strings.Join(unproven, "; ")),
					Remediation: "check the listening port and firewall for each failed endpoint."}
			default:
				return Step{Status: StepSkipped, Detail: "no TCP endpoint to prove"}
			}
		})
	}

	report.Endpoints = stripInternal(endpoints)
	return finish()
}
