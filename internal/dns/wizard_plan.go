package dns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// endpointPlan is Endpoint plus the fields the wizard needs internally but does
// not put in the report.
type endpointPlan struct {
	Endpoint
	UDPOnly bool
}

func stripInternal(plans []endpointPlan) []Endpoint {
	out := make([]Endpoint, 0, len(plans))
	for _, p := range plans {
		out = append(out, p.Endpoint)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Proto < out[j].Proto })
	return out
}

// planEndpoints renders one hostname per protocol.
func planEndpoints(cfg WizardConfig, protocols []ProtocolPlan, domain string) ([]endpointPlan, Step) {
	tpl := NewNameTemplate(cfg.Template)
	out := make([]endpointPlan, 0, len(protocols))
	seen := map[string]bool{}
	for i, plan := range protocols {
		host := NormalizeDomain(plan.Hostname)
		if host == "" {
			label, err := tpl.Render(TemplateVars{
				Proto: plan.Proto, Node: cfg.Node, Region: cfg.Region,
				Seq: i + 1, Now: cfg.now(),
			})
			if err != nil {
				return nil, Step{Name: "plan-hostnames", Status: StepFailed,
					Detail: err.Error(), Remediation: remediationOf(err)}
			}
			host = label + "." + domain
		}
		if err := ValidateFQDN(host); err != nil {
			return nil, Step{Name: "plan-hostnames", Status: StepFailed,
				Detail: err.Error(), Remediation: remediationOf(err)}
		}
		if seen[host] {
			return nil, Step{Name: "plan-hostnames", Status: StepFailed,
				Detail:      fmt.Sprintf("two protocols rendered the same hostname %q", host),
				Remediation: "add {rand} or {seq} to the naming template so each protocol gets a distinct name"}
		}
		seen[host] = true
		port := plan.Port
		if port == 0 {
			port = 443
		}
		out = append(out, endpointPlan{
			Endpoint: Endpoint{
				Proto: plan.Proto, Host: host, Port: port,
				Address: host, Proxied: plan.Proxied,
			},
			UDPOnly: plan.UDP,
		})
	}
	return out, Step{Name: "plan-hostnames", Status: StepOK,
		Detail: fmt.Sprintf("%d hostname(s): %s", len(out), strings.Join(hostnamesOf(out), ", "))}
}

func hostnamesOf(plans []endpointPlan) []string {
	out := make([]string, 0, len(plans))
	for _, p := range plans {
		out = append(out, p.Host)
	}
	return out
}

// waitForPropagation polls public DNS until every name resolves or the budget
// runs out. It returns how many resolved and which are still missing.
func waitForPropagation(ctx context.Context, cfg WizardConfig, names []string, budget, interval time.Duration) (int, []string) {
	res := cfg.resolver()
	deadline := cfg.now().Add(budget)
	pending := append([]string(nil), names...)
	for {
		var still []string
		for _, name := range pending {
			ips, err := res.LookupIP(ctx, name)
			if err != nil || len(ips) == 0 {
				still = append(still, name)
			}
		}
		pending = still
		if len(pending) == 0 {
			return len(names), nil
		}
		if !cfg.now().Before(deadline) || ctx.Err() != nil {
			return len(names) - len(pending), pending
		}
		cfg.sleep(interval)
	}
}

func failStep(err error) Step {
	s := Step{Status: StepFailed, Detail: err.Error()}
	if e, ok := AsError(err); ok {
		s.Detail = e.Message
		s.Remediation = e.Remediation
		if e.MissingScope != "" {
			s.Detail = e.Message + " (missing permission: " + e.MissingScope + ")"
		}
	}
	return s
}

func remediationOf(err error) string {
	if e, ok := AsError(err); ok {
		return e.Remediation
	}
	return ""
}

func firstPreflightRemediation(reports []PreflightReport) string {
	for _, r := range reports {
		for _, c := range r.Failures() {
			if c.Remediation != "" {
				return fmt.Sprintf("%s: %s", r.Domain, c.Remediation)
			}
		}
	}
	return ""
}

// FormatWizardReport renders a run as operator-facing text.
func FormatWizardReport(r *WizardReport) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	verdict := "SUCCEEDED"
	if !r.OK {
		verdict = "FAILED"
	}
	fmt.Fprintf(&b, "Provisioning %s: %s (%s)\n\n", r.Domain, verdict, r.Duration)
	width := 0
	for _, s := range r.Steps {
		if len(s.Name) > width {
			width = len(s.Name)
		}
	}
	marks := map[StepStatus]string{StepOK: "ok  ", StepSkipped: "skip", StepWarn: "warn", StepFailed: "FAIL"}
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "  [%s] %-*s  %s\n", marks[s.Status], width, s.Name, s.Detail)
		if s.Remediation != "" && s.Status != StepOK {
			fmt.Fprintf(&b, "         %*s  fix: %s\n", width, "", s.Remediation)
		}
	}
	if len(r.Endpoints) > 0 {
		b.WriteString("\nEndpoints (address is what the client dials; sni/host stay on the hostname):\n")
		for _, ep := range r.Endpoints {
			proof := "unproven"
			if ep.Proven {
				proof = "proven"
			}
			proxy := "direct"
			if ep.Proxied {
				proxy = "proxied"
			}
			fmt.Fprintf(&b, "  %-8s host=%s port=%d address=%s (%s, %s)\n",
				ep.Proto, ep.Host, ep.Port, ep.Address, proxy, proof)
			if ep.ProofDetail != "" && !ep.Proven {
				fmt.Fprintf(&b, "           %s\n", ep.ProofDetail)
			}
		}
	}
	if r.CleanIPs != nil && len(r.CleanIPs.IPs) > 0 {
		fmt.Fprintf(&b, "\nClean addresses for %s:\n", r.CleanIPs.SNI)
		for _, ip := range r.CleanIPs.IPs {
			fmt.Fprintf(&b, "  %-16s avg %dms  loss %.0f%%\n", ip.IP, ip.AvgRTTMs, ip.LossPct)
		}
	}
	return b.String()
}
