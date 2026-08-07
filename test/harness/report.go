//go:build harness

// report.go emits the two artefacts the harness exists to produce: a
// machine-readable matrix that CI and the panel UI can consume, and a printed
// table a human can read at a glance. Both carry the same verdicts and the same
// reasons — there is no summary that says more than the data behind it.
package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report is the whole run.
type Report struct {
	GeneratedAt  string         `json:"generated_at"`
	PanelVersion map[string]any `json:"panel_version,omitempty"`
	Cores        map[string]string `json:"cores"`
	Topology     Topology       `json:"topology"`
	Summary      Summary        `json:"summary"`
	Cases        []Result       `json:"cases"`
	// Preflight is the check of whether the production runtime image can even
	// execute the cores the panel pins. It is separate from the matrix because
	// it is a property of the shipped image, not of any one protocol.
	Preflight *Preflight `json:"preflight,omitempty"`
	// Findings are conclusions that span cases — the things a reader should take
	// away even if they never open the per-case rows.
	Findings []Finding `json:"findings"`
}

// Preflight records whether each pinned proxy core can be executed inside the
// base image the production Dockerfile ships.
type Preflight struct {
	ProductionBase string           `json:"production_runtime_base"`
	Checks         []PreflightCheck `json:"checks"`
}

// PreflightCheck is one core's exec attempt in that base image.
type PreflightCheck struct {
	Engine string `json:"engine"`
	Binary string `json:"binary"`
	OK     bool   `json:"ok"`
	Exit   int    `json:"exit"`
	Output string `json:"output"`
}

// AddPreflight attaches a preflight result and, when a core cannot run, states
// the consequence as a finding with the command that demonstrates it.
func (r *Report) AddPreflight(p *Preflight) {
	if p == nil {
		return
	}
	r.Preflight = p
	for _, c := range p.Checks {
		if c.OK {
			continue
		}
		affected := "the protocols routed to it"
		if c.Engine == "sing-box" {
			affected = "Hysteria2, TUIC, AnyTLS, ShadowTLS, WireGuard and SSH"
		}
		r.Findings = append(r.Findings, Finding{
			ID:       "core-not-executable-in-production-image-" + c.Engine,
			Severity: "blocker",
			Title:    fmt.Sprintf("The %s core the panel pins cannot be executed in the production image", c.Engine),
			Detail: fmt.Sprintf(
				"The production Dockerfile runtime stage is %s. internal/core/binmgr downloads %s at "+
					"runtime and internal/core/supervisor execs it. Running that exact binary in that "+
					"exact base image exits %d: %q. The release archive is dynamically linked against "+
					"glibc, which musl does not provide, so %s cannot work in the shipped container at "+
					"all — the supervisor reports a start error and the inbound silently never serves. "+
					"Fixes are a glibc base, apk add gcompat, or pinning a musl build.",
				p.ProductionBase, c.Binary, c.Exit, strings.TrimSpace(c.Output), affected),
		})
	}
}

// Topology records the isolation the run relied on, because every "pass" is
// only meaningful relative to it.
type Topology struct {
	PanelURL       string `json:"panel_url"`
	Origin         string `json:"origin"`
	DirectReachable bool  `json:"origin_reachable_without_tunnel"`
	IsolationNote  string `json:"isolation_note"`
}

// Summary is the headline count.
type Summary struct {
	Total        int `json:"total"`
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Experimental int `json:"experimental"`
	Unsupported  int `json:"unsupported"`
}

// Finding is a cross-cutting conclusion with the evidence that supports it.
type Finding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"` // blocker | major | minor | info
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Cases    []string `json:"cases,omitempty"`
}

// NewReport assembles a report from results.
func NewReport(results []Result) *Report {
	r := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Cores:       map[string]string{},
		Cases:       results,
	}
	for _, c := range results {
		r.Summary.Total++
		switch c.Status {
		case StatusPass:
			r.Summary.Pass++
		case StatusFail:
			r.Summary.Fail++
		case StatusExperimental:
			r.Summary.Experimental++
		case StatusUnsupported:
			r.Summary.Unsupported++
		}
	}
	r.Findings = deriveFindings(results)
	return r
}

// deriveFindings turns repeated per-case observations into stated conclusions.
// Every finding names the cases that produced it, so none of them is an opinion.
func deriveFindings(results []Result) []Finding {
	var out []Finding
	collect := func(pred func(Result) bool) []string {
		var ids []string
		for _, r := range results {
			if pred(r) {
				ids = append(ids, r.ID)
			}
		}
		sort.Strings(ids)
		return ids
	}

	if ids := collect(func(r Result) bool { return repairWorked(r, "repair:xray-tls-pin") }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "tls-client-cannot-trust-panel-cert", Severity: "blocker",
			Title: "Xray TLS client configs the panel emits cannot connect to the panel's own TLS inbounds",
			Detail: "Xray 26 removed allowInsecure in favour of pinnedPeerCertSha256. " +
				"internal/api/defaults.go applyExportDefaults still sets Security.AllowInsecure, but " +
				"internal/protocol/render/xray.go never emits it (and Xray would reject it), and nothing " +
				"populates Security.PinSHA256. A TLS inbound therefore serves the panel's self-signed " +
				"certificate to a client that has no way to accept it. The harness only got these cases " +
				"to pass by injecting pinnedPeerCertSha256 itself.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return hasMutationKind(r, "added-inbound") }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "singbox-subscription-not-runnable", Severity: "major",
			Title: "The sing-box subscription format is not a runnable configuration",
			Detail: "internal/api/sub.go singboxSubscription emits only log + outbounds. sing-box starts, " +
				"but with no inbounds[] and no route[] nothing can be sent through it. The xray format " +
				"does ship socks/http inbounds, so the two formats are not equivalent deliverables. " +
				"The harness had to add a mixed inbound and a route to drive any sing-box case.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return repairWorked(r, "repair:singbox-quic-utls") }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "quic-outbound-carries-utls", Severity: "blocker",
			Title: "Hysteria2 / TUIC client configs carry a uTLS block sing-box refuses",
			Detail: "internal/api/defaults.go applyCreateDefaults stamps fingerprint=chrome onto every " +
				"security=tls node, and render.sbTLS turns any fingerprint into a utls block. uTLS mimics " +
				"a browser's TCP TLS ClientHello; QUIC has its own TLS 1.3 stack, so sing-box fails every " +
				"connection with \"unsupported usage for uTLS\". The tunnel itself is fine — the same case " +
				"passes once the block is removed — but the config as delivered never carries a byte.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return repairWorked(r, "repair:credential-from-inbound") }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "subscription-credential-mismatch", Severity: "blocker",
			Title: "The subscription hands out a credential the served inbound does not hold",
			Detail: "internal/api/admin.go stampIdentity overwrites the node's credential with the user's, " +
				"but internal/core/engine/multi.go applyXrayClients only expands settings.clients for " +
				"VLESS, VMess and Trojan and returns early for everything else — so those inbounds keep " +
				"the template credential while the subscription ships the user's. For Shadowsocks the " +
				"mismatch is also fatal at parse time: the user password is keygen.Password (base64url) " +
				"while a 2022-blake3 PSK must be standard base64 of the exact key length, so the client " +
				"core refuses the config outright. Substituting the inbound's own credential makes the " +
				"listed cases work, which locates the defect in the subscription, not the transport.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return repairWorked(r, "repair:shadowtls-chain") }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "shadowtls-client-missing-inner-hop", Severity: "major",
			Title: "The ShadowTLS client config carries no traffic as emitted",
			Detail: "render.SingboxOutbound emits a bare shadowtls outbound. ShadowTLS is camouflage: " +
				"sing-box needs a shadowsocks outbound that detours to it, which is exactly what the " +
				"server side already does (render.SingboxInbounds emits the inner SS inbound). The " +
				"client side does not mirror it, so the emitted config connects and then stalls.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return r.Online != nil && !r.Online.OK }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "no-online-status", Severity: "major",
			Title: "The panel has no online / last-seen signal for a user",
			Detail: "store.User.FirstConnectAt is the only candidate column and nothing writes it — " +
				"internal/job/scheduler.go reads it for the on-hold transition and that is its only " +
				"appearance outside the model. There is no last_seen column and no connection event. " +
				"The harness pushed verified traffic for every listed case and the field stayed null, " +
				"so 'user is online' cannot be asserted by any client of this API.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool {
		return r.Accounting != nil && !r.Accounting.OK && r.TCP != nil && r.TCP.OK
	}); len(ids) > 0 {
		out = append(out, Finding{
			ID: "traffic-not-accounted", Severity: "major",
			Title: "Verified traffic was not attributed to the user",
			Detail: "The listed cases carried a full payload through the tunnel, but the user's " +
				"used_traffic did not rise by a comparable amount within the poll window. For sing-box " +
				"protocols this is expected and documented (no stats API in the official builds); for " +
				"Xray protocols it means quota accounting is not working for that inbound shape.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool { return r.Policy == "inbound-disabled" && r.Status == StatusFail }); len(ids) > 0 {
		out = append(out, Finding{
			ID: "no-inbound-disable", Severity: "major",
			Title: "An inbound cannot be disabled, only deleted",
			Detail: "store.Inbound carries an Enabled column that enabledInboundSpecs and " +
				"subscriptionNodes both honour, and the admin list reports it — but store.CreateInbound " +
				"sets it true and no handler ever clears it. PUT /api/admin/inbounds/:id binds a " +
				"model.Node, which has no such field, so the flag is unreachable through the API. " +
				"Taking an inbound out of service therefore means deleting it and losing its keys, " +
				"ports and REALITY material.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool {
		return r.Expect == ExpectDeny && r.Status == StatusFail && r.Policy != "inbound-disabled"
	}); len(ids) > 0 {
		out = append(out, Finding{
			ID: "policy-not-enforced", Severity: "blocker",
			Title: "An account restriction did not stop traffic",
			Detail: "The listed policy cases proved the tunnel worked, applied the restriction, and then " +
				"kept transferring a full payload. internal/api/engines.go enabledInboundSpecs skips only " +
				"StatusDisabled and StatusExpired, so a user the scheduler moved to StatusLimited is still " +
				"materialised into the served inbound, and internal/api/admin.go subscriptionNodes makes " +
				"the same omission for the subscription.",
			Cases: ids,
		})
	}
	if ids := collect(func(r Result) bool {
		return r.Status == StatusUnsupported && strings.Contains(r.Reason, "engine layer refused")
	}); len(ids) > 0 {
		out = append(out, Finding{
			ID: "accepted-then-skipped", Severity: "major",
			Title: "The API accepted inbounds the engine layer then refused to serve",
			Detail: "These combinations passed model.Validate and were persisted, so they appear in the " +
				"panel as configured inbounds, but engine.BuildMulti dropped them into Skipped. Nothing " +
				"in the create response tells the operator that.",
			Cases: ids,
		})
	}
	return out
}

func hasMutationKind(r Result, kind string) bool {
	for _, m := range r.Mutations {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

// repairWorked reports whether a repair was applied AND the case then carried
// traffic. Findings about the emitted config are gated on this: a repair that
// was attempted and did not help proves nothing about the thing it targeted,
// and claiming otherwise would put a defect in the report that the run did not
// actually demonstrate.
func repairWorked(r Result, kind string) bool {
	return hasMutationKind(r, kind) && r.TCP != nil && r.TCP.OK
}

// WriteJSON persists the machine-readable matrix.
func (r *Report) WriteJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "matrix.json")
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, append(b, '\n'), 0o644)
}

// Table renders the printed matrix.
func (r *Report) Table() string {
	var b strings.Builder
	hdr := fmt.Sprintf("%-46s %-9s %-8s %-5s %-5s %-5s  %s",
		"CASE", "ENGINE", "STATUS", "TCP", "UDP", "ACCT", "NOTE")
	b.WriteString(hdr + "\n")
	b.WriteString(strings.Repeat("-", len(hdr)+20) + "\n")
	for _, c := range r.Cases {
		b.WriteString(fmt.Sprintf("%-46s %-9s %-8s %-5s %-5s %-5s  %s\n",
			truncate(c.ID, 46), c.Engine, c.Status,
			mark(c.TCP != nil, c.TCP != nil && c.TCP.OK),
			mark(c.UDPRes != nil, c.UDPRes != nil && c.UDPRes.OK),
			mark(c.Accounting != nil, c.Accounting != nil && c.Accounting.OK),
			truncate(c.Reason, 110)))
	}
	b.WriteString(strings.Repeat("-", len(hdr)+20) + "\n")
	b.WriteString(fmt.Sprintf("total=%d  pass=%d  fail=%d  experimental=%d  unsupported=%d\n",
		r.Summary.Total, r.Summary.Pass, r.Summary.Fail, r.Summary.Experimental, r.Summary.Unsupported))
	if len(r.Findings) > 0 {
		b.WriteString("\nFINDINGS\n")
		for _, f := range r.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", strings.ToUpper(f.Severity), f.Title, f.ID))
			b.WriteString("      " + wrap(f.Detail, 100, "      ") + "\n")
			if len(f.Cases) > 0 {
				b.WriteString("      cases: " + truncate(strings.Join(f.Cases, ", "), 300) + "\n")
			}
		}
	}
	return b.String()
}

// WriteTable persists the printed matrix next to the JSON.
func (r *Report) WriteTable(dir string) (string, error) {
	p := filepath.Join(dir, "matrix.txt")
	return p, os.WriteFile(p, []byte(r.Table()), 0o644)
}

func mark(present, ok bool) string {
	switch {
	case !present:
		return " -  "
	case ok:
		return "PASS"
	default:
		return "FAIL"
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for _, w := range words {
		if line > 0 && line+len(w)+1 > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if line > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}
