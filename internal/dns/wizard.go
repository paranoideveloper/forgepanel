package dns

import (
	"time"
)

// ProtocolPlan describes one inbound the wizard should provision a hostname
// for. The proxy decision is per-protocol because it is not a preference: a
// WebSocket or XHTTP inbound wants the CDN in front of it, and a REALITY or
// Hysteria2 inbound is destroyed by it.
type ProtocolPlan struct {
	// Proto feeds {proto} in the naming template, e.g. "ws", "reality", "hy2".
	Proto string `json:"proto"`
	// Port is the inbound's listening port, used for the traffic proof.
	Port int `json:"port"`
	// Proxied requests the CDN orange cloud for this hostname.
	Proxied bool `json:"proxied"`
	// TLS is false for a transport that does not terminate TLS on TCP (a UDP
	// protocol such as Hysteria2 or TUIC), which changes how it is proven.
	TLS bool `json:"tls"`
	// UDP marks a protocol whose datagram listener cannot be proven with a TCP
	// handshake.
	UDP bool `json:"udp"`
	// Hostname overrides the generated name when the operator already has one.
	Hostname string `json:"hostname,omitempty"`
}

// DefaultProtocolPlans is the shipped inbound set: the CDN-friendly transports
// behind the orange cloud, the handshake-sensitive ones direct.
func DefaultProtocolPlans() []ProtocolPlan {
	return []ProtocolPlan{
		{Proto: "ws", Port: 443, Proxied: true, TLS: true},
		{Proto: "xhttp", Port: 443, Proxied: true, TLS: true},
		{Proto: "grpc", Port: 443, Proxied: true, TLS: true},
		{Proto: "reality", Port: 443, Proxied: false, TLS: true},
		{Proto: "vision", Port: 8443, Proxied: false, TLS: true},
		{Proto: "hy2", Port: 8443, Proxied: false, TLS: true, UDP: true},
	}
}

// WizardConfig drives an end-to-end provisioning run.
type WizardConfig struct {
	// Provider is the DNS backend. Required unless SkipDNS is set.
	Provider Provider
	// Domain is the parent the hostnames are created under. Required.
	Domain string
	// OriginIP is the server the records point at. Required unless SkipDNS.
	OriginIP string
	// Template names the generated hostnames.
	Template string
	// Node feeds {node} in the template.
	Node string
	// Region feeds {region}.
	Region string
	// Protocols is the inbound set. Empty uses DefaultProtocolPlans.
	Protocols []ProtocolPlan
	// TTL for created records.
	TTL int
	// Settings is the zone configuration to apply. Nil uses
	// RecommendedZoneSettings when the provider supports it.
	Settings *ZoneSettings
	// SkipDNS provisions nothing and only verifies existing hostnames, which is
	// the path for a provider with no implemented backend.
	SkipDNS bool
	// SkipSettings leaves zone settings alone.
	SkipSettings bool
	// SkipPreflight skips ACME readiness.
	SkipPreflight bool
	// Challenge is the ACME challenge preflight targets.
	Challenge ChallengeType
	// Preflight overrides the readiness checker.
	Preflight *Preflight
	// Resolver is used for delegation and readiness checks.
	Resolver Resolver
	// Scan, when non-nil, runs a clean-IP scan for the proxied hostnames.
	Scan *ScanConfig
	// CleanIPs receives the scan result.
	CleanIPs CleanIPRepo
	// Prober proves traffic reaches each inbound. Nil means TLSProber.
	Prober Prober
	// SkipTrafficProof skips the final connectivity proof.
	SkipTrafficProof bool
	// DNSPropagationWait is how long to wait for a freshly written record to
	// appear in public DNS before the checks that depend on it. Zero means 45s;
	// negative means do not wait.
	DNSPropagationWait time.Duration
	// PollInterval is how often propagation is re-checked. Zero means 3s.
	PollInterval time.Duration
	// Now is injectable for deterministic tests.
	Now func() time.Time
	// Sleep is injectable so tests do not actually wait.
	Sleep func(time.Duration)
}

// RecommendedZoneSettings is the edge configuration a TLS inbound behind a CDN
// needs: strict origin-pull so the edge verifies the origin certificate,
// TLS 1.2 floor, and the WebSocket and gRPC switches that transports depend on.
func RecommendedZoneSettings() ZoneSettings {
	strict := TLSFullStrict
	on := true
	minTLS := "1.2"
	return ZoneSettings{
		SSL:            &strict,
		AlwaysUseHTTPS: &on,
		MinTLSVersion:  &minTLS,
		TLS13:          &on,
		GRPC:           &on,
		WebSockets:     &on,
	}
}

// StepStatus is one wizard step's outcome.
type StepStatus string

// Step outcomes.
const (
	StepOK      StepStatus = "ok"
	StepSkipped StepStatus = "skipped"
	StepWarn    StepStatus = "warn"
	StepFailed  StepStatus = "failed"
)

// Step is one stage of a provisioning run.
type Step struct {
	Name        string     `json:"name"`
	Status      StepStatus `json:"status"`
	Detail      string     `json:"detail,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Elapsed     string     `json:"elapsed,omitempty"`
}

// Endpoint is one provisioned inbound hostname and everything a client needs to
// reach it.
type Endpoint struct {
	Proto string `json:"proto"`
	// Host is the hostname: the value of both sni and host in a client config.
	Host string `json:"host"`
	Port int    `json:"port"`
	// Address is what the client actually dials. For a proxied hostname this is
	// a verified clean edge IP; otherwise it is the hostname itself.
	Address  string `json:"address"`
	Proxied  bool   `json:"proxied"`
	RecordID string `json:"record_id,omitempty"`
	Action   string `json:"action,omitempty"`
	// Proven is true when a real connection to this endpoint succeeded.
	Proven      bool   `json:"proven"`
	ProofDetail string `json:"proof_detail,omitempty"`
}

// WizardReport is the full outcome of a run.
type WizardReport struct {
	Domain    string            `json:"domain"`
	Provider  string            `json:"provider,omitempty"`
	Zone      *ZoneResolution   `json:"zone,omitempty"`
	Identity  *Identity         `json:"identity,omitempty"`
	Steps     []Step            `json:"steps"`
	Records   []EnsureResult    `json:"records,omitempty"`
	Settings  []SettingResult   `json:"zone_settings,omitempty"`
	Preflight []PreflightReport `json:"preflight,omitempty"`
	CleanIPs  *CleanIPSet       `json:"clean_ips,omitempty"`
	Endpoints []Endpoint        `json:"endpoints"`
	OK        bool              `json:"ok"`
	StartedAt string            `json:"started_at"`
	Duration  string            `json:"duration"`
}

// Failures returns the steps that failed.
func (r *WizardReport) Failures() []Step {
	var out []Step
	for _, s := range r.Steps {
		if s.Status == StepFailed {
			out = append(out, s)
		}
	}
	return out
}

func (c WizardConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c WizardConfig) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (c WizardConfig) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return NewResolver()
}
