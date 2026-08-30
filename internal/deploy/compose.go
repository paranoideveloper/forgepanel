// Package deploy generates deployment artifacts for the engines ForgePanel
// supervises. It is a PURE generator: every exported function returns text and
// nothing in this package talks to Docker, the network, or the filesystem.
// Running the output is always the operator's own explicit act.
//
// Why generate instead of shipping one static docker-compose.yml: which engines
// a panel needs is a function of which protocols its inbounds use (that mapping
// is render.EngineFor), exactly like an engine config is a function of
// model.Node. So the compose file is derived from the selection, and compose
// `profiles:` are used so that a service NEVER starts unless the operator names
// it -- `docker compose up` with no --profile starts nothing.
//
// Security posture, applied to EVERY generated service (spec §12/§14):
//
//   - `privileged:` is never emitted; there is no code path in this package that
//     can emit it, and no way for a caller to inject one.
//   - The Docker socket is never mounted. Nothing in the generated file can talk
//     to the daemon that runs it.
//   - `cap_drop: [ALL]` on every service. The ONLY capability this package can
//     add is NET_ADMIN, only on the Hysteria2 port-hopping service, and only
//     when the caller explicitly opts in (ComposeOpts.AllowNetAdmin).
//   - Privileged host ports are published onto UNprivileged container ports
//     (443->8443, 53->5353), so no service needs NET_BIND_SERVICE at all. This
//     is why capabilities can stay empty even for a :443 listener.
//   - The container root filesystem is read-only, the config directory is
//     mounted `:ro`, and the only writable paths are a named state volume and a
//     tmpfs /tmp.
//   - Images are pinned to the same engine versions binmgr installs, and can be
//     pinned further to an immutable digest (ComposeOpts.Digests).
package deploy

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// Profile names. These are both the compose service names and the values
// accepted in ?profiles=. They mirror render.EngineFor's engines plus the two
// deployment shapes that need their own container (the DNS-tunnel adapters and
// Hysteria2 port hopping).
const (
	ProfileXray            = "xray"
	ProfileSingbox         = "singbox"
	ProfileBrook           = "brook"
	ProfileStormDNS        = "stormdns"
	ProfileMasterDNS       = "masterdns"
	ProfileCottenDNS       = "cottendns"
	ProfileHysteriaPortHop = "hysteria-porthop"
)

// defaultHopRange is the Hysteria2 port-hopping range the panel's schema offers
// as its placeholder (internal/api/schema.go, "hysteria2.port_hopping").
const defaultHopRange = "20000-50000"

// The DNS-tunnel projects publish GitHub release archives, not container
// images, so their services run the ForgePanel image -- which is the component
// that fetches, pins and supervises those binaries
// (internal/forgedns/upstream). This is the locally built image the repo's own
// docker-compose.yml produces; pin it to a registry digest via
// ComposeOpts.Digests when deploying from a registry.
const (
	panelImageRepo = "forgepanel"
	panelImageTag  = "latest"
)

// ComposeOpts selects what to generate. The zero value generates nothing:
// Profiles must name at least one service.
type ComposeOpts struct {
	// Profiles are the services to include. Unknown names are an error rather
	// than a silent no-op, so a typo can never produce an empty deployment.
	Profiles []string

	// HostNetwork puts every service on the host network namespace. Port
	// publishing is then meaningless and is omitted; each engine binds the
	// CONTAINER-side port listed in the header directly on the host.
	HostNetwork bool

	// AllowNetAdmin opts the Hysteria2 port-hopping service into NET_ADMIN so it
	// can install the in-container DNAT rule that folds the hop range onto the
	// listen port. Without it the hop range is published as a port range, which
	// costs one userland proxy per port -- see the generated header.
	AllowNetAdmin bool

	// ConfigRoot is the host directory holding one config subdirectory per
	// service. It is emitted as a compose variable default, never as an absolute
	// path, so the file stays portable. Default "./config".
	ConfigRoot string

	// Images overrides the image reference (repo:tag) per profile, for operators
	// mirroring images into a private registry.
	Images map[string]string

	// Digests pins a profile's image to an immutable digest ("sha256:<64 hex>"),
	// which wins over the tag. Optional.
	Digests map[string]string
}

// Profiles lists every generatable profile, in the order they appear in output.
func Profiles() []string {
	return []string{
		ProfileXray, ProfileSingbox, ProfileBrook,
		ProfileStormDNS, ProfileMasterDNS, ProfileCottenDNS,
		ProfileHysteriaPortHop,
	}
}

// portSpec is one published port. Published may be a range ("20000-50000");
// Target is the container-side port the engine actually binds.
type portSpec struct {
	Published string
	Target    string
	Proto     string // tcp | udp
}

func (p portSpec) String() string { return p.Published + ":" + p.Target + "/" + p.Proto }

// engineSpec is everything needed to emit one service. Keeping it a table makes
// the security invariants auditable at a glance: NeedsNetAdmin is set on exactly
// one row, and nothing here can express a privileged container or a socket mount.
type engineSpec struct {
	Profile       string
	Image         string   // repository, no tag
	Tag           string   // pinned tag
	Command       []string // entrypoint args; secrets come from the environment
	Env           map[string]string
	Ports         []portSpec
	Health        []string
	NeedsNetAdmin bool
	Why           string // one-line rationale, emitted into the header
}

// specs is the per-profile table. Image tags come from binmgr's pinned versions
// so a container deployment runs the exact engine build the supervisor would
// install itself. Healthchecks invoke the engine's own version subcommand --
// the same liveness signal binmgr.verifyVersion uses -- because these runtime
// images are distroless and have no shell, curl or nc to probe a socket with.
// The image tags stay on binmgr's COMPILED constants even though an operator can
// now pin a different core version: compose generation deploys upstream
// container images and never goes through binmgr at all, so a panel-local pin
// has no bearing on which image tag is correct here.
func specs() map[string]engineSpec {
	return map[string]engineSpec{
		ProfileXray: {
			Profile: ProfileXray,
			Image:   "ghcr.io/xtls/xray-core", Tag: binmgr.XrayVersion,
			Command: []string{"run", "-c", "/etc/forgepanel/xray/config.json"},
			Ports: []portSpec{
				{"443", "8443", "tcp"},
				{"80", "8080", "tcp"},
			},
			Health: []string{"CMD", "xray", "version"},
			Why:    "VLESS/VMess/Trojan/Shadowsocks/SOCKS/HTTP inbounds (render.EngineFor -> xray).",
		},
		ProfileSingbox: {
			Profile: ProfileSingbox,
			Image:   "ghcr.io/sagernet/sing-box", Tag: "v" + binmgr.SingboxVersion,
			Command: []string{"run", "-c", "/etc/forgepanel/singbox/config.json"},
			Ports: []portSpec{
				{"8443", "8443", "tcp"},
				{"8443", "8443", "udp"},
			},
			Health: []string{"CMD", "sing-box", "version"},
			Why:    "Hysteria2/TUIC/AnyTLS/ShadowTLS/SSH/WireGuard inbounds (render.EngineFor -> sing-box). UDP is published because those protocols are QUIC/UDP based.",
		},
		ProfileBrook: {
			Profile: ProfileBrook,
			Image:   "txthinking/brook", Tag: binmgr.BrookVersion,
			// Brook takes its password on the command line; it is read from the
			// environment so no secret is ever written into the compose file.
			Command: []string{"server", "-l", ":9700", "-p", "${BROOK_PASSWORD:?set BROOK_PASSWORD}"},
			Ports: []portSpec{
				{"9700", "9700", "tcp"},
				{"9700", "9700", "udp"},
			},
			Health: []string{"CMD", "brook", "--version"},
			Why:    "Brook server; supervised as an external process only (GPL-3.0, docs/LICENSING.md). Relays UDP on the same port, so both protocols are published.",
		},
		ProfileStormDNS:  dnsSpec(ProfileStormDNS, "5301", "base64-in-TXT DNS tunnel"),
		ProfileMasterDNS: dnsSpec(ProfileMasterDNS, "5302", "base32-in-CNAME DNS tunnel"),
		ProfileCottenDNS: dnsSpec(ProfileCottenDNS, "53", "hex-in-A DNS tunnel; the default adapter, so it gets the host's :53"),
		ProfileHysteriaPortHop: {
			Profile: ProfileHysteriaPortHop,
			Image:   "ghcr.io/sagernet/sing-box", Tag: "v" + binmgr.SingboxVersion,
			Command: []string{"run", "-c", "/etc/forgepanel/hysteria-porthop/config.json"},
			Ports:   []portSpec{{"36712", "36712", "udp"}},
			Health:  []string{"CMD", "sing-box", "version"},
			// This is the ONLY row that may add a capability, and only on opt-in.
			// NET_ADMIN is what internal/core/porthop needs to install its
			// nftables/iptables redirect; without it that package degrades to
			// printing the commands for a human to run, which is why the
			// capability is opt-in rather than assumed.
			NeedsNetAdmin: true,
			Why:           "Hysteria2 with port hopping. UDP only. NET_ADMIN lets internal/core/porthop DNAT the hop range onto the listen port from inside the container instead of publishing tens of thousands of ports.",
		},
	}
}

// dnsSpec builds one DNS-tunnel adapter service. All three run the panel image:
// the upstream projects ship GitHub release archives rather than container
// images, and internal/forgedns/upstream is the component that fetches, pins,
// configures and supervises those binaries.
//
// Each adapter gets a DIFFERENT host port because a delegated zone points at a
// resolver on :53 and only one container can own the host's :53; the other two
// sit behind a host-level forwarder or their own address.
func dnsSpec(profile, hostPort, why string) engineSpec {
	return engineSpec{
		Profile: profile,
		Image:   panelImageRepo, Tag: panelImageTag,
		Env: map[string]string{
			"FORGEPANEL_DATA":     "/data",
			"FORGEPANEL_DNS_PORT": "5353",
		},
		Ports: []portSpec{
			{hostPort, "5353", "udp"},
			{hostPort, "5353", "tcp"},
		},
		// The runtime is distroless (no shell/curl), so liveness is a forgectl
		// invocation, exactly as in the repo's own docker-compose.yml. CottenDNS's
		// /healthz endpoint is polled by the panel, not by Docker.
		Health: []string{"CMD", "/usr/local/bin/forgectl", "keygen", "uuid"},
		Why:    why + " (adapter binary fetched + supervised by internal/forgedns/upstream).",
	}
}

// --- compose document ------------------------------------------------------

type composeHealth struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	Retries     int      `yaml:"retries"`
	StartPeriod string   `yaml:"start_period"`
}

// composeService deliberately has NO field for privileged mode, devices, pid
// namespace or userns -- an escalation cannot be expressed by this type.
type composeService struct {
	Image       string            `yaml:"image"`
	Profiles    []string          `yaml:"profiles"`
	Restart     string            `yaml:"restart"`
	NetworkMode string            `yaml:"network_mode,omitempty"`
	Ports       []string          `yaml:"ports,omitempty"`
	Command     []string          `yaml:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	Volumes     []string          `yaml:"volumes"`
	ReadOnly    bool              `yaml:"read_only"`
	Tmpfs       []string          `yaml:"tmpfs"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add,omitempty"`
	SecurityOpt []string          `yaml:"security_opt"`
	Healthcheck *composeHealth    `yaml:"healthcheck,omitempty"`
}

type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]struct{}       `yaml:"volumes"`
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imageRefRe keeps an operator-supplied override to the characters a registry
// reference can contain; input from an API query string is validated here at the
// boundary rather than trusted into the generated file.
var imageRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*(:[A-Za-z0-9._-]+)?$`)

// GenerateCompose renders a docker-compose.yml for the selected profiles. It
// returns an error for an empty or unknown selection, or a malformed override.
func GenerateCompose(opts ComposeOpts) (string, error) {
	table := specs()
	chosen, err := resolveProfiles(opts.Profiles, table)
	if err != nil {
		return "", err
	}
	configRoot := opts.ConfigRoot
	if strings.TrimSpace(configRoot) == "" {
		configRoot = "./config"
	}

	doc := composeFile{
		Name:     "forgepanel-engines",
		Services: map[string]composeService{},
		Volumes:  map[string]struct{}{},
	}
	for _, name := range chosen {
		sp := table[name]
		image, err := imageRef(sp, opts)
		if err != nil {
			return "", err
		}
		svc := composeService{
			Image:    image,
			Profiles: []string{name},
			Restart:  "unless-stopped",
			Command:  sp.Command,
			Volumes: []string{
				fmt.Sprintf("${FORGEPANEL_CONFIG_ROOT:-%s}/%s:/etc/forgepanel/%s:ro", configRoot, name, name),
				name + "-data:/data",
			},
			ReadOnly:    true,
			Tmpfs:       []string{"/tmp"},
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
			Healthcheck: &composeHealth{
				Test: sp.Health, Interval: "30s", Timeout: "5s", Retries: 3, StartPeriod: "10s",
			},
		}
		if len(sp.Env) > 0 {
			svc.Environment = sp.Env
		}
		if opts.HostNetwork {
			// network_mode: host and ports: are mutually exclusive in compose.
			svc.NetworkMode = "host"
		} else {
			for _, p := range publishedPorts(sp, opts) {
				svc.Ports = append(svc.Ports, p.String())
			}
		}
		if sp.NeedsNetAdmin && opts.AllowNetAdmin {
			svc.CapAdd = []string{"NET_ADMIN"}
		}
		doc.Services[name] = svc
		doc.Volumes[name+"-data"] = struct{}{}
	}

	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", fmt.Errorf("deploy: encode compose: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("deploy: encode compose: %w", err)
	}
	return header(chosen, table, opts) + sb.String(), nil
}

// publishedPorts returns the port mappings for a service. The port-hopping
// service is the one place where the mapping depends on a capability: with
// NET_ADMIN it publishes only its listen port and folds the hop range in with a
// DNAT rule; without it the range must be published, which is expensive.
func publishedPorts(sp engineSpec, opts ComposeOpts) []portSpec {
	out := append([]portSpec(nil), sp.Ports...)
	if sp.Profile == ProfileHysteriaPortHop && !opts.AllowNetAdmin {
		out = append(out, portSpec{defaultHopRange, defaultHopRange, "udp"})
	}
	return out
}

// imageRef resolves the final image reference: an explicit override wins over
// the pinned tag, and a digest wins over both.
func imageRef(sp engineSpec, opts ComposeOpts) (string, error) {
	ref := sp.Image + ":" + sp.Tag
	if o, ok := opts.Images[sp.Profile]; ok {
		o = strings.TrimSpace(o)
		if !imageRefRe.MatchString(o) {
			return "", fmt.Errorf("deploy: invalid image override for %q", sp.Profile)
		}
		ref = o
	}
	if d, ok := opts.Digests[sp.Profile]; ok {
		d = strings.TrimSpace(d)
		if !digestRe.MatchString(d) {
			return "", fmt.Errorf("deploy: invalid image digest for %q (want sha256:<64 hex>)", sp.Profile)
		}
		repo := ref
		if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
			repo = ref[:i]
		}
		ref = repo + "@" + d
	}
	return ref, nil
}

// resolveProfiles validates, de-duplicates and orders the selection.
func resolveProfiles(want []string, table map[string]engineSpec) ([]string, error) {
	seen := map[string]bool{}
	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		if _, ok := table[w]; !ok {
			return nil, fmt.Errorf("deploy: unknown profile %q (valid: %s)", w, strings.Join(Profiles(), ", "))
		}
		seen[w] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("deploy: no profiles selected (valid: %s)", strings.Join(Profiles(), ", "))
	}
	var out []string
	for _, p := range Profiles() { // Profiles() order, not caller order
		if seen[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// header explains the file to whoever opens it: what each selected service is
// for, which ports it needs, and the security decisions that are deliberate.
func header(chosen []string, table map[string]engineSpec, opts ComposeOpts) string {
	var b strings.Builder
	b.WriteString("# Generated by ForgePanel (internal/deploy). Review before running.\n")
	b.WriteString("# Nothing starts by default -- every service is behind a compose profile:\n")
	b.WriteString("#   docker compose --profile " + strings.Join(chosen, " --profile ") + " up -d\n#\n")
	b.WriteString("# Hardening applied to every service:\n")
	b.WriteString("#   * no privileged mode, no docker socket mount, no host devices\n")
	b.WriteString("#   * cap_drop: ALL + no-new-privileges; read-only rootfs; config mounted :ro\n")
	b.WriteString("#   * privileged host ports map onto unprivileged container ports, so no\n")
	b.WriteString("#     service needs NET_BIND_SERVICE -- configure each engine to LISTEN on the\n")
	b.WriteString("#     container-side port shown below, not on the host-side port\n")
	b.WriteString("#   * images pinned to the versions internal/core/binmgr installs\n#\n")
	if opts.HostNetwork {
		b.WriteString("# HOST NETWORKING is on: port publishing is omitted and each engine binds the\n")
		b.WriteString("# container-side port directly on the host.\n#\n")
	}
	for _, name := range chosen {
		sp := table[name]
		b.WriteString("# " + name + ": " + sp.Why + "\n")
		var ports []string
		for _, p := range publishedPorts(sp, opts) {
			ports = append(ports, p.Published+"->"+p.Target+"/"+p.Proto)
		}
		b.WriteString("#   ports: " + strings.Join(ports, ", ") + "\n")
		b.WriteString("#   config: mount the engine config at /etc/forgepanel/" + name + " (read-only)\n")
	}
	if hasProfile(chosen, ProfileHysteriaPortHop) {
		b.WriteString("#\n")
		if opts.AllowNetAdmin {
			b.WriteString("# NET_ADMIN is granted to " + ProfileHysteriaPortHop + " ONLY. It is required for the\n")
			b.WriteString("# in-container DNAT rule (internal/core/porthop) that redirects the\n")
			b.WriteString("# " + defaultHopRange + "/udp hop range onto the listen port. Revoke it by regenerating\n")
			b.WriteString("# without the net_admin option.\n")
		} else {
			b.WriteString("# NET_ADMIN was NOT granted, so the " + defaultHopRange + "/udp hop range is published\n")
			b.WriteString("# directly. Docker starts one userland proxy per port in that range; prefer\n")
			b.WriteString("# host networking, or opt into NET_ADMIN and DNAT the range in-container.\n")
		}
	}
	b.WriteString("\n")
	return b.String()
}

func hasProfile(chosen []string, want string) bool {
	for _, c := range chosen {
		if c == want {
			return true
		}
	}
	return false
}
