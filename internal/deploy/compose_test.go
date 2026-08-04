package deploy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/forgepanel/forgepanel/internal/core/binmgr"
)

// parsed is the shape the tests assert against. It is deliberately a loose,
// separate type: parsing the generated text back with an INDEPENDENT struct
// proves the output is real YAML and really carries the keys, rather than just
// echoing the generator's own types.
type parsed struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Profiles    []string          `yaml:"profiles"`
		Restart     string            `yaml:"restart"`
		NetworkMode string            `yaml:"network_mode"`
		Ports       []string          `yaml:"ports"`
		Volumes     []string          `yaml:"volumes"`
		ReadOnly    bool              `yaml:"read_only"`
		CapDrop     []string          `yaml:"cap_drop"`
		CapAdd      []string          `yaml:"cap_add"`
		SecurityOpt []string          `yaml:"security_opt"`
		Privileged  *bool             `yaml:"privileged"`
		Environment map[string]string `yaml:"environment"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

func mustGenerate(t *testing.T, opts ComposeOpts) (string, parsed) {
	t.Helper()
	out, err := GenerateCompose(opts)
	if err != nil {
		t.Fatalf("GenerateCompose: %v", err)
	}
	var p parsed
	if err := yaml.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("generated compose is not valid YAML: %v\n---\n%s", err, out)
	}
	return out, p
}

// TestComposeXrayAndPortHop is the acceptance test for the generator's security
// posture: nothing privileged, no docker socket, one capability on exactly one
// service, and UDP published for the QUIC-based hop service.
func TestComposeXrayAndPortHop(t *testing.T) {
	raw, doc := mustGenerate(t, ComposeOpts{
		Profiles: []string{ProfileXray, ProfileHysteriaPortHop},
	})

	if len(doc.Services) != 2 {
		t.Fatalf("want 2 services, got %d: %v", len(doc.Services), doc.Services)
	}
	for _, want := range []string{ProfileXray, ProfileHysteriaPortHop} {
		if _, ok := doc.Services[want]; !ok {
			t.Fatalf("service %q missing from generated compose", want)
		}
	}

	// No privileged mode anywhere -- neither as a parsed key nor as a raw line.
	// The header prose legitimately says "privileged host ports", so this looks
	// for the compose KEY on a non-comment line.
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "privileged:") {
			t.Errorf("generated compose sets privileged: %q", line)
		}
	}
	// No docker socket mount: the file must not be able to control its own daemon.
	for name, svc := range doc.Services {
		if svc.Privileged != nil {
			t.Errorf("%s: privileged key present", name)
		}
		for _, v := range svc.Volumes {
			if strings.Contains(v, "docker.sock") || strings.HasPrefix(v, "/var/run/docker") {
				t.Errorf("%s: docker socket mounted: %q", name, v)
			}
		}
	}

	// Capabilities: ALL dropped everywhere, NET_ADMIN nowhere unless opted in.
	for name, svc := range doc.Services {
		if len(svc.CapDrop) != 1 || svc.CapDrop[0] != "ALL" {
			t.Errorf("%s: want cap_drop [ALL], got %v", name, svc.CapDrop)
		}
		if len(svc.CapAdd) != 0 {
			t.Errorf("%s: no capability may be added without AllowNetAdmin, got %v", name, svc.CapAdd)
		}
		if !svc.ReadOnly {
			t.Errorf("%s: want a read-only root filesystem", name)
		}
		if svc.Restart != "unless-stopped" {
			t.Errorf("%s: want a restart policy, got %q", name, svc.Restart)
		}
		if len(svc.Healthcheck.Test) == 0 {
			t.Errorf("%s: want a healthcheck", name)
		}
		if len(svc.Profiles) != 1 || svc.Profiles[0] != name {
			t.Errorf("%s: want profiles [%s] so nothing runs unless selected, got %v", name, name, svc.Profiles)
		}
		// Config must be mounted read-only, state on a named volume.
		var roConfig, dataVol bool
		for _, v := range svc.Volumes {
			if strings.Contains(v, "/etc/forgepanel/"+name) && strings.HasSuffix(v, ":ro") {
				roConfig = true
			}
			if v == name+"-data:/data" {
				dataVol = true
			}
		}
		if !roConfig {
			t.Errorf("%s: config is not mounted read-only: %v", name, svc.Volumes)
		}
		if !dataVol {
			t.Errorf("%s: no persistent state volume: %v", name, svc.Volumes)
		}
		if _, ok := doc.Volumes[name+"-data"]; !ok {
			t.Errorf("%s: state volume not declared at the top level", name)
		}
	}

	// The hop service is UDP; without NET_ADMIN the hop range is published too.
	hop := doc.Services[ProfileHysteriaPortHop]
	var haveUDP, haveRange bool
	for _, p := range hop.Ports {
		if strings.HasSuffix(p, "/udp") {
			haveUDP = true
		}
		if strings.Contains(p, defaultHopRange) {
			haveRange = true
		}
		if strings.HasSuffix(p, "/tcp") {
			t.Errorf("%s: Hysteria2 is UDP only, got a TCP mapping %q", ProfileHysteriaPortHop, p)
		}
	}
	if !haveUDP {
		t.Errorf("%s: no UDP port published: %v", ProfileHysteriaPortHop, hop.Ports)
	}
	if !haveRange {
		t.Errorf("%s: without NET_ADMIN the hop range must be published: %v", ProfileHysteriaPortHop, hop.Ports)
	}

	// Images are pinned to the versions binmgr installs.
	if got := doc.Services[ProfileXray].Image; !strings.HasSuffix(got, binmgr.XrayVersion) {
		t.Errorf("xray image %q is not pinned to %s", got, binmgr.XrayVersion)
	}
	if got := hop.Image; !strings.HasSuffix(got, binmgr.SingboxVersion) {
		t.Errorf("port-hop image %q is not pinned to sing-box %s", got, binmgr.SingboxVersion)
	}
	// Privileged host ports must land on unprivileged container ports, which is
	// what makes cap_drop: ALL survivable for a :443 listener.
	for _, p := range doc.Services[ProfileXray].Ports {
		if strings.HasPrefix(p, "443:") && !strings.HasPrefix(p, "443:8443") {
			t.Errorf("xray: :443 must map to an unprivileged container port, got %q", p)
		}
	}
}

// TestComposeNetAdminIsOptInAndScoped proves the one capability the generator
// can emit is both opt-in and confined to the port-hopping service.
func TestComposeNetAdminIsOptInAndScoped(t *testing.T) {
	_, doc := mustGenerate(t, ComposeOpts{
		Profiles:      []string{ProfileXray, ProfileSingbox, ProfileBrook, ProfileHysteriaPortHop},
		AllowNetAdmin: true,
	})
	for name, svc := range doc.Services {
		switch name {
		case ProfileHysteriaPortHop:
			if len(svc.CapAdd) != 1 || svc.CapAdd[0] != "NET_ADMIN" {
				t.Errorf("%s: want cap_add [NET_ADMIN], got %v", name, svc.CapAdd)
			}
		default:
			if len(svc.CapAdd) != 0 {
				t.Errorf("%s: must not gain a capability, got %v", name, svc.CapAdd)
			}
		}
		if len(svc.SecurityOpt) == 0 || svc.SecurityOpt[0] != "no-new-privileges:true" {
			t.Errorf("%s: want no-new-privileges, got %v", name, svc.SecurityOpt)
		}
	}
	// With NET_ADMIN the hop range is DNAT'd in-container, not published.
	for _, p := range doc.Services[ProfileHysteriaPortHop].Ports {
		if strings.Contains(p, defaultHopRange) {
			t.Errorf("with NET_ADMIN the hop range should not be published, got %q", p)
		}
	}
}

// TestComposeSecretsNeverInlined checks the one service that takes a credential
// on its command line reads it from the environment instead.
func TestComposeSecretsNeverInlined(t *testing.T) {
	raw, _ := mustGenerate(t, ComposeOpts{Profiles: []string{ProfileBrook}})
	if !strings.Contains(raw, "${BROOK_PASSWORD") {
		t.Error("brook password must come from the environment")
	}
}

func TestComposeHostNetworkDropsPortPublishing(t *testing.T) {
	_, doc := mustGenerate(t, ComposeOpts{Profiles: []string{ProfileSingbox}, HostNetwork: true})
	svc := doc.Services[ProfileSingbox]
	if svc.NetworkMode != "host" {
		t.Errorf("want network_mode host, got %q", svc.NetworkMode)
	}
	if len(svc.Ports) != 0 {
		t.Errorf("ports: and network_mode: host are mutually exclusive, got %v", svc.Ports)
	}
}

func TestComposeDNSProfilesGetDistinctHostPorts(t *testing.T) {
	_, doc := mustGenerate(t, ComposeOpts{
		Profiles: []string{ProfileStormDNS, ProfileMasterDNS, ProfileCottenDNS},
	})
	seen := map[string]string{}
	for name, svc := range doc.Services {
		for _, p := range svc.Ports {
			host := strings.SplitN(p, ":", 2)[0]
			key := host + "/" + p[strings.LastIndex(p, "/")+1:]
			if other, dup := seen[key]; dup {
				t.Errorf("%s and %s both claim host port %s", name, other, key)
			}
			seen[key] = name
		}
		if svc.Environment["FORGEPANEL_DNS_PORT"] != "5353" {
			t.Errorf("%s: DNS should bind an unprivileged container port, got %q", name, svc.Environment["FORGEPANEL_DNS_PORT"])
		}
	}
}

func TestComposeDigestPinning(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	_, doc := mustGenerate(t, ComposeOpts{
		Profiles: []string{ProfileXray},
		Digests:  map[string]string{ProfileXray: digest},
	})
	if got := doc.Services[ProfileXray].Image; got != "ghcr.io/xtls/xray-core@"+digest {
		t.Errorf("digest not applied: %q", got)
	}
	if _, err := GenerateCompose(ComposeOpts{
		Profiles: []string{ProfileXray},
		Digests:  map[string]string{ProfileXray: "not-a-digest"},
	}); err == nil {
		t.Error("want an error for a malformed digest")
	}
	if _, err := GenerateCompose(ComposeOpts{
		Profiles: []string{ProfileXray},
		Images:   map[string]string{ProfileXray: "evil image\nprivileged: true"},
	}); err == nil {
		t.Error("want an error for a malformed image override")
	}
}

func TestComposeRejectsEmptyAndUnknownProfiles(t *testing.T) {
	if _, err := GenerateCompose(ComposeOpts{}); err == nil {
		t.Error("want an error when no profile is selected")
	}
	if _, err := GenerateCompose(ComposeOpts{Profiles: []string{"xray", "nope"}}); err == nil {
		t.Error("want an error for an unknown profile")
	}
	// Every profile must be generatable on its own.
	for _, p := range Profiles() {
		if _, err := GenerateCompose(ComposeOpts{Profiles: []string{p}}); err != nil {
			t.Errorf("profile %q: %v", p, err)
		}
	}
}
