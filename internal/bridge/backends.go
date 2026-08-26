// Package bridge manages reverse-tunnel backends: the hop that lets a client
// inside Iran reach a server outside it.
//
// The shape is always the same. A machine users can reach — a domestic VPS, a
// cheap box on an ISP that is not blocked — accepts connections and forwards
// them over a single outbound tunnel to the real server abroad. The exit never
// takes an inbound connection from Iran, so blocking its address achieves
// nothing, and the bridge holds no credentials worth stealing.
//
// Nothing in ForgePanel did this. There was no reverse-tunnel management
// anywhere: no installer, no supervision, no config generation, no way to say
// "this inbound is reached through that bridge".
//
// # Why UDP is the deciding property
//
// Hysteria2, TUIC and WireGuard are UDP. A bridge that carries only TCP quietly
// drops exactly the protocols that work best against Iranian DPI, and the
// failure is invisible from the panel: the inbound is up, the bridge is up, and
// clients simply never connect. Every backend here was checked against its own
// binary for UDP before being offered.
package bridge

import (
	"fmt"
	"sort"
	"strings"
)

// Backend is one reverse-tunnel implementation.
type Backend struct {
	// Name is the panel-facing key.
	Name string `json:"name"`
	// Title is what an operator reads.
	Title string `json:"title"`
	// Owner/Repo locate the GitHub releases.
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	// AssetPattern matches the linux/amd64 release asset. %s is the version
	// with any leading "v" stripped, because these projects disagree about it.
	AssetPattern string `json:"asset_pattern"`
	// Exe is the binary inside the archive.
	Exe string `json:"exe"`
	// PeerExe is a second binary when the two sides are different programs, as
	// frp's frps/frpc are. Empty when one binary does both.
	PeerExe string `json:"peer_exe,omitempty"`
	// PinnedVersion is the release this panel renders configs for. Pinned
	// rather than "latest" because these tools change their config schema
	// between minor versions — frp moved from INI to TOML, rathole changed
	// hands and org — and a config rendered for the wrong version is rejected
	// at startup, taking the bridge down with no obvious cause.
	PinnedVersion string `json:"pinned_version"`

	// SHA256 is the pinned asset's digest, computed from the downloaded file on
	// 2026-08-26.
	//
	// A release asset is a binary this panel is about to run as root on a
	// machine the operator may not be sitting at. Pinning the digest means a
	// replaced asset — a compromised release, a mirror that lies, a truncated
	// download — fails the install instead of running.
	SHA256 string `json:"sha256"`

	// CarriesUDP means the backend forwards UDP as well as TCP.
	//
	// Verified against the tool's own binary, never assumed — see the table in
	// backends_verified.md. A backend that cannot carry UDP silently breaks
	// Hysteria2, TUIC and WireGuard while looking healthy.
	CarriesUDP bool `json:"carries_udp"`
	// ConfigFormat is "toml" for a config file, "args" for a CLI-only tool.
	ConfigFormat string `json:"config_format"`
	// VerifyArgs runs the tool's own config check, when it has one. Empty when
	// the tool validates only by starting.
	VerifyArgs []string `json:"verify_args,omitempty"`
	// MutatesSysctl warns that starting the tool changes host networking.
	MutatesSysctl bool `json:"mutates_sysctl,omitempty"`
	// Notes is operator-facing detail that decides whether this is the right
	// backend, not marketing.
	Notes string `json:"notes"`
}

// backends is the registry.
//
// Every field below was checked against the real binary on 2026-08-26; the
// commands and their output are recorded in backends_verified.md so the next
// person can re-run them rather than trust this comment.
var backends = map[string]Backend{
	"backhaul": {
		Name: "backhaul", Title: "Backhaul",
		Owner: "Musixal", Repo: "Backhaul",
		AssetPattern: "backhaul_linux_amd64.tar.gz", Exe: "backhaul",
		PinnedVersion: "v0.7.2",
		SHA256:        "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc",
		CarriesUDP:    true, ConfigFormat: "toml",
		MutatesSysctl: true,
		Notes: "Built for this exact problem and the most widely used inside Iran. " +
			"Transports: tcp, tcpmux, ws, wss, wsmux, udp. NOTE: it raises the host's " +
			"rmem_max/wmem_max on start — verified in its own log — so it changes " +
			"networking for everything else on that machine, not just itself.",
	},
	"rathole": {
		Name: "rathole", Title: "rathole",
		// The project moved orgs; rapiz1/rathole redirects. Following a redirect
		// silently would work until it stops, so the current home is named.
		Owner: "rathole-org", Repo: "rathole",
		AssetPattern: "rathole-x86_64-unknown-linux-gnu.zip", Exe: "rathole",
		PinnedVersion: "v0.5.0",
		SHA256:        "3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e",
		CarriesUDP:    true, ConfigFormat: "toml",
		Notes: "Small, fast and strict: it rejects a config with an unknown key rather " +
			"than ignoring it, so a typo fails loudly at start instead of silently " +
			"disabling a service. Per-service tcp/udp.",
	},
	"frp": {
		Name: "frp", Title: "frp",
		Owner: "fatedier", Repo: "frp",
		AssetPattern: "frp_%s_linux_amd64.tar.gz", Exe: "frps", PeerExe: "frpc",
		PinnedVersion: "v0.71.0",
		SHA256:        "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716",
		CarriesUDP:    true, ConfigFormat: "toml",
		// The only one of the four that can check a config without starting.
		VerifyArgs: []string{"verify", "-c"},
		Notes: "The most mature, and the only one that validates a config without " +
			"starting (`frps verify -c`). Two binaries: frps on the exit, frpc on the " +
			"bridge. Per-proxy tcp/udp.",
	},
	"wstunnel": {
		Name: "wstunnel", Title: "wstunnel",
		Owner: "erebe", Repo: "wstunnel",
		AssetPattern: "wstunnel_%s_linux_amd64.tar.gz", Exe: "wstunnel",
		PinnedVersion: "v10.6.2",
		SHA256:        "db6064cca0515b67f8652e201cff8e27553b8cbb7216b2e19241311e34868e6e",
		CarriesUDP:    true, ConfigFormat: "args",
		Notes: "Tunnels over WebSocket or HTTP/2, so the hop looks like ordinary web " +
			"traffic and survives a CDN or an HTTP proxy in the path. Configured " +
			"entirely by flags, no config file.",
	},
}

// Names lists the registered backends, sorted for stable output.
func Names() []string {
	out := make([]string, 0, len(backends))
	for k := range backends {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// All returns every backend, sorted by name.
func All() []Backend {
	out := make([]Backend, 0, len(backends))
	for _, n := range Names() {
		out = append(out, backends[n])
	}
	return out
}

// Get resolves a backend by name.
func Get(name string) (Backend, error) {
	b, ok := backends[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Backend{}, fmt.Errorf("bridge: unknown backend %q — available: %s",
			name, strings.Join(Names(), ", "))
	}
	return b, nil
}

// Asset is the release asset filename for this backend's pinned version.
func (b Backend) Asset() string {
	if !strings.Contains(b.AssetPattern, "%s") {
		return b.AssetPattern
	}
	return fmt.Sprintf(b.AssetPattern, strings.TrimPrefix(b.PinnedVersion, "v"))
}

// DownloadURL is where the pinned asset lives.
func (b Backend) DownloadURL() string {
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s",
		b.Owner, b.Repo, b.PinnedVersion, b.Asset())
}
