// Package upstream wires the real DNS-tunnel server binaries — StormDNS,
// MasterDnsVPN and CottenDNS — into the panel as supervised external processes.
//
// Why one package for what look like three protocols: per
// docs/FORGEDNS_UPSTREAM_SETUP.md §0, the three projects are a single Go/MIT
// codebase family (StormDNS and CottenDNS are both forks of MasterDnsVPN). They
// share one TOML config dialect, one release layout and one on-wire model, and
// differ only in their CONFIG_VERSION and in which keys that version knows. So
// this is ONE integration parameterised by the per-adapter Descriptor table
// below (§4a), not three implementations. The panel never reimplements the wire
// protocol — it fetches, configures and supervises the upstream binary.
//
// The panel's own `internal/forgedns/{codec,adapter,session,server}` subsystem
// is unaffected: it remains the `native` (a.k.a. `forge`) zone path.
package upstream

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// Adapter names. These are the values stored in ForgeDNSZone.Adapter that select
// a real upstream binary; anything else (`forge`, `native`, empty) stays on the
// panel-native path.
const (
	AdapterStormDNS  = "stormdns"
	AdapterMasterDNS = "masterdns"
	AdapterCottenDNS = "cottendns"
)

// DefaultAdapter is what new zones get (§4e): CottenDNS is the most actively
// maintained fork, is the only one with a health/metrics endpoint the panel can
// poll, has the richest anti-fingerprinting knobs (QUERY_TYPES rotation), and
// its multi-domain-per-server support maps onto the panel's multi-zone model.
const DefaultAdapter = AdapterCottenDNS

// Descriptor is everything the panel needs to install, configure and supervise
// one upstream tool. Every field is taken verbatim from the verified table in
// docs/FORGEDNS_UPSTREAM_SETUP.md §4a and the per-tool sections §1–§3.
type Descriptor struct {
	Adapter string `json:"adapter"`
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`

	// Project is the release-asset basename prefix. Note the casing trap (§0):
	// the CottenDNS *repo* is `CottenDNS` but its *assets* are spelled
	// `CottenDns_…` with a lower-case "ns".
	Project string `json:"project"`

	// ConfigVersion must be stamped into every rendered config: these binaries
	// reject a file whose CONFIG_VERSION they do not recognise (§4b).
	ConfigVersion string `json:"config_version"`

	// DefaultCipher is the DATA_ENCRYPTION_METHOD the upstream ships with
	// (0=None 1=XOR 2=ChaCha20 3=AES128 4=AES192 5=AES256-GCM).
	DefaultCipher int `json:"default_cipher"`

	// Capability flags decide which keys the renderer may emit. §4b: "only fill
	// the keys that adapter version knows" — an unknown key risks a rejected
	// config, so a flag is false unless the doc verifies the key for that tool.
	HasListenerToggles bool `json:"has_listener_toggles"`   // TCP_/DOT_/DOH_LISTENER_ENABLED (§3)
	HasAutoDetect      bool `json:"has_auto_detect"`        // ENCRYPTION_AUTO_DETECT (§3)
	HasARecordDelivery bool `json:"has_a_record_delivery"`  // A_RECORD_DATA_DELIVERY (§3)
	HasQueryTypes      bool `json:"has_query_types"`        // client-side QUERY_TYPES rotation (§3)
	HasResolverTransp  bool `json:"has_resolver_transport"` // client RESOLVER_TRANSPORT (§3)
	HasCompression     bool `json:"has_compression"`        // UPLOAD/DOWNLOAD_COMPRESSION_TYPE (§2,§3)
	HasBalancing       bool `json:"has_balancing"`          // RESOLVER_BALANCING_STRATEGY (§2)

	// HealthURL is the tool's own health endpoint, empty when it has none.
	// Only CottenDNS exposes one (§3: 127.0.0.1:9090 health + Prometheus); for
	// the other two the supervisor falls back to process liveness + logs (§4c).
	HealthURL string `json:"health_url,omitempty"`

	// Notes is UI-facing prose explaining what picking this adapter means.
	Notes string `json:"notes"`
}

// descriptors is the per-adapter table (§4a). Values are verbatim from the doc.
var descriptors = map[string]Descriptor{
	AdapterStormDNS: {
		Adapter: AdapterStormDNS, Owner: "nullroute1970", Repo: "StormDNS",
		Project: "StormDNS", ConfigVersion: "10", DefaultCipher: 1,
		HasCompression: true, HasBalancing: true,
		Notes: "Derivative of MasterDnsVPN. Lean key set, no health endpoint; " +
			"supervision falls back to process liveness and logs.",
	},
	AdapterMasterDNS: {
		Adapter: AdapterMasterDNS, Owner: "masterking32", Repo: "MasterDnsVPN",
		Project: "MasterDnsVPN", ConfigVersion: "12", DefaultCipher: 1,
		Notes: "The upstream original (~6.9k stars). Compatibility adapter for " +
			"operators who already delegated to it or run its client.",
	},
	AdapterCottenDNS: {
		Adapter: AdapterCottenDNS, Owner: "WhiteDNS", Repo: "CottenDNS",
		Project: "CottenDns", ConfigVersion: "14", DefaultCipher: 3,
		HasListenerToggles: true, HasAutoDetect: true, HasARecordDelivery: true,
		HasQueryTypes: true, HasResolverTransp: true, HasCompression: true,
		HealthURL: "http://127.0.0.1:9090/healthz",
		Notes: "Newest fork, backs the WhiteDNS-Android client. Serves MANY tunnel " +
			"domains from one instance (DOMAIN is an array) provided every listed " +
			"domain is delegated to this same server. Adds DoT/DoH listeners, " +
			"QUERY_TYPES rotation and a Prometheus/health endpoint.",
	},
}

// order fixes the UI listing order (most recommended first).
var order = []string{AdapterCottenDNS, AdapterStormDNS, AdapterMasterDNS}

// Lookup returns the descriptor for an adapter name (case-insensitive).
func Lookup(name string) (Descriptor, error) {
	d, ok := descriptors[Canonical(name)]
	if !ok {
		return Descriptor{}, fmt.Errorf("forgedns upstream: %q is not a real-binary adapter", name)
	}
	return d, nil
}

// Canonical normalises an adapter name for comparison/storage.
func Canonical(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// IsUpstream reports whether a zone's adapter selects a real upstream binary.
// Everything else (`forge`, `native`, "") stays on the panel-native codec path.
func IsUpstream(name string) bool {
	_, ok := descriptors[Canonical(name)]
	return ok
}

// Descriptors lists every upstream adapter, recommended first, for the UI.
func Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(descriptors))
	for _, n := range order {
		out = append(out, descriptors[n])
	}
	if len(out) != len(descriptors) { // defensive: a new entry not added to order
		out = out[:0]
		names := make([]string, 0, len(descriptors))
		for n := range descriptors {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, descriptors[n])
		}
	}
	return out
}

// Names lists the upstream adapter names.
func Names() []string {
	out := make([]string, 0, len(descriptors))
	for _, d := range Descriptors() {
		out = append(out, d.Adapter)
	}
	return out
}

// ArchToken maps a Go GOARCH onto the release-asset arch token (§4a step 4).
// Only tokens observed in the upstream release listings are accepted; an
// unsupported arch is a hard error rather than a guessed asset name.
func ArchToken(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "AMD64", nil
	case "arm64":
		return "ARM64", nil
	case "arm":
		return "ARMV7", nil
	default:
		return "", fmt.Errorf("forgedns upstream: no release asset for GOARCH %q", goarch)
	}
}

// HostArch is ArchToken for the machine the panel runs on.
func HostArch() (string, error) { return ArchToken(runtime.GOARCH) }

// ServerAsset returns the server archive basename for an arch token, e.g.
// "StormDNS_Server_Linux_AMD64" (§0 URL pattern).
func (d Descriptor) ServerAsset(arch string) string {
	return d.Project + "_Server_Linux_" + arch
}

// ClientAsset returns the client archive basename. Only Linux naming is
// verified (§0); other OS tokens are passed through unchecked, which is why
// Downloads() also hands the user the releases page.
func (d Descriptor) ClientAsset(osToken, arch string) string {
	return d.Project + "_Client_" + osToken + "_" + arch
}

// ExeGlobPrefix is the prefix of the executable inside the server archive. The
// real filename carries the release tag ("<asset>_<TAG>"), so the installer
// must glob for it rather than assume a fixed name (§0, §4a step 3).
func (d Descriptor) ExeGlobPrefix(arch string) string { return d.ServerAsset(arch) + "_" }

// LatestReleaseAPI is the GitHub endpoint that resolves the newest tag (§4a).
func (d Descriptor) LatestReleaseAPI() string {
	return "https://api.github.com/repos/" + d.Owner + "/" + d.Repo + "/releases/latest"
}

// AssetURL builds a release download URL for a tag and asset filename.
func (d Descriptor) AssetURL(tag, file string) string {
	return "https://github.com/" + d.Owner + "/" + d.Repo + "/releases/download/" + tag + "/" + file
}

// ReleasesPage is the human-facing release listing (for platforms whose asset
// naming the panel has not verified).
func (d Descriptor) ReleasesPage() string {
	return "https://github.com/" + d.Owner + "/" + d.Repo + "/releases"
}
