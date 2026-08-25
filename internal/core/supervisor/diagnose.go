package supervisor

// Turning an engine's own output into a cause an operator can act on.
//
// A core that fails to start produces a long chained error — Xray's are five
// clauses deep — ending in the one phrase that matters. The panel was surfacing
// the raw tail, so "app/proxyman/inbound: failed to listen TCP on 443 >
// transport/internet: failed to listen on address: 0.0.0.0:443 >
// transport/internet/tcp: failed to listen TCP on 0.0.0.0:443 > listen tcp
// 0.0.0.0:443: bind: permission denied" was what an operator got, when the
// answer is "the panel is not allowed to bind port 443; grant
// CAP_NET_BIND_SERVICE or run as root".
//
// EVERY SIGNATURE HERE WAS CAPTURED FROM A REAL FAILING CORE, not written from
// memory of what the message might be. A signature that does not match is worse
// than none: it makes the panel look like it has diagnostics while quietly
// falling back to the raw text.

import "strings"

// Diagnosis is a recognised failure with something to do about it.
type Diagnosis struct {
	// Cause is one plain sentence.
	Cause string `json:"cause"`
	// Remedy is the action to take. Empty when there is nothing generic to
	// suggest — a made-up remedy sends people down the wrong path.
	Remedy string `json:"remedy,omitempty"`
	// Line is the engine output that matched, kept so an operator can confirm
	// the diagnosis rather than trust it.
	Line string `json:"line"`
}

type signature struct {
	// all of these substrings must appear in the line.
	needles []string
	cause   string
	remedy  string
}

// signatures are matched newest-line-first.
var signatures = []signature{
	{
		needles: []string{"bind: address already in use"},
		cause:   "another process is already listening on that port",
		remedy: "stop whatever holds the port, or change the inbound's port. " +
			"`ss -ltnp` names the process.",
	},
	{
		needles: []string{"bind: permission denied"},
		cause:   "the panel is not permitted to bind that port",
		remedy: "ports below 1024 need CAP_NET_BIND_SERVICE (systemd: " +
			"AmbientCapabilities=CAP_NET_BIND_SERVICE) or root.",
	},
	{
		needles: []string{"bind: cannot assign requested address"},
		cause:   "the listen address does not exist on this machine",
		remedy:  "use 0.0.0.0 (or ::) unless the inbound must bind one specific local address.",
	},
	{
		needles: []string{"code not found in geosite.dat"},
		cause:   "a routing rule names a geosite category that this geosite.dat does not contain",
		remedy: "check the spelling, or the category may not exist at all — geosite.dat has no " +
			"torrent category, for example. The core refuses the whole config for this.",
	},
	{
		needles: []string{"failed to load geoip"},
		cause:   "a routing rule names a geoip set that this geoip.dat does not contain",
		remedy:  "check the country code; the core refuses the whole config for this.",
	},
	{
		needles: []string{"failed to parse certificate", "no such file or directory"},
		cause:   "the certificate file an inbound points at does not exist",
		remedy:  "re-issue or re-import the certificate; a TLS inbound cannot start without one.",
	},
	{
		needles: []string{"failed to parse certificate"},
		cause:   "the certificate an inbound points at could not be read",
		remedy:  "check that the file is PEM and that its key matches.",
	},
	{
		needles: []string{"tls: failed to find any PEM data"},
		cause:   "the certificate or key file is empty or not PEM",
		remedy:  "re-issue or re-import the certificate.",
	},
	{
		needles: []string{"failed to load config files"},
		cause:   "the core rejected the generated configuration",
		remedy:  "the clause after the last '>' names the field; Config Doctor shows the same check.",
	},
	{
		needles: []string{"v2ray api is not included in this build"},
		cause:   "this sing-box binary was built without the stats API",
		remedy: "per-user accounting for sing-box protocols needs a build with -tags with_v2ray_api; " +
			"see scripts/build-singbox.sh.",
	},
	{
		needles: []string{"no such file or directory"},
		cause:   "a file the configuration refers to is missing",
		remedy:  "",
	},
	{
		needles: []string{"permission denied"},
		cause:   "the core was denied access to something it needs",
		remedy:  "",
	},
}

// Diagnose scans engine output for a known failure signature.
//
// It walks NEWEST first: a process that failed, was restarted and failed again
// has several matching lines, and the current failure is the last one. Reporting
// the oldest would describe a problem that may already be fixed.
func Diagnose(lines []string) (Diagnosis, bool) {
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		for _, sig := range signatures {
			if matchesAll(lower, sig.needles) {
				return Diagnosis{Cause: sig.cause, Remedy: sig.remedy, Line: tail(line)}, true
			}
		}
	}
	return Diagnosis{}, false
}

func matchesAll(haystack string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, strings.ToLower(n)) {
			return false
		}
	}
	return true
}
