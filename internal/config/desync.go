package config

import (
	"os"
	"strings"
)

// Desync is the PingNG Desync setting stamped onto the client links a Railway
// deployment hands out.
//
// PingNG is a v2rayNG fork that embeds ByeDPI and reads two extra fields from a
// share link: png, the Desync profile, and pngargs, the ByeDPI command line a
// Custom profile runs. A link that carries them imports with Desync already on,
// so a Railway config that does not connect on a network filtering the TLS
// hello starts working without the user finding the setting. Clients other than
// PingNG ignore the two fields.
//
// Railway only. Every other deployment emits links exactly as before.
type Desync struct {
	// Profile is PingNG's profile name, spelled exactly as PingNG spells it:
	// Light, Balanced, Severe, Adaptive or Custom. PingNG matches the name case
	// sensitively and treats anything else as Off. Empty means no Desync fields
	// are emitted.
	Profile string
	// Args is the ByeDPI command line. It is emitted only with Custom, the one
	// profile that reads it; a built-in profile carries its own arguments.
	Args string
	// Rejected holds a FORGEPANEL_PINGNG_PROFILE value that is not a profile
	// PingNG knows. Emitting it would switch Desync off on every phone without a
	// word, so the default is kept and the value is reported at boot instead.
	Rejected string
}

// DefaultDesyncArgs is the Custom profile emitted when the operator sets none:
// split the TLS hello one byte into the SNI, cut the TLS record two bytes into
// it, and wait 1–5 ms between the pieces. It is the setting PingNG users share
// alongside Railway configs.
const DefaultDesyncArgs = "--proto=tls --split 1+s --tlsrec 2+s --timeout 3 --cache-ttl 3600 --delay-range 1-5"

// desyncProfiles are PingNG's profile names in its own spelling.
var desyncProfiles = []string{"Off", "Light", "Balanced", "Severe", "Adaptive", "Custom"}

// canonicalDesyncProfile maps an operator-typed name, in any case, to PingNG's
// spelling.
func canonicalDesyncProfile(v string) (string, bool) {
	for _, p := range desyncProfiles {
		if strings.EqualFold(v, p) {
			return p, true
		}
	}
	return "", false
}

// railwayDesync resolves the Desync setting from FORGEPANEL_PINGNG_PROFILE and
// FORGEPANEL_PINGNG_ARGS, defaulting to Custom with DefaultDesyncArgs.
func railwayDesync() Desync {
	d := Desync{Profile: "Custom", Args: DefaultDesyncArgs}
	if v := strings.TrimSpace(os.Getenv("FORGEPANEL_PINGNG_PROFILE")); v != "" {
		switch p, ok := canonicalDesyncProfile(v); {
		case !ok:
			d.Rejected = v
		case p == "Off":
			return Desync{}
		default:
			d.Profile = p
		}
	}
	// Collapsed to single spaces: PingNG splits the command line on whitespace,
	// and a newline pasted into a platform's variable editor must not reach a
	// link as a separate argument.
	if a := strings.Join(strings.Fields(os.Getenv("FORGEPANEL_PINGNG_ARGS")), " "); a != "" {
		d.Args = a
	}
	if d.Profile != "Custom" {
		d.Args = ""
	}
	return d
}
