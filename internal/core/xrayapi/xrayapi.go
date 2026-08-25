package xrayapi

// Hot user add/remove, instead of restarting every core on every mutation.
//
// Creating one customer, disabling one account, or rotating one UUID rewrote the
// config and restarted BOTH cores — dropping every other user's connections with
// it. On a panel with real traffic that is an outage per edit, and it is the
// reason panels grow a "don't touch it during peak hours" folklore.
//
// Xray can add and remove users on a running instance through its HandlerService.
// The panel already enables that service and already had a RemoveUser helper —
// with zero callers, so nothing ever used it.
//
// THE RULE HERE IS CONSERVATISM. A hot apply is attempted ONLY when the two
// configs are identical in every respect except which users appear on which
// inbound. Any other difference — a port, a transport, a certificate, a routing
// rule, a new inbound — falls back to the restart that was always happening.
// Getting that judgement wrong in the permissive direction means a running core
// silently disagreeing with its own config, which is far worse than a restart.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// hotApplyTimeout bounds a single CLI call. The default in `xray api` is three
// seconds; this is the outer bound on the whole call including process spawn.
const hotApplyTimeout = 10 * time.Second

// userDelta is the change to one inbound's user list.
type UserDelta struct {
	Tag string
	// Add carries the full inbound entry with ONLY the added users in it: the
	// `adu` subcommand builds a real inbound from the JSON it is given and takes
	// the users out of the result, so a partial entry is not enough. This was
	// measured, not assumed — a tag-plus-clients document is accepted and adds
	// nothing.
	Add    []json.RawMessage
	Remove []string
	// Entry is the new config's full inbound object, used as the template that
	// Add users are spliced into.
	Entry map[string]json.RawMessage
}

var (
	// `xray api adu` prints "Added N user(s) in total." and EXITS ZERO even when
	// N is 0 — which is what happens when the document shape is wrong. Trusting
	// the exit code alone reports success for a change that did not happen, and
	// the panel would then believe a user exists that the core has never heard
	// of. Measured against Xray 26.2.6.
	addedRe   = regexp.MustCompile(`Added (\d+) user`)
	removedRe = regexp.MustCompile(`Removed (\d+) user`)
)

func AddUsers(bin, server, dir string, d UserDelta) error {
	entry := make(map[string]json.RawMessage, len(d.Entry))
	for k, v := range d.Entry {
		entry[k] = v
	}
	settings := map[string]json.RawMessage{}
	if raw, ok := entry["settings"]; ok {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return fmt.Errorf("inbound %q settings: %w", d.Tag, err)
		}
	}
	clients, err := json.Marshal(d.Add)
	if err != nil {
		return err
	}
	settings["clients"] = clients
	rawSettings, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	entry["settings"] = rawSettings

	doc, err := json.Marshal(map[string]any{"inbounds": []any{entry}})
	if err != nil {
		return err
	}

	// The document goes to a temp file because `adu` takes file paths, not
	// stdin. It is written with the .json suffix Xray requires to infer the
	// format, and removed straight after — it carries user credentials.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "adu-"+sanitizeTag(d.Tag)+".json")
	// 0600 and removed immediately: this document contains the UUIDs and
	// passwords of the users being added.
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()

	out, err := runXrayAPI(bin, "adu", "--server="+server, path)
	if err != nil {
		return fmt.Errorf("adding %d user(s) to %q: %w: %s", len(d.Add), d.Tag, err, out)
	}
	n := parseCount(addedRe, out)
	if n != len(d.Add) {
		// A partial add leaves the core serving a different user set than its
		// own config file describes. Reporting it makes the caller restart,
		// which reconciles the two.
		return fmt.Errorf("adding users to %q: core added %d of %d: %s", d.Tag, n, len(d.Add), strings.TrimSpace(out))
	}
	return nil
}

func RemoveUsers(bin, server, tag string, emails []string) error {
	args := append([]string{"rmu", "--server=" + server, "-tag=" + tag}, emails...)
	out, err := runXrayAPI(bin, args...)
	if err != nil {
		return fmt.Errorf("removing %d user(s) from %q: %w: %s", len(emails), tag, err, out)
	}
	if n := parseCount(removedRe, out); n != len(emails) {
		return fmt.Errorf("removing users from %q: core removed %d of %d: %s", tag, n, len(emails), strings.TrimSpace(out))
	}
	return nil
}

func parseCount(re *regexp.Regexp, out string) int {
	m := re.FindStringSubmatch(out)
	if len(m) != 2 {
		// No count line at all means the CLI did something other than what was
		// asked; treat it as zero so the caller reports a mismatch rather than
		// assuming success.
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// diffUsersOnly reports the per-inbound user changes between two Xray configs,
// and whether the configs are otherwise identical.
//
// ok is false the moment anything outside an inbound's client list differs.
func DiffUsersOnly(oldCfg, newCfg []byte) (deltas []UserDelta, ok bool, err error) {
	oldDoc, err := parseXrayConfig(oldCfg)
	if err != nil {
		return nil, false, err
	}
	newDoc, err := parseXrayConfig(newCfg)
	if err != nil {
		return nil, false, err
	}

	// Everything except "inbounds" must match byte-for-byte after
	// canonicalisation. Routing, policy, outbounds, the api block, log settings:
	// a change to any of them needs the core rebuilt.
	if !sameExcept(oldDoc, newDoc, "inbounds") {
		return nil, false, nil
	}

	oldIn, err := indexInbounds(oldDoc["inbounds"])
	if err != nil {
		return nil, false, err
	}
	newIn, err := indexInbounds(newDoc["inbounds"])
	if err != nil {
		return nil, false, err
	}
	// An inbound appearing or disappearing is a listener change, not a user
	// change: it has to bind or release a port, which only a restart does.
	if len(oldIn) != len(newIn) {
		return nil, false, nil
	}

	tags := make([]string, 0, len(newIn))
	for tag := range newIn {
		if _, present := oldIn[tag]; !present {
			return nil, false, nil
		}
		tags = append(tags, tag)
	}
	// Sorted so the applied order is deterministic; an operator reading logs
	// from two identical panels should see the same sequence.
	sort.Strings(tags)

	for _, tag := range tags {
		o, n := oldIn[tag], newIn[tag]
		if !sameExceptSettingsClients(o, n) {
			return nil, false, nil
		}
		oldUsers, oErr := clientsByEmail(o)
		newUsers, nErr := clientsByEmail(n)
		switch {
		case oErr != nil && nErr != nil:
			// Neither side has an email-keyed client list. Plenty of inbounds
			// legitimately do not — the panel's own api dokodemo-door is one, and
			// it is in every config — so this is not a refusal. It just means
			// there is no user delta to compute, and the settings must therefore
			// be IDENTICAL for the change to be hot-appliable at all.
			if !jsonEqual(o["settings"], n["settings"]) {
				return nil, false, nil
			}
			continue
		case oErr != nil || nErr != nil:
			// One side has a keyed client list and the other does not: the
			// inbound changed shape, which is not a user change.
			return nil, false, nil
		}

		d := UserDelta{Tag: tag, Entry: n}
		for email, raw := range newUsers {
			prev, existed := oldUsers[email]
			if !existed {
				d.Add = append(d.Add, raw)
				continue
			}
			if !jsonEqual(prev, raw) {
				// A user whose credentials changed — a rotated UUID or password.
				// Remove and re-add: there is no "update user" call, and leaving
				// the old entry in place would keep the OLD credential working,
				// which is the entire thing a rotation is for.
				d.Remove = append(d.Remove, email)
				d.Add = append(d.Add, raw)
			}
		}
		for email := range oldUsers {
			if _, still := newUsers[email]; !still {
				d.Remove = append(d.Remove, email)
			}
		}
		if len(d.Add) == 0 && len(d.Remove) == 0 {
			continue
		}
		sort.Strings(d.Remove)
		sort.Slice(d.Add, func(i, j int) bool { return string(d.Add[i]) < string(d.Add[j]) })
		deltas = append(deltas, d)
	}
	return deltas, true, nil
}

func parseXrayConfig(b []byte) (map[string]json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// sameExcept compares two documents ignoring one key.
func sameExcept(a, b map[string]json.RawMessage, skip string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if k == skip {
			continue
		}
		bv, ok := b[k]
		if !ok || !jsonEqual(av, bv) {
			return false
		}
	}
	for k := range b {
		if k == skip {
			continue
		}
		if _, ok := a[k]; !ok {
			return false
		}
	}
	return true
}

// sameExceptSettingsClients compares two inbound entries ignoring only
// settings.clients — the one field a hot apply can change.
func sameExceptSettingsClients(a, b map[string]json.RawMessage) bool {
	if !sameExcept(a, b, "settings") {
		return false
	}
	as, aok := a["settings"]
	bs, bok := b["settings"]
	if aok != bok {
		return false
	}
	if !aok {
		return true
	}
	var am, bm map[string]json.RawMessage
	if json.Unmarshal(as, &am) != nil || json.Unmarshal(bs, &bm) != nil {
		return false
	}
	// "decryption", "fallbacks", "method", "network" and anything else inside
	// settings must be identical: those change how the listener behaves.
	return sameExcept(am, bm, "clients")
}

func indexInbounds(raw json.RawMessage) (map[string]map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		return map[string]map[string]json.RawMessage{}, nil
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	out := make(map[string]map[string]json.RawMessage, len(arr))
	for _, entry := range arr {
		var tag string
		if raw, ok := entry["tag"]; ok {
			if err := json.Unmarshal(raw, &tag); err != nil {
				return nil, err
			}
		}
		if tag == "" {
			// An untagged inbound cannot be addressed by the handler API at all.
			return nil, fmt.Errorf("inbound without a tag")
		}
		if _, dup := out[tag]; dup {
			// Duplicate tags make "which inbound" ambiguous, and a hot apply
			// would hit whichever the core happened to index first.
			return nil, fmt.Errorf("duplicate inbound tag %q", tag)
		}
		out[tag] = entry
	}
	return out, nil
}

// clientsByEmail keys an inbound's client list by email.
//
// It fails for an inbound whose users are not an email-keyed client list, which
// is the signal to fall back to a restart rather than guess.
func clientsByEmail(entry map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	settings, ok := entry["settings"]
	if !ok {
		return nil, fmt.Errorf("no settings")
	}
	var sm map[string]json.RawMessage
	if err := json.Unmarshal(settings, &sm); err != nil {
		return nil, err
	}
	raw, ok := sm["clients"]
	if !ok {
		return nil, fmt.Errorf("no clients")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(arr))
	for _, c := range arr {
		var probe struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(c, &probe); err != nil {
			return nil, err
		}
		if probe.Email == "" {
			// A client with no email cannot be removed by the handler API — rmu
			// addresses users by email — so this inbound is not hot-appliable.
			return nil, fmt.Errorf("client without an email")
		}
		if _, dup := out[probe.Email]; dup {
			return nil, fmt.Errorf("duplicate client email %q", probe.Email)
		}
		out[probe.Email] = c
	}
	return out, nil
}

// jsonEqual compares two JSON documents by value, not by their serialised bytes.
//
// Byte comparison would report a difference for a re-ordered object or different
// whitespace, and every such false difference forces a restart that drops every
// connection for no reason.
func jsonEqual(a, b json.RawMessage) bool {
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	ab, err1 := json.Marshal(canonical(av))
	bb, err2 := json.Marshal(canonical(bv))
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// canonical rewrites a decoded document so that marshalling it is stable.
//
// Go's encoding/json already sorts map keys on output, so this only has to
// recurse; it exists so the recursion is explicit rather than depending on that
// behaviour continuing to hold for nested values.
func canonical(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = canonical(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = canonical(val)
		}
		return out
	default:
		return v
	}
}

// runXrayAPI runs one `xray api` subcommand and returns its combined output.
//
// The output is returned in EVERY case, including success: the CLI reports
// "Added 0 user(s)" with a zero exit status when it did nothing, so the caller
// has to read what it said rather than only whether it failed.
func runXrayAPI(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hotApplyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"api"}, args...)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		// A timeout must not look like a refusal: the difference decides whether
		// an operator investigates the core or the network to it.
		return string(out), fmt.Errorf("timed out after %s", hotApplyTimeout)
	}
	return string(out), err
}

func sanitizeTag(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "inbound"
	}
	return b.String()
}

// HotApplyOptions is everything HotApply needs to reach a running core.
type HotApplyOptions struct {
	// Bin is the xray binary that speaks to the core. It does not have to be
	// the same process; the API is over loopback gRPC.
	Bin string
	// Server is the core's api listener, host:port.
	Server string
	// WorkDir is where the short-lived `adu` documents are written. They carry
	// user credentials, so it must not be a world-readable temp directory.
	WorkDir string
}

// HotApply applies a user-only change to a RUNNING core.
//
// It returns true only when every part of the change was applied. Anything else
// returns false (the caller should restart) or an error (restart, with a reason
// worth recording).
func HotApply(opts HotApplyOptions, oldCfg, newCfg []byte) (bool, error) {
	deltas, ok, err := DiffUsersOnly(oldCfg, newCfg)
	if err != nil || !ok {
		// Not a user-only change, or not parseable: restart. Returning an error
		// here for an unparseable config would report a failure for what is
		// really just "this needs the normal path".
		return false, nil
	}
	if len(deltas) == 0 {
		// The configs differ in whitespace or key order but not in content. A
		// restart would drop every connection for no change at all.
		return true, nil
	}
	for _, d := range deltas {
		if len(d.Remove) > 0 {
			if err := RemoveUsers(opts.Bin, opts.Server, d.Tag, d.Remove); err != nil {
				return false, err
			}
		}
		if len(d.Add) > 0 {
			if err := AddUsers(opts.Bin, opts.Server, opts.WorkDir, d); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}
