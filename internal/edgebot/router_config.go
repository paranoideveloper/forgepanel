package edgebot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// router_config.go — the config editor. Every command is read-modify-write on
// the Worker's live EdgeConfig: fetch it, change one field, write it back, and
// let the Worker validate. A rejected write comes back as the Worker's own
// field-level complaint, relayed verbatim.

// allowedCFPorts are the Cloudflare-reachable ports the edge can be fronted on;
// the Worker rejects any advertised port outside httpPorts+httpsPorts, so /ports
// is pre-checked here to give a friendly error instead of a validation dump.
var allowedCFPorts = map[int]bool{
	443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true, // https
	80: true, 8080: true, 8880: true, 2052: true, 2082: true, 2086: true, 2095: true, // http
}

// handleConfigCommand resolves the target Worker then dispatches the field edit.
func (r *Router) handleConfigCommand(ctx context.Context, in Incoming, cmd string, args []string) Result {
	d, rest, errMsg := r.mustDeployment(in.UserID, args)
	if errMsg != "" {
		return r.reply(in, errMsg)
	}

	switch cmd {
	case "ips":
		cfg, err := r.ops.GetConfig(ctx, d)
		if err != nil {
			return r.reply(in, "Couldn't read config:\n"+errText(err))
		}
		ips := asStringSlice(cfg["cleanIPs"])
		if len(ips) == 0 {
			return r.reply(in, d.Name+" has no manual clean IPs. Add some with /addip, or /refreships to mint fresh Cloudflare edge IPs.")
		}
		return r.reply(in, d.Name+" clean IPs ("+strconv.Itoa(len(ips))+"):\n"+strings.Join(ips, "\n"))

	case "probeip":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /probeip [name] <ip-or-host>")
		}
		pr, err := r.ops.ProbeCleanIP(ctx, d, rest[0])
		if err != nil {
			return r.reply(in, "Probe failed:\n"+errText(err))
		}
		lat := "n/a"
		if pr.AvgLatencyMs != nil {
			lat = strconv.Itoa(*pr.AvgLatencyMs) + " ms"
		}
		return r.reply(in, fmt.Sprintf("Probe %s: %s reachable, avg %s", pr.Target, pr.SuccessRate, lat))

	case "refreships":
		st, err := r.ops.RefreshCleanIPs(ctx, d)
		if err != nil {
			return r.reply(in, "Refresh failed:\n"+errText(err))
		}
		return r.reply(in, fmt.Sprintf("♻️ %s clean IPs refreshed: %d entries now.", d.Name, len(st.Entries)))

	case "refreshext":
		n, err := r.ops.RefreshExternal(ctx, d)
		if err != nil {
			return r.reply(in, "Refresh failed:\n"+errText(err))
		}
		return r.reply(in, fmt.Sprintf("♻️ %s external subs refreshed: %d nodes merged.", d.Name, n))

	case "addip":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /addip [name] <ip-or-host> [more…]")
		}
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cur := asStringSlice(cfg["cleanIPs"])
			before := len(cur)
			cur = appendUnique(cur, rest...)
			cfg["cleanIPs"] = cur
			return fmt.Sprintf("clean IPs %d → %d", before, len(cur)), nil
		})

	case "rmip":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /rmip [name] <ip-or-host>")
		}
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cur := asStringSlice(cfg["cleanIPs"])
			cur, removed := removeItem(cur, rest[0])
			if !removed {
				return "", fmt.Errorf("%s isn't in the clean-IP list", rest[0])
			}
			cfg["cleanIPs"] = cur
			return "removed " + rest[0] + ", " + strconv.Itoa(len(cur)) + " left", nil
		})

	case "sni":
		val := firstOrEmpty(rest)
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["customCdnSni"] = val
			return "fronting SNI = " + orCleared(val), nil
		})

	case "cdnhost":
		val := firstOrEmpty(rest)
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["customCdnHost"] = val
			return "CDN Host header = " + orCleared(val), nil
		})

	case "cdnaddr":
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["customCdnAddrs"] = append([]string{}, rest...)
			if len(rest) == 0 {
				return "custom CDN addresses cleared", nil
			}
			return fmt.Sprintf("custom CDN addresses set (%d)", len(rest)), nil
		})

	case "ports":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /ports [name] <port> [port…]\nAllowed CF ports: 443 2053 2083 2087 2096 8443 (and http 80 8080 8880 2052 2082 2086 2095)")
		}
		ports, err := parsePorts(rest)
		if err != nil {
			return r.reply(in, "⚠️ "+err.Error())
		}
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["ports"] = ports
			return "advertised ports = " + joinInts(ports), nil
		})

	case "fingerprint":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /fingerprint [name] <chrome|firefox|safari|ios|android|edge|randomized>")
		}
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["fingerprint"] = rest[0]
			return "uTLS fingerprint = " + rest[0], nil
		})

	case "fragment":
		return r.handleFragment(ctx, in, d, rest)

	case "proxyip":
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			if len(rest) == 1 && strings.EqualFold(rest[0], "off") {
				cfg["proxyIPMode"] = "off"
				cfg["proxyIPs"] = []string{}
				return "proxyIP disabled", nil
			}
			if len(rest) == 0 {
				return "", fmt.Errorf("usage: /proxyip [name] <relay-ip…> | off")
			}
			cfg["proxyIPs"] = append([]string{}, rest...)
			cfg["proxyIPMode"] = "proxyip"
			return fmt.Sprintf("proxyIP on, %d relay(s)", len(rest)), nil
		})

	case "nat64":
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			if len(rest) == 1 && strings.EqualFold(rest[0], "off") {
				cfg["proxyIPMode"] = "off"
				return "NAT64 disabled", nil
			}
			if len(rest) == 0 {
				return "", fmt.Errorf("usage: /nat64 [name] <[ipv6:prefix::]…> | off")
			}
			cfg["nat64Prefixes"] = append([]string{}, rest...)
			cfg["proxyIPMode"] = "nat64"
			return fmt.Sprintf("NAT64 on, %d prefix(es)", len(rest)), nil
		})

	case "chain":
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			if len(rest) == 0 || strings.EqualFold(rest[0], "off") {
				cfg["chainProxy"] = ""
				return "chain proxy cleared", nil
			}
			cfg["chainProxy"] = rest[0]
			return "chain proxy set", nil
		})

	case "backend":
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			b := getMap(cfg, "backend")
			if len(rest) == 0 || strings.EqualFold(rest[0], "off") {
				b["enabled"] = false
				return "backend mode off (edge terminates directly)", nil
			}
			b["enabled"] = true
			b["url"] = rest[0]
			if len(rest) >= 2 {
				b["token"] = rest[1]
			}
			return "backend mode → " + rest[0], nil
		})

	case "extsub":
		return r.handleExtSub(ctx, in, d, rest)

	case "protocols":
		if len(rest) < 1 {
			return r.reply(in, "Usage: /protocols [name] vless,trojan  (any of vless, trojan)")
		}
		protos := parseProtocols(rest)
		if len(protos) == 0 {
			return r.reply(in, "⚠️ pick at least one of: vless, trojan")
		}
		return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
			cfg["protocols"] = protos
			return "protocols = " + strings.Join(protos, ", "), nil
		})
	}
	return r.reply(in, "Unknown config command.")
}

func (r *Router) handleFragment(ctx context.Context, in Incoming, d Deployment, rest []string) Result {
	if len(rest) < 1 {
		return r.reply(in, "Usage: /fragment [name] on|off [len a-b] [delay a-b]\ne.g. /fragment on 10-100 10-20")
	}
	on := strings.EqualFold(rest[0], "on")
	off := strings.EqualFold(rest[0], "off")
	if !on && !off {
		return r.reply(in, "First argument must be on or off.")
	}
	// Optional length/delay ranges follow.
	var lMin, lMax, dMin, dMax int
	haveLen, haveDelay := false, false
	for _, tok := range rest[1:] {
		if a, b, ok := parseRange(tok); ok {
			if !haveLen {
				lMin, lMax, haveLen = a, b, true
			} else {
				dMin, dMax, haveDelay = a, b, true
			}
		}
	}
	return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
		f := getMap(cfg, "fragment")
		f["enabled"] = on
		if haveLen {
			f["lengthMin"], f["lengthMax"] = lMin, lMax
		}
		if haveDelay {
			f["delayMin"], f["delayMax"] = dMin, dMax
		}
		if off {
			return "fragmentation off", nil
		}
		s := "fragmentation on"
		if haveLen {
			s += fmt.Sprintf(", len %d-%d", lMin, lMax)
		}
		if haveDelay {
			s += fmt.Sprintf(", delay %d-%d", dMin, dMax)
		}
		return s, nil
	})
}

func (r *Router) handleExtSub(ctx context.Context, in Incoming, d Deployment, rest []string) Result {
	if len(rest) < 1 {
		return r.reply(in, "Usage: /extsub [name] add <url> | rm <url> | list")
	}
	action := strings.ToLower(rest[0])
	if action == "list" {
		cfg, err := r.ops.GetConfig(ctx, d)
		if err != nil {
			return r.reply(in, "Couldn't read config:\n"+errText(err))
		}
		subs := asStringSlice(cfg["externalSubs"])
		if len(subs) == 0 {
			return r.reply(in, d.Name+" has no external subscription sources.")
		}
		return r.reply(in, d.Name+" external subs:\n"+strings.Join(subs, "\n"))
	}
	if len(rest) < 2 {
		return r.reply(in, "Usage: /extsub [name] add <url> | rm <url> | list")
	}
	url := rest[1]
	return r.editConfig(ctx, in, d, func(cfg map[string]any) (string, error) {
		subs := asStringSlice(cfg["externalSubs"])
		switch action {
		case "add":
			subs = appendUnique(subs, url)
			cfg["externalSubs"] = subs
			return "added external sub (" + strconv.Itoa(len(subs)) + " total)", nil
		case "rm", "remove":
			var removed bool
			subs, removed = removeItem(subs, url)
			if !removed {
				return "", fmt.Errorf("that URL isn't in the list")
			}
			cfg["externalSubs"] = subs
			return "removed external sub", nil
		default:
			return "", fmt.Errorf("unknown action %q — use add, rm or list", action)
		}
	})
}

// editConfig runs get → mutate → put and reports the outcome.
func (r *Router) editConfig(ctx context.Context, in Incoming, d Deployment, mutate func(cfg map[string]any) (string, error)) Result {
	cfg, err := r.ops.GetConfig(ctx, d)
	if err != nil {
		return r.reply(in, "Couldn't read config:\n"+errText(err))
	}
	summary, err := mutate(cfg)
	if err != nil {
		return r.reply(in, "⚠️ "+err.Error())
	}
	if _, err := r.ops.PutConfig(ctx, d, cfg); err != nil {
		return r.reply(in, "The edge rejected the change:\n"+errText(err))
	}
	return r.reply(in, "✅ "+d.Name+": "+summary)
}

// --- small pure helpers -----------------------------------------------------

func asStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func appendUnique(cur []string, items ...string) []string {
	seen := map[string]bool{}
	for _, c := range cur {
		seen[c] = true
	}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" && !seen[it] {
			cur = append(cur, it)
			seen[it] = true
		}
	}
	return cur
}

func removeItem(cur []string, item string) ([]string, bool) {
	out := cur[:0:0]
	removed := false
	for _, c := range cur {
		if c == item {
			removed = true
			continue
		}
		out = append(out, c)
	}
	return out, removed
}

func getMap(cfg map[string]any, key string) map[string]any {
	if m, ok := cfg[key].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	cfg[key] = m
	return m
}

func parsePorts(toks []string) ([]int, error) {
	out := make([]int, 0, len(toks))
	for _, t := range toks {
		p, err := strconv.Atoi(t)
		if err != nil {
			return nil, fmt.Errorf("%q is not a port number", t)
		}
		if !allowedCFPorts[p] {
			return nil, fmt.Errorf("port %d is not a Cloudflare-reachable port", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseRange(tok string) (int, int, bool) {
	a, b, ok := strings.Cut(tok, "-")
	if !ok {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

func parseProtocols(toks []string) []string {
	set := map[string]bool{}
	for _, t := range toks {
		for _, p := range strings.Split(t, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "vless" || p == "trojan" {
				set[p] = true
			}
		}
	}
	out := []string{}
	for _, p := range []string{"vless", "trojan"} {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func orCleared(s string) string {
	if s == "" {
		return "(cleared)"
	}
	return s
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, " ")
}
