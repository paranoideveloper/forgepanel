// Package online tracks who is connected right now, from which addresses.
//
// The panel could say how many bytes a user had ever moved and nothing about
// whether they were connected at this moment, from where, or on which inbound.
// That is the first question asked when a customer says "it's not working", the
// only way to notice one account being shared across a dozen households, and the
// data that per-user IP limits have to be enforced against.
//
// WHERE IT COMES FROM. Xray's access log names the user on every accepted
// connection. The panel already supervises the Xray process and already reads
// every line it writes, so the access log is pointed at STDOUT rather than a
// file: nothing to rotate, nothing to grow without bound on disk, and no second
// copy of connection metadata sitting around after a restart. Presence lives in
// memory for as long as it is useful and is never written down.
package online

import (
	"strings"
	"time"
)

// Entry is one accepted connection parsed out of an access log line.
type Entry struct {
	At      time.Time
	IP      string // source address, without the port
	User    string // the email Xray was configured with; empty for unauthenticated inbounds
	Inbound string // inbound tag
	Target  string // destination, kept for the connection explorer
}

// ParseAccessLine parses one Xray access log line.
//
// The format was confirmed against a live Xray 26.2.6 rather than assumed, and
// it is NOT uniform — these two real lines differ in the source field:
//
//	2026/08/25 17:58:23.673870 from tcp:127.0.0.1:43522 accepted tcp:[2606:4700:10::ac42:93f3]:80 [in-socks >> direct]
//	2026/08/25 17:58:56.880563 from 127.0.0.1:64792 accepted tcp:[2606:4700:10::6814:179a]:80 [vless-in >> direct] email: alice@forgepanel
//
// The first carries a "tcp:" network prefix on the source and no email; the
// second carries neither prefix nor... has an email. A parser written against
// only one of them silently drops every connection of the other shape, and
// silently dropping half the data is worse here than not collecting it, because
// the resulting presence list looks complete.
//
// ok is false for any line that is not an accepted connection — the log also
// carries startup banners, warnings and DNS lines, and treating those as
// connections would invent sessions.
func ParseAccessLine(line string) (Entry, bool) {
	// "from " is the anchor. Anything before it is a timestamp of a format that
	// has changed across Xray versions, and parsing a timestamp we do not need
	// would make this brittle for no gain: the panel stamps observations with
	// its own clock, which is also the clock every other panel time is on.
	i := strings.Index(line, " from ")
	if i < 0 {
		return Entry{}, false
	}
	rest := line[i+len(" from "):]

	j := strings.Index(rest, " accepted ")
	if j < 0 {
		// Rejected/blocked connections and non-connection lines land here.
		return Entry{}, false
	}
	src := rest[:j]
	rest = rest[j+len(" accepted "):]

	ip := hostOf(stripNetwork(src))
	if ip == "" {
		return Entry{}, false
	}

	e := Entry{IP: ip}

	// The destination runs to the " [" that opens the routing bracket.
	if k := strings.Index(rest, " ["); k >= 0 {
		e.Target = rest[:k]
		rest = rest[k+2:]
		if m := strings.Index(rest, "]"); m >= 0 {
			route := rest[:m]
			rest = rest[m+1:]
			// "inbound-tag >> outbound-tag"; the inbound is the half that says
			// which listener the user came in on.
			if sep := strings.Index(route, " >> "); sep >= 0 {
				e.Inbound = strings.TrimSpace(route[:sep])
			} else {
				e.Inbound = strings.TrimSpace(route)
			}
		}
	} else {
		e.Target = strings.TrimSpace(rest)
		rest = ""
	}

	if k := strings.Index(rest, "email: "); k >= 0 {
		e.User = strings.TrimSpace(rest[k+len("email: "):])
	}

	return e, true
}

// stripNetwork removes a leading "tcp:"/"udp:" network prefix.
//
// It must not strip the leading part of a bare IPv6 address: "::1" contains
// colons but no network prefix, and cutting at the first colon would turn it
// into an empty host.
func stripNetwork(s string) string {
	for _, p := range []string{"tcp:", "udp:", "unix:"} {
		if strings.HasPrefix(s, p) {
			return s[len(p):]
		}
	}
	return s
}

// hostOf drops the ":port" from an address, handling bracketed IPv6.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			return s[1:end]
		}
		return ""
	}
	// An unbracketed address with more than one colon is a bare IPv6 literal;
	// cutting at the last colon would lop off its final group and produce an
	// address that is wrong rather than absent.
	if strings.Count(s, ":") > 1 {
		return s
	}
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		return s[:idx]
	}
	return s
}
