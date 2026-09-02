package api

// Guarding a login on the TARGET as well as the source.
//
// The limiter was keyed on the source IP alone. That stops one host hammering
// one account, and does nothing at all about the attack that actually works: a
// list of stolen credentials tried against one username from a thousand
// addresses, each of which fails once and is never seen again. Every one of
// those requests looked like a first attempt from a new visitor.
//
// THE OBVIOUS FIX IS ALSO A DENIAL OF SERVICE, and that is the whole design
// problem. Locking a username after N failures lets anyone lock the real
// administrator out of their own panel by failing to log in as them — which is
// cheaper for an attacker than guessing the password. So the username guard is
// deliberately weaker than the IP one:
//
//   - it takes far more failures to trip;
//   - it caps at a short lockout instead of escalating without bound;
//   - a SUCCESSFUL login clears it, so the real owner getting in ends the
//     lockout for everybody, including the attacker's next attempt. That is the
//     right trade: the alternative punishes the victim to inconvenience someone
//     who has other addresses anyway.
//
// The IP guard remains the one that escalates, because an address that keeps
// failing has no legitimate reason to.

import (
	"fmt"
	"strings"
	"time"

	"github.com/forgepanel/forgepanel/internal/telegram"
)

const (
	// usernameFailBudget is how many failures against ONE username, across all
	// sources, are tolerated before it is briefly locked.
	//
	// Much higher than the per-IP budget: this is the counter an attacker can
	// drive on somebody else's behalf, so tripping it must be expensive and
	// recovering from it must be cheap.
	usernameFailBudget = 50
)

// usernameKey namespaces the username entries so they cannot collide with an IP.
//
// Without a namespace, a username that happens to look like an address shares an
// entry with it — and locking "127.0.0.1" the user would lock 127.0.0.1 the
// source.
func usernameKey(username string) string {
	return "user\x00" + strings.ToLower(strings.TrimSpace(username))
}

// loginAllowed reports whether an attempt may proceed at all.
func (s *Server) loginAllowed(ip, username string) bool {
	if s.login == nil {
		return true
	}
	if !s.login.Allowed(ip) {
		return false
	}
	if username == "" {
		return true
	}
	return s.login.AllowedKey(usernameKey(username), usernameFailBudget)
}

// loginFailed records a failed attempt against both the source and the target,
// and says so out loud the first time an address is actually locked out.
//
// telegram.EventSecurity was declared for this and had NO producer anywhere: the
// panel would lock an address out, escalate the backoff for an hour, and tell
// nobody. A credential-stuffing run against a panel was invisible unless someone
// thought to read the audit log, which is the opposite of how anyone finds out
// they are being attacked.
func (s *Server) loginFailed(ip, username string) {
	if s.login == nil {
		return
	}
	lockout := s.login.Fail(ip)
	if username != "" {
		s.login.FailKey(usernameKey(username))
	}
	if lockout <= 0 {
		return
	}
	// Keyed on the ADDRESS, so the repeat gate holds one alert per attacker per
	// six hours rather than one per request — an attacker who keeps trying is
	// re-locked on every attempt, and that is the whole point of the gate.
	target := ""
	if username != "" {
		target = fmt.Sprintf(" (most recently as %q)", username)
	}
	s.emit(telegram.EventSecurity, ip, fmt.Sprintf(
		"Sign-in attempts from %s%s have failed repeatedly; the address is locked out for %s.",
		ip, target, lockout.Round(time.Second)))
}

// loginSucceeded clears both counters.
//
// Clearing the USERNAME counter on success is what stops the guard becoming a
// way to lock somebody out of their own panel indefinitely.
func (s *Server) loginSucceeded(ip, username string) {
	if s.login == nil {
		return
	}
	s.login.Success(ip)
	if username != "" {
		s.login.Success(usernameKey(username))
	}
}
