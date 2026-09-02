package api

import (
	"fmt"
	"testing"
	"time"
)

// The limiter was keyed on the source IP alone. That stops one host hammering
// one account, and does nothing about the attack that actually works: a
// credential list tried against one username from a thousand addresses, each
// failing once and never seen again. Every request looked like a first attempt
// from a new visitor.

func guardFixture(t *testing.T) (*Server, func(time.Time)) {
	t.Helper()
	s := dbServerT(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	s.login.now = func() time.Time { return now }
	return s, func(v time.Time) { now = v; s.login.now = func() time.Time { return v } }
}

func TestSprayingOneUsernameFromManyAddressesIsCaught(t *testing.T) {
	s, _ := guardFixture(t)

	// Each address fails ONCE and is never seen again, so the per-IP guard never
	// trips for any of them.
	for i := 0; i < usernameFailBudget; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i%250)
		if !s.loginAllowed(ip, "admin") {
			t.Fatalf("blocked after only %d distinct sources", i)
		}
		s.loginFailed(ip, "admin")
	}

	// A fresh address, which the IP guard has never seen, must still be refused:
	// the TARGET is what has been under attack.
	if s.loginAllowed("198.51.100.77", "admin") {
		t.Fatal("a distributed guessing run against one username was never blocked")
	}
}

func TestOneUsernameBeingLockedDoesNotLockAnother(t *testing.T) {
	s, _ := guardFixture(t)
	for i := 0; i < usernameFailBudget+5; i++ {
		s.loginFailed(fmt.Sprintf("203.0.113.%d", i%250), "victim")
	}
	if s.loginAllowed("198.51.100.77", "victim") {
		t.Fatal("setup: the sprayed username should be locked")
	}
	// Everyone else's login must keep working, or one targeted username takes
	// the whole panel down.
	if !s.loginAllowed("198.51.100.77", "someone-else") {
		t.Fatal("locking one username blocked a different one")
	}
}

func TestTheUsernameLockIsShortAndFlat(t *testing.T) {
	s, setNow := guardFixture(t)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	for i := 0; i < usernameFailBudget+20; i++ {
		s.loginFailed(fmt.Sprintf("203.0.113.%d", i%250), "admin")
	}
	if s.loginAllowed("198.51.100.1", "admin") {
		t.Fatal("setup: should be locked")
	}

	// FLAT, not escalating. An escalating lock would let an attacker extend the
	// victim's lockout without bound simply by continuing to fail — the guard
	// becomes the attack.
	setNow(base.Add(usernameLockout + time.Second))
	if !s.loginAllowed("198.51.100.1", "admin") {
		t.Fatalf("the username was still locked after %s despite 20 extra failures", usernameLockout)
	}
}

func TestASuccessfulLoginClearsTheUsernameLock(t *testing.T) {
	s, _ := guardFixture(t)
	for i := 0; i < usernameFailBudget+5; i++ {
		s.loginFailed(fmt.Sprintf("203.0.113.%d", i%250), "admin")
	}
	if s.loginAllowed("198.51.100.1", "admin") {
		t.Fatal("setup: should be locked")
	}

	// The real owner getting in ends the lockout for everybody. That is the right
	// trade: the alternative punishes the victim to inconvenience an attacker who
	// has other addresses anyway.
	s.loginSucceeded("192.0.2.5", "admin")
	if !s.loginAllowed("198.51.100.1", "admin") {
		t.Fatal("a successful login did not clear the username lock")
	}
}

func TestThePerIPGuardStillEscalates(t *testing.T) {
	s, _ := guardFixture(t)
	// One host hammering: the IP guard is the one that escalates, because an
	// address that keeps failing has no legitimate reason to.
	for i := 0; i < 10; i++ {
		s.loginFailed("203.0.113.9", "admin")
	}
	if s.loginAllowed("203.0.113.9", "admin") {
		t.Fatal("a repeatedly failing address was not locked out")
	}
	// And a different address is unaffected by that particular lock.
	if !s.loginAllowed("198.51.100.4", "someone-else") {
		t.Fatal("one bad address locked out an unrelated one")
	}
}

func TestAUsernameThatLooksLikeAnAddressDoesNotCollide(t *testing.T) {
	s, _ := guardFixture(t)
	// Without a namespace, locking the USER "127.0.0.1" would lock the SOURCE
	// 127.0.0.1 — and a login from localhost would start failing.
	for i := 0; i < usernameFailBudget+5; i++ {
		s.loginFailed(fmt.Sprintf("203.0.113.%d", i%250), "127.0.0.1")
	}
	if !s.loginAllowed("127.0.0.1", "unrelated") {
		t.Fatal("locking a username collided with the identically-named source address")
	}
}
