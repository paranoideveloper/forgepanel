// The presence window: how recently a user must have been active to count as
// "online right now".
//
// Presence here is inferred, never observed. Nothing reports a disconnect — the
// backend sees connections being accepted and the panel sees traffic counters
// moving — so a user counts as present while their last activity is recent
// enough, and the length of that window IS the answer. Two screens with two
// windows therefore give two different answers about the same person, and they
// did: the Users table carried its own three-minute constant for its presence
// dot while the backend tracker (internal/core/online/tracker.go, DefaultTTL)
// expires presence after two. A user idle for 2m30s showed a green dot in Users
// and was already absent from the Online screen.
//
// So the window lives here, once. The default mirrors the backend's DefaultTTL
// so the very first render is right before any request has come back, and
// /admin/online publishes ttl_seconds precisely so readers do not have to guess
// — the Online view feeds that value in here, which keeps every screen moving
// together if the server's TTL ever differs from the compiled-in default.

/** Mirrors DefaultTTL in internal/core/online/tracker.go (2 minutes). */
export const DEFAULT_PRESENCE_TTL_SECONDS = 120;

let ttlSeconds = DEFAULT_PRESENCE_TTL_SECONDS;

/** The window currently in force, in seconds. */
export function presenceTtlSeconds(): number {
  return ttlSeconds;
}

/** The window currently in force, in milliseconds. */
export function presenceWindowMs(): number {
  return ttlSeconds * 1000;
}

/**
 * setPresenceTtlSeconds adopts the window the server published, and returns the
 * window in force afterwards.
 *
 * A missing, zero or otherwise nonsense value keeps the current window instead
 * of adopting it: a response that came back without the field would otherwise
 * set the window to zero and mark every user offline at once, which on this
 * screen reads as an outage rather than as a parsing mistake.
 */
export function setPresenceTtlSeconds(seconds: unknown): number {
  const n = typeof seconds === 'number' ? seconds : Number(seconds);
  if (Number.isFinite(n) && n > 0) ttlSeconds = n;
  return ttlSeconds;
}

/**
 * isPresent reports whether an activity timestamp is recent enough to count as
 * online.
 *
 * `now` is injectable so callers and tests can ask the question at a fixed
 * instant rather than racing the clock.
 */
export function isPresent(
  lastSeen: string | number | Date | null | undefined,
  now: number = Date.now()
): boolean {
  if (lastSeen === null || lastSeen === undefined || lastSeen === '') return false;
  const t = lastSeen instanceof Date ? lastSeen.getTime() : new Date(lastSeen).getTime();
  // An unparseable timestamp is not evidence of activity. Returning false keeps
  // a malformed record from showing as permanently online.
  if (Number.isNaN(t)) return false;
  return now - t < presenceWindowMs();
}
