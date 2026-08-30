/**
 * Edge connection limits — a per-IP abuse brake, not a global guarantee.
 *
 * SCOPE, stated up front so nobody reads more into it than is there:
 *
 *  - The registry below is a module global in a Worker isolate. Isolates are
 *    per-colo, created and discarded at Cloudflare's discretion, and a busy
 *    Worker runs many at once. So these counts are per-isolate: an abuser who
 *    reconnects enough times will land in a fresh one. A globally consistent
 *    limiter needs a Durable Object, and the panel cannot deploy one today —
 *    `internal/edge/workers.go` `uploadMetadata` emits no `migrations` stanza
 *    and no DO binding. This is the honest, deployable half.
 *
 *  - Backend Mode connections are NOT counted. `forwardToBackend` hands back a
 *    relayed `fetch()` Response and the Worker holds no handle on the spliced
 *    socket's lifetime, so there is no correct moment to decrement. A limiter
 *    that only ever increments is strictly worse than none. The VPS terminates
 *    those connections and owns their limiting.
 *
 *  - `perUUIDConcurrent` is DECLARED, NOT ENFORCED. Enforcing it needs the UUID
 *    surfaced out of `parseVlessHeader` (framing.ts computes it and throws it
 *    away) and a handle re-keyed mid-connection, and it is near-degenerate until
 *    the edge accepts more than one UUID — router.ts authenticates every VLESS
 *    connection against the single `cfg.vlessUUID`. The key ships now so its
 *    shape is fixed; the enforcement is a separate change.
 *
 * The two bounds that ARE enforced are checked in `admitIP` and released by
 * `releaseConnection`, which the data-path handlers hook to both `close` and
 * `error`. Miss the release and the limiter becomes the outage it was meant to
 * prevent, so it is idempotent and hooked twice on purpose.
 */

import type { LimitsConfig } from '../config/schema';

/** Handed to the protocol handler so it can give the slot back. */
export interface ConnHandle {
  /** Empty when the admission was not accounted (limiter off, or no client IP). */
  ip: string;
  released: boolean;
}

export type Admission =
  | { ok: true; handle: ConnHandle }
  | { ok: false; reason: 'ip-concurrent' | 'ip-rate' };

interface IPEntry {
  /** Live edge-terminated sockets. */
  live: number;
  /** Token bucket for new connections. */
  tokens: number;
  lastRefill: number;
  lastSeen: number;
}

/**
 * Hard ceiling on distinct tracked IPs. A spoofed-source flood must not exhaust
 * the isolate's memory — that outage would be worse than the abuse the limiter
 * exists to stop. Mirrors the discipline of `internal/api/ratelimit.go`.
 */
const MAX_IPS = 10_000;
/** An entry idle this long is indistinguishable from a fresh one, so drop it. */
const ENTRY_TTL_MS = 10 * 60 * 1000;
const SWEEP_EVERY_MS = 60 * 1000;

const entries = new Map<string, IPEntry>();
let lastSweep = 0;

/** An admission that took nothing and therefore owes nothing back. */
function unaccounted(): Admission {
  return { ok: true, handle: { ip: '', released: true } };
}

/**
 * A configured bound, or `Infinity` when it is unusable.
 *
 * KV can hold a config written before `validateConfig` knew about `limits`, or
 * one typed straight into the panel's free-form JSON box. Disabling that one
 * bound is the right failure: a brake with a number the operator never chose is
 * a surprise outage, and `validateConfig` already refuses such a PUT.
 */
function bound(v: number): number {
  return Number.isInteger(v) && v > 0 ? v : Infinity;
}

/**
 * Drop entries nobody is using. Only called from `admitIP`, so cleanup rides on
 * traffic rather than needing a timer the Worker does not have.
 *
 * An entry idle for ENTRY_TTL_MS necessarily has a full bucket — a bucket
 * refills completely in 60s at any capacity — so idleness alone is the test.
 */
function sweep(now: number): void {
  if (now - lastSweep < SWEEP_EVERY_MS) return;
  lastSweep = now;
  for (const [ip, e] of entries) {
    if (e.live === 0 && now - e.lastSeen >= ENTRY_TTL_MS) entries.delete(ip);
  }
}

/**
 * Free one slot at capacity, or report that none could be freed.
 *
 * A Map iterates in insertion order, so the head is the oldest-created entry;
 * taking the first one with no live sockets is an approximation of LRU that
 * costs O(1) in the normal case. Getting the choice "wrong" only hands one idle
 * IP a fresh token bucket, which is a far cheaper mistake than closing a live
 * connection or letting the map grow without limit.
 */
function evictOne(): boolean {
  for (const [ip, e] of entries) {
    if (e.live === 0) {
      entries.delete(ip);
      return true;
    }
  }
  return false;
}

/**
 * Decide whether one new edge-terminated connection from `ip` may proceed.
 *
 * `now` is injectable so the refill behaviour is testable without a wall clock.
 */
export function admitIP(ip: string, cfg: LimitsConfig | undefined, now: number = Date.now()): Admission {
  if (!cfg?.enabled) return unaccounted();
  // An absent CF-Connecting-IP (service binding, some local dev) must not funnel
  // every caller into one shared bucket: that would lock out real users because
  // a header was missing, which is worse than not limiting at all.
  if (!ip) return unaccounted();

  sweep(now);

  const maxLive = bound(cfg.perIPConcurrent);
  const capacity = bound(cfg.perIPNewPerMinute);

  let e = entries.get(ip);
  if (!e) {
    if (entries.size >= MAX_IPS && !evictOne()) {
      // Every tracked IP is holding live sockets. Refusing here would punish a
      // real user for a condition they did not cause, so admit unaccounted and
      // keep the map at its ceiling.
      return unaccounted();
    }
    e = { live: 0, tokens: capacity, lastRefill: now, lastSeen: now };
    entries.set(ip, e);
  }

  e.lastSeen = now;

  // Concurrency first: it is the cheaper check and the more damaging condition,
  // and a request refused for concurrency must not also burn a token.
  if (e.live >= maxLive) return { ok: false, reason: 'ip-concurrent' };

  const elapsed = Math.max(0, now - e.lastRefill);
  e.lastRefill = now;
  e.tokens = Math.min(capacity, e.tokens + (elapsed * capacity) / 60_000);
  if (e.tokens < 1) return { ok: false, reason: 'ip-rate' };

  e.tokens -= 1;
  e.live += 1;
  return { ok: true, handle: { ip, released: false } };
}

/**
 * Give a slot back. Idempotent because `close` and `error` are distinct events
 * on the same socket (see ws.ts) and either, both, or neither may fire.
 */
export function releaseConnection(handle: ConnHandle | undefined): void {
  if (!handle || handle.released) return;
  handle.released = true;

  const e = entries.get(handle.ip);
  if (!e) return;
  if (e.live > 0) e.live -= 1;
  e.lastSeen = Date.now();
}

/** Observability, and the assertion surface for the release hooks. */
export function limiterSnapshot(): { ips: number; totalLive: number } {
  let totalLive = 0;
  for (const e of entries.values()) totalLive += e.live;
  return { ips: entries.size, totalLive };
}

/** Test seam: reset between cases, mirroring `clearRuntime` in config/runtime.ts. */
export function resetLimiter(): void {
  entries.clear();
  lastSweep = 0;
}
