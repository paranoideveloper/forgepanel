/**
 * WARP endpoint scanner.
 *
 * HONEST LIMITATION, stated up front: a Cloudflare Worker has no UDP socket.
 * WARP speaks WireGuard over UDP. Therefore a Worker CANNOT measure WARP
 * endpoint latency itself, and any number it printed would be fabricated.
 *
 * So the scanner does the two things it legitimately can, and delegates the
 * third:
 *
 *  1. ENUMERATE — expand Cloudflare's published WARP prefixes across the port
 *     set the client accepts, producing the candidate list. This is pure
 *     arithmetic and is exact.
 *  2. RANK — order candidates by (a) real measurements when they exist, else
 *     (b) a deterministic spread that maximises prefix and port diversity, so a
 *     client's own url-test has the best chance of finding a working one early.
 *  3. MEASURE — ask the operator's ForgePanel VPS (Backend Mode) to run the
 *     actual UDP probe and return per-endpoint RTT. When there is no backend,
 *     results are returned with `measured: false` and no latency field. A caller
 *     that wants numbers without a backend gets nothing, on purpose.
 */

import type { BackendConfig } from '../config/schema';
import { backendControl } from '../protocols/backend';

/** Cloudflare's WARP anycast ranges (the /24s the consumer client dials). */
export const WARP_PREFIXES = [
  '162.159.192', '162.159.193', '162.159.195',
  '188.114.96', '188.114.97', '188.114.98', '188.114.99',
];

/** Ports the WARP server answers on. 2408 is the default; the rest are alternates. */
export const WARP_PORTS = [2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886];

export interface WarpCandidate {
  endpoint: string;
  /** True only when a real probe produced the latency below. */
  measured: boolean;
  latencyMs?: number;
  loss?: number;
}

/** Deterministic pseudo-random from a string, so the same input ranks the same way. */
function hash32(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

/**
 * Build `count` candidates spread evenly across prefixes and ports.
 *
 * The spread matters: handing a client 30 endpoints from one /24 means one
 * blocked prefix kills all 30. Round-robining the prefixes guarantees that a
 * single blocked range costs at most 1/7th of the list.
 */
export function enumerateCandidates(count = 24, seed = 'forgeedge'): WarpCandidate[] {
  const out: WarpCandidate[] = [];
  const seen = new Set<string>();
  const ports = [...new Set(WARP_PORTS)];

  for (let i = 0; out.length < count && i < count * 8; i++) {
    const prefix = WARP_PREFIXES[i % WARP_PREFIXES.length];
    const port = ports[Math.floor(i / WARP_PREFIXES.length) % ports.length];
    // Host octet in 1..254, deterministic per (seed, prefix, index).
    const host = (hash32(`${seed}|${prefix}|${i}`) % 254) + 1;
    const endpoint = `${prefix}.${host}:${port}`;
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    out.push({ endpoint, measured: false });
  }
  return out;
}

/** Rank measured candidates by latency; unmeasured ones keep enumeration order behind them. */
export function rank(candidates: WarpCandidate[]): WarpCandidate[] {
  const measured = candidates.filter((c) => c.measured && typeof c.latencyMs === 'number');
  const rest = candidates.filter((c) => !(c.measured && typeof c.latencyMs === 'number'));
  measured.sort((a, b) => (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity));
  return [...measured, ...rest];
}

interface BackendScanReply {
  results: { endpoint: string; latency_ms?: number; loss?: number; ok: boolean }[];
}

/**
 * Full scan. Returns the enumerated candidates, measured through the backend
 * when one is available.
 *
 * `measured: false` on every row is a truthful outcome, not a failure — it means
 * "here are the endpoints worth trying; your client's url-test will pick".
 */
export async function scanWarpEndpoints(
  backend: BackendConfig,
  count = 24,
  seed = 'forgeedge',
): Promise<{ candidates: WarpCandidate[]; measuredBy: 'backend' | 'none' }> {
  const candidates = enumerateCandidates(count, seed);

  const reply = await backendControl<BackendScanReply>(
    backend, '/forgeedge/warp-scan', { endpoints: candidates.map((c) => c.endpoint) },
  );
  if (!reply || !Array.isArray(reply.results)) {
    return { candidates: rank(candidates), measuredBy: 'none' };
  }

  const byEndpoint = new Map(reply.results.map((r) => [r.endpoint, r]));
  for (const c of candidates) {
    const r = byEndpoint.get(c.endpoint);
    if (!r || !r.ok || typeof r.latency_ms !== 'number') continue;
    c.measured = true;
    c.latencyMs = r.latency_ms;
    if (typeof r.loss === 'number') c.loss = r.loss;
  }
  // Endpoints the backend proved dead are dropped; the rest keep their order.
  const alive = candidates.filter((c) => !byEndpoint.has(c.endpoint) || byEndpoint.get(c.endpoint)!.ok);
  return { candidates: rank(alive), measuredBy: 'backend' };
}
