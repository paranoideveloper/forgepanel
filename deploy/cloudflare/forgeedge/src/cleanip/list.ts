/**
 * Clean-IP handling.
 *
 * A "clean IP" is a Cloudflare edge address that is not blocked from the user's
 * network. Which addresses are clean changes constantly, so the list is:
 *
 *   - seeded with a built-in set of Cloudflare-fronted hostnames that resolve to
 *     rotating edge IPs (a hostname stays valid longer than any literal),
 *   - extended from operator-supplied source URLs on the cron trigger,
 *   - validated before use — every entry must be a hostname or an IP literal, so
 *     a defaced source list cannot inject arbitrary text into a subscription.
 *
 * A Worker can genuinely reachability-test a candidate; that lives in probe.ts,
 * which needs a socket. It runs on demand from the panel, not on the cron,
 * because it costs a socket per candidate.
 */

import { isDomain, isIPv4, isIPv6, parseHostPort } from '../common/net';
import type { Env } from '../env';
import { KV_KEYS } from '../config/schema';
import { getJSON, putJSON } from '../config/store';

/**
 * Built-in seeds. These are Cloudflare-fronted hostnames whose A records rotate
 * across the edge, which is why they outlive any hardcoded literal.
 */
export const BUILTIN_CLEAN_HOSTS = [
  'speed.cloudflare.com',
  'www.speedtest.net',
  'cf.090227.xyz',
  'cdn.anycast.eu.org',
  'cloudflare.182682.xyz',
  'ip.sb',
];

export interface CleanIPStore {
  updatedAt: string;
  entries: string[];
  sources: string[];
}

/** Accept a hostname, an IPv4 literal, or a bracketed IPv6 literal — nothing else. */
export function isValidCleanEntry(raw: string): boolean {
  const s = raw.trim();
  if (!s || s.length > 253) return false;
  const { host } = parseHostPort(s, true);
  if (!host) return false;
  return isDomain(host) || isIPv4(host) || isIPv6(host);
}

/** Parse a fetched list: one entry per line, `#` comments, CSV first column. */
export function parseCleanList(text: string, limit = 500): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const comma = line.indexOf(',');
    if (comma > 0) line = line.slice(0, comma).trim();
    if (!isValidCleanEntry(line)) continue;
    out.push(line);
    if (out.length >= limit) break;
  }
  return out;
}

export async function loadCleanIPs(env: Env): Promise<CleanIPStore> {
  const stored = await getJSON<CleanIPStore>(env, KV_KEYS.cleanIPs);
  if (stored && Array.isArray(stored.entries)) return stored;
  return { updatedAt: new Date(0).toISOString(), entries: [...BUILTIN_CLEAN_HOSTS], sources: [] };
}

/**
 * Refresh from the configured sources. Merges (never replaces) with the built-in
 * seeds so a dead source URL cannot empty the list out from under live users.
 */
export async function refreshCleanIPs(env: Env, sources: string[]): Promise<CleanIPStore> {
  const merged = new Set<string>(BUILTIN_CLEAN_HOSTS);
  const used: string[] = [];

  for (const url of sources) {
    try {
      const res = await fetch(url, { cf: { cacheTtl: 300 } as RequestInitCfProperties });
      if (!res.ok) continue;
      const entries = parseCleanList(await res.text());
      if (entries.length === 0) continue;
      for (const e of entries) merged.add(e);
      used.push(url);
    } catch {
      // A source that is down is not an error worth failing the cron for.
    }
  }

  const store: CleanIPStore = {
    updatedAt: new Date().toISOString(),
    entries: [...merged],
    sources: used,
  };
  await putJSON(env, KV_KEYS.cleanIPs, store);
  return store;
}
