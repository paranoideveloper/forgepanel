/**
 * External subscription aggregation.
 *
 * The operator can list OTHER subscription URLs (their own fleet subs, a
 * community feed) and have every config in them merged into this one, so a
 * family member imports a single URL and gets everything. The fetched configs
 * are parsed into the SAME canonical nodes the rest of the pipeline uses (via
 * the chain-proxy parser), so they render in every format and ride the best-ping
 * groups — not a dumb text concatenation.
 *
 * Fetching happens on the cron and the result is cached in KV, so a serving
 * subscription never blocks on a slow or dead upstream.
 */

import type { Env } from '../env';
import { KV_KEYS } from '../config/schema';
import { getJSON, putJSON } from '../config/store';
import { b64AnyDecode } from '../common/encoding';
import { parseChainProxy } from './chain';
import type { Node } from '../model/node';

const MAX_PER_SUB = 200;
const MAX_TOTAL = 600;
const TD = new TextDecoder();

export interface ExternalStore {
  updatedAt: string;
  nodes: Node[];
  sources: string[];
}

export function emptyExternalStore(): ExternalStore {
  return { updatedAt: new Date(0).toISOString(), nodes: [], sources: [] };
}

/** A subscription body is either base64 (v2ray) or already a list of URI lines. */
function toLines(body: string): string[] {
  const raw = body.trim();
  let text = raw;
  if (!raw.includes('://')) {
    try {
      const decoded = TD.decode(b64AnyDecode(raw));
      if (decoded.includes('://')) text = decoded;
    } catch {
      // Not base64 — fall through and treat the body as plain text.
    }
  }
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.includes('://'));
}

/** Stable identity so the same node from two upstreams is not duplicated. */
export function nodeKey(n: Node): string {
  return `${n.protocol}|${n.address}|${n.port}|${n.uuid ?? n.password ?? ''}`;
}

/**
 * Parse one subscription body (base64 or plain) into canonical nodes, skipping
 * lines a parser doesn't cover and de-duplicating against `seen`. Pure — no
 * network or KV — so it is unit-testable. `limit` caps this body's contribution.
 */
export function parseSubBody(body: string, seen: Set<string>, limit = MAX_PER_SUB): Node[] {
  const out: Node[] = [];
  for (const line of toLines(body)) {
    if (out.length >= limit) break;
    let node: Node;
    try {
      node = parseChainProxy(line);
    } catch {
      continue;
    }
    const key = nodeKey(node);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(node);
  }
  return out;
}

/**
 * Fetch every configured subscription, parse what we can, de-duplicate, and cache
 * the canonical nodes in KV. Unparseable lines (exotic protocols) are skipped,
 * not fatal. Returns the store it wrote.
 */
export async function refreshExternalSubs(env: Env, urls: string[]): Promise<ExternalStore> {
  const seen = new Set<string>();
  const nodes: Node[] = [];
  const used: string[] = [];

  for (const url of urls) {
    if (nodes.length >= MAX_TOTAL) break;
    try {
      const res = await fetch(url, { cf: { cacheTtl: 300 } as RequestInitCfProperties });
      if (!res.ok) continue;
      const limit = Math.min(MAX_PER_SUB, MAX_TOTAL - nodes.length);
      const parsed = parseSubBody(await res.text(), seen, limit);
      if (parsed.length > 0) {
        nodes.push(...parsed);
        used.push(url);
      }
    } catch {
      // A dead or slow upstream just contributes nothing this round.
    }
  }

  const store: ExternalStore = { updatedAt: new Date().toISOString(), nodes, sources: used };
  await putJSON(env, KV_KEYS.external, store);
  return store;
}

export async function loadExternalNodes(env: Env): Promise<Node[]> {
  const stored = await getJSON<ExternalStore>(env, KV_KEYS.external);
  return stored && Array.isArray(stored.nodes) ? stored.nodes : [];
}
