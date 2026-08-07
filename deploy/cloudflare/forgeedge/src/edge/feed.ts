/**
 * The canonical feed: the contract between the ForgePanel VPS (Go) and the edge.
 *
 * "One user, one subscription" means a subscriber's single URL must resolve to
 * the union of everything that user can connect through — the VPS inbounds, the
 * edge Worker entries, and any ForgeDNS tunnels. The VPS owns users; the edge
 * owns its own entries. So the VPS pushes (or the edge pulls) this document, and
 * the edge merges its own nodes into it at render time.
 *
 * Every node in here is a `model.Node` verbatim — see `docs/GO_WIRING.md` for
 * the exact Go-side handler that produces it.
 */

import type { Node } from '../model/node';

export interface FeedUser {
  /** Stable user id from the panel DB. */
  id: string;
  /** The bearer that appears in the subscription URL. This IS a credential. */
  sub_token: string;
  email?: string;
  enabled: boolean;
  /** RFC3339, or absent for "never expires". */
  expires_at?: string;
  /** Bytes used, for the Subscription-Userinfo header. */
  used_traffic?: number;
  /** Byte cap, 0 = unlimited. */
  data_limit?: number;
  /**
   * Per-user credentials the EDGE should use when minting its own entries. When
   * absent the edge falls back to its own configured UUID/password, which means
   * every subscriber shares one edge identity — fine for a personal deploy,
   * wrong for a multi-user panel.
   */
  vless_uuid?: string;
  trojan_password?: string;
  /** This user's VPS inbounds, already redacted of server-only secrets. */
  nodes: Node[];
}

export interface CanonicalFeed {
  /** Bumped by the Go side when the shape changes. */
  version: number;
  generated_at: string;
  panel?: { name?: string; base_url?: string };
  users: FeedUser[];
  /** Nodes every user gets, in addition to their own. */
  shared_nodes?: Node[];
}

export const FEED_VERSION = 1;

export function emptyFeed(): CanonicalFeed {
  return { version: FEED_VERSION, generated_at: new Date(0).toISOString(), users: [] };
}

/**
 * Validate a pushed/pulled feed enough that a malformed document cannot poison
 * every subscription. Unknown extra fields are preserved (forward compatibility
 * with a newer Go side); structurally broken users are dropped with a reason.
 */
export function sanitizeFeed(raw: unknown): { feed: CanonicalFeed; warnings: string[] } {
  const warnings: string[] = [];
  const feed = emptyFeed();
  if (!raw || typeof raw !== 'object') {
    warnings.push('feed is not an object');
    return { feed, warnings };
  }
  const r = raw as Partial<CanonicalFeed>;
  feed.version = typeof r.version === 'number' ? r.version : FEED_VERSION;
  feed.generated_at = typeof r.generated_at === 'string' ? r.generated_at : new Date().toISOString();
  if (r.panel && typeof r.panel === 'object') feed.panel = r.panel;

  if (Array.isArray(r.shared_nodes)) {
    feed.shared_nodes = r.shared_nodes.filter((n) => isNodeish(n));
    const dropped = r.shared_nodes.length - feed.shared_nodes.length;
    if (dropped > 0) warnings.push(`dropped ${dropped} malformed shared node(s)`);
  }

  if (!Array.isArray(r.users)) {
    warnings.push('feed.users is missing or not an array');
    return { feed, warnings };
  }

  for (const u of r.users) {
    if (!u || typeof u !== 'object') { warnings.push('dropped a non-object user'); continue; }
    const user = u as Partial<FeedUser>;
    if (!user.sub_token || typeof user.sub_token !== 'string') {
      warnings.push(`dropped user ${String(user.id ?? '?')}: no sub_token`);
      continue;
    }
    const nodes = Array.isArray(user.nodes) ? user.nodes.filter((n) => isNodeish(n)) : [];
    feed.users.push({
      id: String(user.id ?? user.sub_token),
      sub_token: user.sub_token,
      email: typeof user.email === 'string' ? user.email : undefined,
      enabled: user.enabled !== false,
      expires_at: typeof user.expires_at === 'string' ? user.expires_at : undefined,
      used_traffic: typeof user.used_traffic === 'number' ? user.used_traffic : 0,
      data_limit: typeof user.data_limit === 'number' ? user.data_limit : 0,
      vless_uuid: typeof user.vless_uuid === 'string' ? user.vless_uuid : undefined,
      trojan_password: typeof user.trojan_password === 'string' ? user.trojan_password : undefined,
      nodes,
    });
  }

  return { feed, warnings };
}

function isNodeish(n: unknown): n is Node {
  if (!n || typeof n !== 'object') return false;
  const o = n as Partial<Node>;
  return typeof o.protocol === 'string' && typeof o.address === 'string' && typeof o.port === 'number';
}

/** Lookup by subscription token; returns null for unknown or disabled users. */
export function findUser(feed: CanonicalFeed, token: string): FeedUser | null {
  for (const u of feed.users) {
    if (u.sub_token === token) return u.enabled ? u : null;
  }
  return null;
}

/** SIP008-style `Subscription-Userinfo`, matching the Go panel's format exactly. */
export function userinfoHeader(u: FeedUser | null): string {
  if (!u) return 'upload=0; download=0; total=0; expire=0';
  const expire = u.expires_at ? Math.floor(new Date(u.expires_at).getTime() / 1000) : 0;
  return `upload=0; download=${u.used_traffic ?? 0}; total=${u.data_limit ?? 0}; expire=${Number.isFinite(expire) ? expire : 0}`;
}
