/**
 * The subscription endpoint: `/<securePath>/sub/<sub_token>[/<format>]`.
 *
 * One user, one URL. What comes back is the union of:
 *   - the user's VPS inbounds, from the canonical feed the ForgePanel Go side
 *     pushed or the edge pulled,
 *   - the shared nodes in that feed (ForgeDNS tunnels usually live here),
 *   - the edge's own VLESS/Trojan-over-WebSocket entries, minted per user,
 *   - the chain proxy, when configured, as an explicit entry,
 *   - WARP, when accounts have been registered.
 *
 * Format is chosen by an explicit suffix, else `?app=`/`?format=`, else the
 * User-Agent — the same precedence `internal/api/sub.go` uses.
 */

import type { Env } from './env';
import type { EdgeConfig, EdgeSecrets } from './config/schema';
import { KV_KEYS } from './config/schema';
import { HttpStatus, subscriptionHeaders } from './common/http';
import { getJSON } from './config/store';
import { b64EncodeUtf8 } from './common/encoding';
import {
  type CanonicalFeed, emptyFeed, findUser, userinfoHeader, type FeedUser,
} from './edge/feed';
import { buildEdgeNodes } from './edge/nodes';
import { parseChainProxy } from './edge/chain';
import { warpNodes } from './warp/config';
import type { WarpAccount } from './warp/account';
import { loadCleanIPs } from './cleanip/list';
import { resolveDNS } from './dns/resolve';
import {
  canonicalSubFormat, detectFormat, renderSubscription, classify,
  type OriginTaggedNode, type SubFormat,
} from './export/subscription';
import type { Node } from './model/node';

export interface SubContext {
  env: Env;
  cfg: EdgeConfig;
  secrets: EdgeSecrets;
  host: string;
}

/** Everything the edge can advertise, in the order clients should see it. */
export async function assembleNodes(ctx: SubContext, user: FeedUser | null): Promise<OriginTaggedNode[]> {
  const { cfg, env } = ctx;

  // Addresses to front the edge with: the Worker host itself, its resolved IPs,
  // the refreshed clean-IP list, and any operator CDN fronts.
  const addresses: string[] = [];
  const clean = await loadCleanIPs(env);
  try {
    const { ipv4, ipv6 } = await resolveDNS(ctx.host, !cfg.enableIPv6, cfg.dohUpstream);
    addresses.push(...ipv4, ...ipv6.map((ip) => `[${ip}]`));
  } catch {
    // A DoH failure just means fewer addresses, not a broken subscription.
  }
  addresses.push(...cfg.cleanIPs, ...clean.entries, ...cfg.customCdnAddrs);

  const edge = buildEdgeNodes({
    cfg,
    identity: {
      vlessUUID: user?.vless_uuid || cfg.vlessUUID,
      trojanPassword: user?.trojan_password || cfg.trojanPassword,
      subjectKey: user?.id ?? 'shared',
    },
    workerHost: ctx.host,
    addresses,
  });

  const out: OriginTaggedNode[] = [...classify(edge, 'edge')];

  if (user) out.push(...classify(user.nodes, 'vps'));

  const feed = (await getJSON<CanonicalFeed>(env, KV_KEYS.feed)) ?? emptyFeed();
  if (feed.shared_nodes?.length) out.push(...classify(feed.shared_nodes, 'vps'));

  if (cfg.chainProxy) {
    try {
      const chain = parseChainProxy(cfg.chainProxy);
      chain.remark = chain.remark || 'Chain proxy';
      chain.tag = chain.remark;
      out.push({ node: chain, origin: 'vps' });
    } catch {
      // A malformed chain proxy is caught at save time; skip it here rather
      // than failing every subscription if one slipped through an old config.
    }
  }

  const accounts = (await getJSON<WarpAccount[]>(env, KV_KEYS.warp)) ?? [];
  if (accounts.length > 0) {
    const plain: Node[] = warpNodes(accounts, cfg.warp, false);
    const pro: Node[] = warpNodes(accounts, cfg.warp, true);
    out.push(...classify([...plain, ...pro], 'vps'));
  }

  return out;
}

function resolveFormat(url: URL, explicit: string | undefined, ua: string): SubFormat | null {
  const requested = explicit || url.searchParams.get('format') || url.searchParams.get('app') || '';
  if (requested) return canonicalSubFormat(requested);
  return detectFormat(ua);
}

export async function handleSubscription(
  request: Request, segments: string[], ctx: SubContext,
): Promise<Response> {
  const url = new URL(request.url);
  const token = segments[0] ?? '';
  const explicit = segments[1];

  const format = resolveFormat(url, explicit, request.headers.get('User-Agent') ?? '');
  if (!format) {
    return new Response(
      `unsupported subscription format "${explicit ?? ''}"; supported: v2ray, clash, sing-box, xray, links, json`,
      { status: HttpStatus.NOT_FOUND, headers: { 'Vary': 'User-Agent' } },
    );
  }

  const feed = (await getJSON<CanonicalFeed>(ctx.env, KV_KEYS.feed)) ?? emptyFeed();
  const user = token ? findUser(feed, token) : null;

  // An unknown token yields a VALID but empty subscription rather than a 404,
  // so an attacker cannot enumerate which tokens exist by status code. This
  // mirrors `internal/api/sub.go`.
  const nodes = user || feed.users.length === 0 ? await assembleNodes(ctx, user) : [];

  // ?patt=1/only → pattern links; ?patt=both → normal + patterned copies.
  const patt = (url.searchParams.get('patt') ?? '').toLowerCase();
  const pattern = patt === 'both' || patt === '2' ? 'both'
    : ['1', 'on', 'true', 'yes', 'only', 'patt'].includes(patt) ? 'only'
    : 'off';

  const rendered = renderSubscription(format, {
    cfg: ctx.cfg,
    nodes,
    title: ctx.cfg.subTitle,
    pattern,
  });

  return new Response(rendered.body, {
    status: HttpStatus.OK,
    headers: subscriptionHeaders(
      rendered.filename,
      rendered.contentType,
      b64EncodeUtf8(ctx.cfg.subTitle),
      userinfoHeader(user),
    ),
  });
}
