/**
 * Request routing.
 *
 * Two disjoint surfaces:
 *
 *  1. THE DATA PATH — `/vl/…` and `/tr/…` WebSocket upgrades. These are NOT
 *     under the secure path, on purpose: those URLs are handed to every
 *     subscriber inside their config, so putting the admin secret in them would
 *     leak it to every user and to anyone who sees a config file. The
 *     credential (UUID / Trojan password) is what authenticates here.
 *
 *  2. THE CONTROL PATH — panel, API, subscriptions, DoH. All under the
 *     compulsory secure path. Anything that does not match falls through to the
 *     decoy, so a scanner cannot tell a ForgeEdge Worker from an ordinary site.
 */

import type { Env } from './env';
import { HttpStatus, respond, timingSafeEqual } from './common/http';
import { loadConfig, loadSecrets, rotateSecurePath } from './config/store';
import { setRuntime } from './config/runtime';
import { matchSecurePath } from './auth';
import { vlessOverWS } from './protocols/vless';
import { trojanOverWS } from './protocols/trojan';
import { forwardToBackend } from './protocols/backend';
import type { OutboundOptions } from './protocols/outbound';
import { handleDoH } from './dns/doh';
import { handleSubscription } from './sub';
import { handlePanelAPI, handleFeedPush } from './panel/handler';
import { panelHTML } from './panel/ui';
import { landingHTML } from './panel/landing';
import { handleTelegram } from './telegram/bot';
import { getJSON } from './config/store';
import { KV_KEYS } from './config/schema';
import { type CanonicalFeed, emptyFeed } from './edge/feed';

/**
 * The decoy for unmatched paths.
 *
 * When `fallbackHost` is set the request is reverse-proxied there, so the Worker
 * presents a real, complete website. Otherwise it is a plain 404 — quiet, and
 * indistinguishable from an empty Worker.
 */
async function decoy(request: Request, fallbackHost: string): Promise<Response> {
  if (!fallbackHost) return new Response('Not Found', { status: HttpStatus.NOT_FOUND });
  const url = new URL(request.url);
  url.hostname = fallbackHost;
  url.protocol = 'https:';
  url.port = '';
  try {
    return await fetch(new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: 'manual',
    }));
  } catch {
    return new Response('Not Found', { status: HttpStatus.NOT_FOUND });
  }
}

export async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const [cfg, secrets] = await Promise.all([loadConfig(env), loadSecrets(env)]);
  setRuntime(cfg, secrets);

  const outbound: OutboundOptions = {
    proxyIPMode: cfg.proxyIPMode,
    proxyIPs: cfg.proxyIPs,
    nat64Prefixes: cfg.nat64Prefixes,
    dohUpstream: cfg.dohUpstream,
  };

  // --- 1. data path -------------------------------------------------------
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    // Backend Mode short-circuits everything: the Worker relays the upgrade to
    // the operator's VPS, which has real UDP and the full protocol matrix.
    if (cfg.backend.enabled && cfg.backend.url) {
      const result = await forwardToBackend(request, cfg.backend);
      if (result.ok || !cfg.backend.fallbackToEdge) return result.response;
      console.log('[forgeedge] backend refused the upgrade; terminating at the edge');
    }

    const kind = url.pathname.split('/').filter(Boolean)[0];
    if (kind === 'vl') {
      return vlessOverWS(request, { uuid: cfg.vlessUUID, outbound, dohUpstream: cfg.dohUpstream });
    }
    if (kind === 'tr') {
      return trojanOverWS(request, { password: cfg.trojanPassword, outbound });
    }
    return decoy(request, cfg.fallbackHost);
  }

  // --- 2. control path ----------------------------------------------------
  const segments = matchSecurePath(url.pathname, secrets.securePath);
  if (!segments) return decoy(request, cfg.fallbackHost);

  const head = segments[0] ?? '';
  const rest = segments.slice(1);
  const origin = url.origin;

  switch (head) {
    case 'panel':
      return new Response(panelHTML(secrets.securePath, !secrets.adminHash), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer',
          'X-Content-Type-Options': 'nosniff',
        },
      });

    case 'api':
      return handlePanelAPI(request, rest, { env, cfg, secrets, origin, host: url.hostname });

    case 'sub':
      return handleSubscription(request, rest, { env, cfg, secrets, host: url.hostname });

    case 'import': {
      // End-user onboarding page: /<securePath>/import/<sub_token>. Built from the
      // subscriber's own token — one-tap import + a QR, no admin secret exposed.
      const subToken = rest[0] ?? '';
      return new Response(landingHTML(url.hostname, secrets.securePath, subToken, cfg.subTitle), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    case 'dns-query':
      return handleDoH(request, cfg.dohUpstream);

    case 'feed': {
      // Machine-to-machine push from the ForgePanel VPS. Authorised by the push
      // token, NOT by a browser session — there is no browser on that side.
      const bearer = (request.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
      if (!timingSafeEqual(bearer, secrets.feedPushToken)) {
        return respond(false, HttpStatus.UNAUTHORIZED, 'Invalid feed push token.');
      }
      return handleFeedPush(request, env);
    }

    case 'telegram': {
      const feed = (await getJSON<CanonicalFeed>(env, KV_KEYS.feed)) ?? emptyFeed();
      return handleTelegram(request, {
        cfg, secrets, origin,
        subTokens: feed.users.map((u) => u.sub_token),
        rotateSecurePath: async () => (await rotateSecurePath(env, true)).securePath,
      });
    }

    default:
      return decoy(request, cfg.fallbackHost);
  }
}
