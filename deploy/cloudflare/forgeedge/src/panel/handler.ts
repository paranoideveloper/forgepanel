/**
 * Panel API, all under `/<securePath>/api/…`.
 *
 * Authorisation model: every route except `/login` requires a valid session. The
 * secure path gets you to the door; the password opens it.
 */

import type { Env } from '../env';
import type { EdgeConfig, EdgeSecrets } from '../config/schema';
import { KV_KEYS } from '../config/schema';
import { HttpStatus, respond, safeError, timingSafeEqual } from '../common/http';
import {
  checkPassword, clearSessionCookie, isAuthenticated, issueSession, sessionCookieHeader,
} from '../auth';
import {
  loadConfig, saveConfig, saveSecrets, rotateSecurePath, hashPassword, randomToken, migrateConfig,
  getJSON, putJSON,
} from '../config/store';
import { loadCleanIPs, refreshCleanIPs, isValidCleanEntry } from '../cleanip/list';
import { probeCleanIP } from '../cleanip/probe';
import { validateConfig } from '../config/validate';
import { scanWarpEndpoints } from '../warp/scanner';
import type { WarpAccount } from '../warp/account';
import { wireguardConf } from '../warp/config';
import { checkForUpdate, status as deployStatus, type CfCredentials } from '../deploy/cloudflare';
import { sanitizeFeed, type CanonicalFeed, emptyFeed } from '../edge/feed';
import { VERSION } from '../version';

export interface PanelContext {
  env: Env;
  cfg: EdgeConfig;
  secrets: EdgeSecrets;
  origin: string;
  host: string;
}

function credentials(env: Env): CfCredentials | null {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return null;
  return { accountID: env.CF_ACCOUNT_ID, apiToken: env.CF_API_TOKEN };
}

export async function handlePanelAPI(
  request: Request, segments: string[], ctx: PanelContext,
): Promise<Response> {
  const { env, secrets } = ctx;
  const route = segments.join('/');

  // --- login is the only unauthenticated route ---------------------------
  if (route === 'login') {
    if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST only');
    const body = (await request.json().catch(() => ({}))) as { password?: string };
    const password = body.password ?? '';

    // First-run: no password has ever been set, so the first POST sets it.
    if (!secrets.adminHash) {
      if (password.length < 10) {
        return respond(false, HttpStatus.BAD_REQUEST, 'Choose a password of at least 10 characters.');
      }
      secrets.adminSalt = randomToken(12);
      secrets.adminHash = hashPassword(secrets.adminSalt, password);
      await saveSecrets(env, secrets);
      const token = await issueSession(secrets);
      return respond(true, HttpStatus.OK, 'Password set.', { firstRun: true },
        { 'Set-Cookie': sessionCookieHeader(token) });
    }

    if (!checkPassword(secrets, password)) {
      return respond(false, HttpStatus.UNAUTHORIZED, 'Wrong password.');
    }
    const token = await issueSession(secrets);
    return respond(true, HttpStatus.OK, 'Signed in.', { firstRun: false },
      { 'Set-Cookie': sessionCookieHeader(token) });
  }

  if (route === 'logout') {
    return respond(true, HttpStatus.OK, 'Signed out.', null, { 'Set-Cookie': clearSessionCookie() });
  }

  // --- everything below requires a session OR the machine push token ------
  // A browser authenticates with the session cookie the password issued. The
  // ForgePanel VPS has no browser and no admin password, so it authenticates
  // with the feed push token it already holds — enough to drive machine-safe
  // actions (register WARP, read config, download a WARP .conf) but it never
  // sees the admin password.
  const bearer = (request.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
  const machineAuthed = bearer !== '' && timingSafeEqual(bearer, secrets.feedPushToken);
  if (!machineAuthed && !(await isAuthenticated(request, secrets))) {
    return respond(false, HttpStatus.UNAUTHORIZED, 'Unauthorized.');
  }

  switch (route) {
    case 'status': {
      const clean = await loadCleanIPs(env);
      const feed = (await getJSON<CanonicalFeed>(env, KV_KEYS.feed)) ?? emptyFeed();
      const creds = credentials(env);
      return respond(true, HttpStatus.OK, undefined, {
        version: VERSION,
        host: ctx.host,
        panel: `${ctx.origin}/${secrets.securePath}/panel`,
        dohEndpoint: `${ctx.origin}/${secrets.securePath}/dns-query`,
        subscriptionTemplate: `${ctx.origin}/${secrets.securePath}/sub/<sub_token>`,
        feedPushEndpoint: `${ctx.origin}/${secrets.securePath}/api/feed`,
        feedPushToken: secrets.feedPushToken,
        securePathRotatedAt: secrets.rotatedAt,
        backendMode: ctx.cfg.backend.enabled ? ctx.cfg.backend.url : 'off',
        users: feed.users.length,
        feedGeneratedAt: feed.generated_at,
        cleanIPs: { count: clean.entries.length, updatedAt: clean.updatedAt },
        deployment: creds
          ? await deployStatus(creds, env.CF_PAGES === '1' ? 'pages' : 'workers', ctx.host.split('.')[0])
          : null,
      });
    }

    case 'config': {
      if (request.method === 'GET') {
        return respond(true, HttpStatus.OK, undefined, ctx.cfg);
      }
      if (request.method === 'PUT') {
        const raw = await request.json().catch(() => null);
        if (!raw || typeof raw !== 'object') return respond(false, HttpStatus.BAD_REQUEST, 'Body must be a config object.');
        const merged = migrateConfig(raw as Partial<EdgeConfig>);
        const errors = validateConfig(merged);
        if (errors.length) return respond(false, HttpStatus.BAD_REQUEST, errors.join('; '), { errors });
        await saveConfig(env, merged, 'panel');
        return respond(true, HttpStatus.OK, 'Saved.', merged);
      }
      return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'GET or PUT');
    }

    case 'rotate-path': {
      if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST only');
      const fresh = await rotateSecurePath(env, true);
      return respond(true, HttpStatus.OK, 'Rotated. Every previous URL is dead.', {
        securePath: fresh.securePath,
        panel: `${ctx.origin}/${fresh.securePath}/panel`,
      }, { 'Set-Cookie': clearSessionCookie() });
    }

    case 'clean-ip/probe': {
      const target = new URL(request.url).searchParams.get('target') ?? '';
      if (!isValidCleanEntry(target)) return respond(false, HttpStatus.BAD_REQUEST, 'target must be a host or IP');
      // Several attempts: a single probe from one colo says very little.
      const attempts = await Promise.all([0, 1, 2].map(() => probeCleanIP(target)));
      const ok = attempts.filter((a) => a.ok);
      return respond(true, HttpStatus.OK, undefined, {
        target,
        successRate: `${ok.length}/${attempts.length}`,
        avgLatencyMs: ok.length ? Math.round(ok.reduce((s, a) => s + a.elapsedMs, 0) / ok.length) : null,
        attempts,
      });
    }

    case 'clean-ip/refresh': {
      if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST only');
      const store = await refreshCleanIPs(env, ctx.cfg.cleanIPSources);
      return respond(true, HttpStatus.OK, undefined, store);
    }

    case 'warp/scan': {
      if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST only');
      const result = await scanWarpEndpoints(ctx.cfg.backend, 24, secrets.securePath);
      return respond(true, HttpStatus.OK,
        result.measuredBy === 'none'
          ? 'Candidates only: no Backend Mode VPS is configured, and a Worker cannot send UDP. No latencies were measured.'
          : 'Measured by the ForgePanel backend.',
        result);
    }

    case 'warp/accounts': {
      if (request.method !== 'POST') return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST only');

      // Import-only: the panel registers WARP from the VPS (which CAN reach
      // Cloudflare's WARP API) and POSTs the accounts here to store. A Worker
      // cannot register them itself — a fetch() to api.cloudflareclient.com is a
      // Cloudflare-owned host and the edge refuses that subrequest (error 1104),
      // the same CF→CF block that stops a Worker connecting to a Cloudflare IP.
      // So there is no self-registration path here; the accounts must be pushed.
      const raw = await request.text().catch(() => '');
      let imported: { accounts?: WarpAccount[] } | null = null;
      try { imported = raw ? JSON.parse(raw) : null; } catch { imported = null; }
      const accounts = (imported?.accounts ?? []).filter(
        (a) => a && a.privateKey && a.publicKey && a.warpIPv6 && a.reserved,
      );
      if (accounts.length === 0) {
        return respond(false, HttpStatus.BAD_REQUEST,
          'POST {"accounts":[…]} of WARP accounts registered by the ForgePanel. ' +
          'A Worker cannot register WARP itself (Cloudflare blocks the edge→WARP-API request), ' +
          'so registration runs on the panel host and the accounts are pushed here.');
      }
      await putJSON(env, KV_KEYS.warp, accounts);
      return respond(true, HttpStatus.OK, `Stored ${accounts.length} WARP account(s).`,
        accounts.map((a: WarpAccount) => ({ publicKey: a.publicKey, warpIPv6: a.warpIPv6 })));
    }

    case 'warp/conf': {
      // The raw wg-quick .conf for the Amnezia app / any WireGuard client:
      // `plain` is a standard WireGuard tunnel, `pro` adds AmneziaWG's
      // junk-packet obfuscation. Built from the registered account, so WARP
      // must have been registered first.
      const accounts = (await getJSON<WarpAccount[]>(env, KV_KEYS.warp)) ?? [];
      if (accounts.length === 0) {
        return respond(false, HttpStatus.NOT_FOUND,
          'No WARP accounts are registered yet — register WARP first, then download the .conf.');
      }
      const ep = ctx.cfg.warp.endpoints[0] || 'engage.cloudflareclient.com:2408';
      return respond(true, HttpStatus.OK, undefined, {
        plain: wireguardConf(accounts[0], ep, ctx.cfg.warp, false),
        pro: wireguardConf(accounts[0], ep, ctx.cfg.warp, true),
      });
    }

    case 'update-check': {
      const info = await checkForUpdate(ctx.cfg.updateRepo, VERSION);
      await putJSON(env, KV_KEYS.updateCheck, info);
      return respond(true, HttpStatus.OK, undefined, info);
    }

    case 'feed': {
      // Also reachable with the push token (see router.ts) so the Go panel can
      // POST without a browser session.
      if (request.method === 'GET') {
        const feed = (await getJSON<CanonicalFeed>(env, KV_KEYS.feed)) ?? emptyFeed();
        return respond(true, HttpStatus.OK, undefined, feed);
      }
      return handleFeedPush(request, env);
    }

    default:
      return respond(false, HttpStatus.NOT_FOUND, `unknown panel route "${route}"`);
  }
}

/** Accept a canonical feed push from the ForgePanel VPS. */
export async function handleFeedPush(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST' && request.method !== 'PUT') {
    return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'POST or PUT');
  }
  const raw = await request.json().catch(() => null);
  const { feed, warnings } = sanitizeFeed(raw);
  if (feed.users.length === 0 && warnings.length) {
    return respond(false, HttpStatus.BAD_REQUEST, warnings.join('; '), { warnings });
  }
  await putJSON(env, KV_KEYS.feed, feed);
  return respond(true, HttpStatus.OK, 'Feed accepted.', {
    users: feed.users.length,
    sharedNodes: feed.shared_nodes?.length ?? 0,
    warnings,
  });
}

/** Pull the canonical feed from the panel — the alternative to a push. */
export async function pullFeed(env: Env, cfg: EdgeConfig): Promise<{ ok: boolean; detail: string }> {
  if (!cfg.feedPullURL) return { ok: false, detail: 'no feedPullURL configured' };
  try {
    const res = await fetch(cfg.feedPullURL, {
      headers: cfg.feedPullToken ? { Authorization: `Bearer ${cfg.feedPullToken}` } : {},
    });
    if (!res.ok) return { ok: false, detail: `pull returned ${res.status}` };
    const { feed, warnings } = sanitizeFeed(await res.json());
    if (feed.users.length === 0 && warnings.length) {
      return { ok: false, detail: warnings.join('; ') };
    }
    await putJSON(env, KV_KEYS.feed, feed);
    return { ok: true, detail: `pulled ${feed.users.length} user(s)` };
  } catch (e) {
    return { ok: false, detail: safeError(e) };
  }
}

export { loadConfig };
