/**
 * ForgeEdge — the Cloudflare Worker deployment target for ForgePanel.
 *
 * WHAT IT IS. A Worker that terminates VLESS and Trojan over WebSocket at
 * Cloudflare's edge, serves DoH, and serves the SAME canonical subscription the
 * ForgePanel VPS serves — so a subscriber has one URL that carries their VPS
 * inbounds, the edge entries, and their ForgeDNS tunnels together, with url-test
 * failover between them.
 *
 * WHAT IT IS NOT, and cannot be. A Worker has outbound TCP via
 * `cloudflare:sockets` and nothing else — no UDP socket, no raw IP, no QUIC, no
 * inbound listener on an arbitrary port. So the edge can carry VLESS/Trojan over
 * WS and DNS-over-UDP-as-DoH, and NOTHING ELSE. Hysteria2, TUIC, WireGuard,
 * voice/video calls and games all need real UDP, which means they need a real
 * server. That is what Backend Mode is for: the Worker becomes a WebSocket relay
 * in front of the operator's own ForgePanel node, contributing the Cloudflare
 * anycast entry IP and TLS while the VPS does the proxying.
 */

import type { Env } from './env';
import { route } from './router';
import { loadConfig } from './config/store';
import { refreshCleanIPs } from './cleanip/list';
import { checkForUpdate } from './deploy/cloudflare';
import { pullFeed } from './panel/handler';
import { putJSON } from './config/store';
import { KV_KEYS } from './config/schema';
import { VERSION } from './version';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (e) {
      // Never leak a stack trace to an unauthenticated caller: on this product,
      // an error page that names the software is a fingerprint.
      console.error('[forgeedge] unhandled', e);
      return new Response('Bad Request', { status: 400 });
    }
  },

  /**
   * Cron work, all of it optional and all of it failure-tolerant: a Worker whose
   * scheduled handler throws still serves traffic, and none of these tasks are
   * on the data path.
   */
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil((async () => {
      const cfg = await loadConfig(env);

      if (cfg.cleanIPRefresh) {
        const store = await refreshCleanIPs(env, cfg.cleanIPSources);
        console.log(`[forgeedge] clean IPs refreshed: ${store.entries.length} entries`);
      }

      if (cfg.feedPullURL) {
        const result = await pullFeed(env, cfg);
        console.log(`[forgeedge] feed pull: ${result.detail}`);
      }

      if (cfg.autoUpdateCheck) {
        const info = await checkForUpdate(cfg.updateRepo, VERSION);
        await putJSON(env, KV_KEYS.updateCheck, info);
        if (info.updateAvailable) {
          console.log(`[forgeedge] update available: ${info.current} → ${info.latest} (${info.releaseURL ?? ''})`);
        }
      }
    })());
  },
};
