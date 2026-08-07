/**
 * BACKEND MODE — the architectural centrepiece.
 *
 * A Cloudflare Worker cannot run a native TCP proxy for arbitrary protocols and
 * cannot touch UDP at all. `connect()` gives outbound TCP only; there is no UDP
 * socket, no raw IP, no QUIC. That is not a limitation ForgeEdge can engineer
 * around — it is the platform contract. So every protocol beyond
 * VLESS/Trojan-over-WebSocket, and every UDP flow (QUIC, WireGuard, FaceTime,
 * WhatsApp and Telegram calls, games), simply cannot terminate at the edge.
 *
 * Backend Mode is the honest answer: the Worker stops being a proxy and becomes
 * a WebSocket relay in front of the operator's OWN ForgePanel VPS. The VPS runs
 * the real Xray/sing-box, so it has the full protocol matrix and real UDP. The
 * Worker still contributes what only it can:
 *
 *   - a Cloudflare-anycast entry IP that is hard to block wholesale,
 *   - TLS termination on Cloudflare's certificate, on any of the CDN ports,
 *   - the panel, the subscription, the DoH endpoint and the clean-IP rotation.
 *
 * Wire contract with the VPS: the backend must expose a WebSocket endpoint that
 * speaks the SAME inbound protocol the client used (a ws inbound in Xray/
 * sing-box). The Worker forwards the upgrade verbatim — same path, same
 * `sec-websocket-protocol` early data, same query — so the backend sees exactly
 * what the client sent and no re-framing happens anywhere.
 */

import type { BackendConfig } from '../config/schema';

/** Compose the backend URL for an incoming request, preserving path and query. */
export function backendTarget(backendURL: string, incoming: URL): string | null {
  let u: URL;
  try {
    u = new URL(backendURL);
  } catch {
    return null;
  }
  // A backend URL with a path pins the endpoint; otherwise the client's path
  // (which carries the per-user WS path) is preserved.
  if (u.pathname === '/' || u.pathname === '') u.pathname = incoming.pathname;
  u.search = incoming.search;
  // ws:// and wss:// are accepted for convenience; fetch() needs http(s).
  if (u.protocol === 'ws:') u.protocol = 'http:';
  if (u.protocol === 'wss:') u.protocol = 'https:';
  return u.toString();
}

export interface BackendResult {
  response: Response;
  /** False when the backend refused and the caller should fall back to edge termination. */
  ok: boolean;
}

/**
 * Forward a WebSocket upgrade to the backend and splice the two sockets.
 *
 * Cloudflare returns the upstream `webSocket` on a 101 response, so the relay is
 * a byte pump in both directions with no protocol awareness — which is exactly
 * what keeps VLESS/Trojan/VMess/anything-else working unchanged.
 */
export async function forwardToBackend(
  request: Request,
  cfg: BackendConfig,
): Promise<BackendResult> {
  const target = backendTarget(cfg.url, new URL(request.url));
  if (!target) {
    return { response: new Response('Bad backend URL', { status: 500 }), ok: false };
  }

  const headers = new Headers(request.headers);
  headers.delete('Host');
  headers.delete('Sec-WebSocket-Extensions');
  // cf-* headers describe the CLIENT↔Worker hop and confuse an origin that
  // inspects them; drop them so the backend sees a clean upgrade.
  for (const key of [...headers.keys()]) {
    if (key.toLowerCase().startsWith('cf-')) headers.delete(key);
  }
  headers.set('Connection', 'Upgrade');
  headers.set('Upgrade', 'websocket');
  if (cfg.token) headers.set('X-ForgeEdge-Token', cfg.token);

  let upstream: Response;
  try {
    upstream = await fetch(target, { method: 'GET', headers, redirect: 'manual' });
  } catch (e) {
    return {
      response: new Response(`Backend unreachable: ${e instanceof Error ? e.message : String(e)}`, { status: 502 }),
      ok: false,
    };
  }

  const upstreamWS = (upstream as unknown as { webSocket?: WebSocket }).webSocket;
  if (upstream.status !== 101 || !upstreamWS) {
    return {
      response: new Response(`Backend refused the upgrade (status ${upstream.status})`, { status: 502 }),
      ok: false,
    };
  }

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();
  server.binaryType = 'arraybuffer';
  upstreamWS.accept();
  upstreamWS.binaryType = 'arraybuffer';

  const relay = (from: WebSocket, to: WebSocket) => {
    from.addEventListener('message', (ev: MessageEvent) => {
      try { to.send(ev.data as ArrayBuffer | string); } catch { /* peer gone */ }
    });
    from.addEventListener('close', (ev: CloseEvent) => {
      try { to.close(ev.code || 1000, ev.reason); } catch { /* already closed */ }
    });
    from.addEventListener('error', () => {
      try { to.close(1011, 'relay error'); } catch { /* already closed */ }
    });
  };

  relay(server, upstreamWS);
  relay(upstreamWS, server);

  return { response: new Response(null, { status: 101, webSocket: client }), ok: true };
}

/**
 * Ask the backend to run a task the Worker cannot — today, the UDP probe behind
 * the WARP endpoint scanner. Returns null when there is no usable backend, so
 * callers degrade to "candidates, unmeasured" instead of inventing latencies.
 */
export async function backendControl<T>(
  cfg: BackendConfig,
  path: string,
  body: unknown,
): Promise<T | null> {
  if (!cfg.enabled || !cfg.url) return null;
  let base: URL;
  try { base = new URL(cfg.url); } catch { return null; }
  if (base.protocol === 'ws:') base.protocol = 'http:';
  if (base.protocol === 'wss:') base.protocol = 'https:';
  base.pathname = path;
  base.search = '';

  try {
    const res = await fetch(base.toString(), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cfg.token ? { 'X-ForgeEdge-Token': cfg.token } : {}),
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}
