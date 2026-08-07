/**
 * Clean-IP reachability probing — the part that needs a socket.
 *
 * A bare TCP connect proves nothing: Cloudflare accepts on every edge IP, and a
 * DPI middlebox will happily complete a handshake it intends to drop. So this
 * speaks plaintext HTTP/1.1 to :443 and requires the reply to be Cloudflare's
 * own 400 carrying a `cf-ray` header. That pair only comes from a real
 * Cloudflare edge that is actually passing traffic, which is what "clean" has to
 * mean for this to be worth anything.
 */

import { connect } from 'cloudflare:sockets';
import { parseHostPort } from '../common/net';

export interface ReachabilityResult {
  target: string;
  ok: boolean;
  elapsedMs: number;
  detail: string;
}

export async function probeCleanIP(target: string, timeoutMs = 5000): Promise<ReachabilityResult> {
  const start = Date.now();
  const { host, port } = parseHostPort(target, true);
  const dialPort = port || 443;

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('timeout')), timeoutMs));

  try {
    const socket = connect({ hostname: host, port: dialPort });
    const writer = socket.writable.getWriter();
    const req = 'GET /__down?bytes=1 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n';
    await writer.write(new TextEncoder().encode(req));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const { value, done } = await Promise.race([reader.read(), timeout]);
    reader.releaseLock();
    await socket.close().catch(() => { /* already gone */ });

    if (done || !value) return { target, ok: false, elapsedMs: Date.now() - start, detail: 'no response' };

    const text = new TextDecoder().decode(value as Uint8Array);
    const isCfError = /^HTTP\/1\.[01] 400/.test(text);
    const hasCfRay = /cf-ray:/i.test(text);
    return {
      target,
      ok: isCfError && hasCfRay,
      elapsedMs: Date.now() - start,
      detail: isCfError && hasCfRay ? 'cloudflare edge' : text.slice(0, 60).replace(/\s+/g, ' '),
    };
  } catch (e) {
    return { target, ok: false, elapsedMs: Date.now() - start, detail: e instanceof Error ? e.message : String(e) };
  }
}
