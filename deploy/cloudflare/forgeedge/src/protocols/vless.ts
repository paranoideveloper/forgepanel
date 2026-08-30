/**
 * VLESS over WebSocket, terminated at the edge.
 *
 * TCP is proxied through `cloudflare:sockets`. UDP is NOT: a Worker has no UDP
 * socket API at all, so the only UDP a Worker can honestly carry is DNS, which
 * it does by forwarding each datagram to DoH. Anything else (QUIC, WhatsApp/
 * FaceTime/Telegram calls) requires Backend Mode — see `backend.ts`. This is the
 * architectural constraint that shapes the whole product: the edge is a clean
 * TCP entry point, not a full proxy.
 */

import { getGlobalConfig } from '../config/runtime';
import { parseVlessHeader, vlessResponseHeader } from './framing';
import { handleTCPOutbound } from './outbound';
import { readableFromWebSocket, safeCloseSocket, WS_OPEN, concatBytes } from './ws';
import { releaseConnection, type ConnHandle } from './limits';
import type { OutboundOptions } from './outbound';

export interface VlessHandlerOptions {
  uuid: string;
  outbound: OutboundOptions;
  /** Where DNS-over-UDP requests are forwarded. */
  dohUpstream: string;
  /** The limiter slot the router took for this connection, given back on close. */
  handle?: ConnHandle;
}

export function vlessOverWS(request: Request, opts: VlessHandlerOptions): Response {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();
  server.binaryType = 'arraybuffer';

  // Before anything that can throw, and on BOTH events: `close` and `error` are
  // separate listeners on this socket (see ws.ts) and an errored socket need not
  // also close. releaseConnection is idempotent, so one that fires both is
  // counted once.
  server.addEventListener('close', () => releaseConnection(opts.handle));
  server.addEventListener('error', () => releaseConnection(opts.handle));

  let address = '';
  let tag = '';
  const log = (msg: string, extra?: string) => {
    if (getGlobalConfig()?.logLevel === 'none') return;
    console.log(`[vless ${address}:${tag}] ${msg}`, extra ?? '');
  };

  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  const readable = readableFromWebSocket(server, earlyData, log);

  const remote: { value: Socket | null } = { value: null };
  let udpWrite: ((chunk: ArrayBuffer) => Promise<void>) | null = null;
  let isDns = false;

  const sink = new WritableStream({
    async write(chunk: ArrayBuffer) {
      if (isDns && udpWrite) return udpWrite(chunk);

      if (remote.value) {
        const writer = remote.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const parsed = parseVlessHeader(chunk, opts.uuid);
      if (!parsed.ok) throw new Error(parsed.message);

      address = parsed.addressRemote;
      tag = `${parsed.portRemote} ${parsed.isUDP ? 'udp' : 'tcp'}`;

      const responseHeader = vlessResponseHeader(parsed.version);
      const payload = new Uint8Array(chunk, parsed.rawDataIndex);

      if (parsed.isUDP) {
        if (parsed.portRemote !== 53) {
          // Be explicit rather than opening a socket that silently drops
          // datagrams: the client should fail fast and try another node.
          throw new Error('UDP is only proxied for DNS (port 53); enable Backend Mode for full UDP');
        }
        isDns = true;
        udpWrite = makeDnsRelay(server, responseHeader, opts.dohUpstream, log);
        await udpWrite(payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength));
        return;
      }

      await handleTCPOutbound(
        remote, parsed.addressRemote, parsed.portRemote,
        payload, server, responseHeader, opts.outbound, log,
      );
    },
    close() { safeCloseSocket(remote.value); },
    abort(reason) { log('readable aborted', String(reason)); },
  });

  readable.pipeTo(sink).catch((e) => {
    // The client→remote direction ending is NOT a reason to tear down the
    // WebSocket: the remote→ws pump may still be flushing the response, and
    // force-closing the socket here truncates it (curl sees "empty reply",
    // browsers see ERR_CONTENT_LENGTH_MISMATCH). This mirrors the proven
    // edgetunnel flow, which lets the client close the WebSocket once it has
    // read the response; the remote socket is reclaimed by the sink's close()
    // handler or the pump's own error path.
    log('client->remote pipe ended', String(e));
  });

  return new Response(null, { status: 101, webSocket: client });
}

/**
 * VLESS UDP framing is `[2-byte length][payload]…`. Each datagram is forwarded
 * to DoH and the reply is framed back the same way.
 */
function makeDnsRelay(
  ws: WebSocket,
  responseHeader: Uint8Array,
  dohUpstream: string,
  log: (m: string, e?: string) => void,
): (chunk: ArrayBuffer) => Promise<void> {
  let headerSent = false;

  const transform = new TransformStream<ArrayBuffer, Uint8Array>({
    transform(chunk, controller) {
      const view = new DataView(chunk);
      let i = 0;
      while (i + 2 <= chunk.byteLength) {
        const len = view.getUint16(i);
        if (i + 2 + len > chunk.byteLength) break;
        controller.enqueue(new Uint8Array(chunk, i + 2, len));
        i += 2 + len;
      }
    },
  });

  transform.readable.pipeTo(new WritableStream({
    async write(query) {
      const res = await fetch(dohUpstream || 'https://cloudflare-dns.com/dns-query', {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: query,
      });
      const answer = new Uint8Array(await res.arrayBuffer());
      const size = new Uint8Array([(answer.length >> 8) & 0xff, answer.length & 0xff]);
      if (ws.readyState !== WS_OPEN) return;
      const framed = concatBytes(size, answer);
      ws.send(headerSent ? framed : concatBytes(responseHeader, framed));
      headerSent = true;
    },
  })).catch((e) => log('dns relay error', String(e)));

  const writer = transform.writable.getWriter();
  return async (chunk: ArrayBuffer) => { await writer.write(chunk); };
}
