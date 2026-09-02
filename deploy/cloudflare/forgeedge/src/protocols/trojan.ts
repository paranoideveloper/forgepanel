/**
 * Trojan over WebSocket, terminated at the edge.
 *
 * Trojan's wire format has no UDP ASSOCIATE that a Worker could serve, so only
 * CONNECT is accepted — `parseTrojanHeader` rejects anything else. Full UDP is
 * Backend Mode's job.
 */

import { getGlobalConfig } from '../config/runtime';
import { parseTrojanHeader } from './framing';
import { handleTCPOutbound, type OutboundOptions } from './outbound';
import { readableFromWebSocket, safeCloseSocket, safeCloseWebSocket } from './ws';
import { releaseConnection, type ConnHandle } from './limits';

export interface TrojanHandlerOptions {
  password: string;
  outbound: OutboundOptions;
  /** The limiter slot the router took for this connection, given back on close. */
  handle?: ConnHandle;
}

export function trojanOverWS(request: Request, opts: TrojanHandlerOptions): Response {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
  server.accept();
  server.binaryType = 'arraybuffer';

  // Both events, before anything that can throw — see the same hook in vless.ts.
  server.addEventListener('close', () => releaseConnection(opts.handle));
  server.addEventListener('error', () => releaseConnection(opts.handle));

  let address = '';
  let tag = '';
  const log = (msg: string, extra?: string) => {
    if (getGlobalConfig()?.logLevel === 'none') return;
    console.log(`[trojan ${address}:${tag}] ${msg}`, extra ?? '');
  };

  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  const readable = readableFromWebSocket(server, earlyData, log);

  const remote: { value: Socket | null } = { value: null };

  const sink = new WritableStream({
    async write(chunk: ArrayBuffer) {
      if (remote.value) {
        const writer = remote.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const parsed = parseTrojanHeader(chunk, opts.password);
      if (!parsed.ok) throw new Error(parsed.message);

      address = parsed.addressRemote;
      tag = `${parsed.portRemote} tcp`;

      const payload = new Uint8Array(chunk, parsed.rawDataIndex);
      await handleTCPOutbound(
        remote, parsed.addressRemote, parsed.portRemote,
        payload, server, null, opts.outbound, log,
      );
    },
    close() { safeCloseSocket(remote.value); },
    abort(reason) { log('readable aborted', String(reason)); },
  });

  readable.pipeTo(sink).catch((e) => {
    log('pipeTo error', String(e));
    safeCloseSocket(remote.value);
    safeCloseWebSocket(server);
  });

  return new Response(null, { status: 101, webSocket: client });
}
