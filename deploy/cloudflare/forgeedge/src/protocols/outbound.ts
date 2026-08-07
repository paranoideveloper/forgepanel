/**
 * The Worker's outbound socket path: open TCP to the requested destination and
 * pump bytes back to the client WebSocket.
 *
 * The retry POLICY (which address to fall back to, and whether there is one at
 * all) lives in retry.ts so it stays testable outside workerd. This file is only
 * the I/O.
 *
 * The retry fires only when the first attempt produced ZERO inbound bytes, which
 * is the signature of a connection that was accepted and then blackholed —
 * exactly what a filtered path looks like, and distinguishable from a
 * destination that simply had nothing to say.
 */

import { connect } from 'cloudflare:sockets';
import { safeCloseSocket, safeCloseWebSocket, WS_OPEN, concatBytes } from './ws';
import { retryTarget, type OutboundOptions } from './retry';

export type { OutboundOptions };
export { retryTarget };

type Log = (msg: string, extra?: string) => void;

/**
 * Connect, write the first payload, then stream both directions.
 * `responseHeader` is VLESS's 2-byte prelude (null for Trojan).
 */
export async function handleTCPOutbound(
  remote: { value: Socket | null },
  address: string,
  port: number,
  firstPayload: Uint8Array,
  ws: WebSocket,
  responseHeader: Uint8Array | null,
  opts: OutboundOptions,
  log: Log,
): Promise<void> {
  const connectAndWrite = async (addr: string, p: number): Promise<Socket> => {
    const sock = connect({ hostname: addr, port: p });
    remote.value = sock;
    log(`connected to ${addr}:${p}`);
    const writer = sock.writable.getWriter();
    await writer.write(firstPayload);
    writer.releaseLock();
    return sock;
  };

  const retry = async (): Promise<void> => {
    const target = await retryTarget(address, port, opts);
    if (!target) {
      log('no retry strategy configured; closing');
      ws.close(1011, 'destination unreachable');
      return;
    }
    log(`direct connection produced no data, retrying via ${target.address}:${target.port}`);
    try {
      const sock = await connectAndWrite(target.address, target.port);
      sock.closed.catch((e: unknown) => log('retry socket closed', String(e)))
        .finally(() => safeCloseWebSocket(ws));
      await pumpToWebSocket(sock, ws, responseHeader, null, log);
    } catch (e) {
      log('retry connection failed', String(e));
      ws.close(1011, 'retry connection failed');
    }
  };

  try {
    const sock = await connectAndWrite(address, port);
    await pumpToWebSocket(sock, ws, responseHeader, retry, log);
  } catch (e) {
    log('connection failed', String(e));
    ws.close(1011, 'connection failed');
  }
}

/** Pipe socket → WebSocket, prefixing `responseHeader` onto the first chunk. */
export async function pumpToWebSocket(
  socket: Socket,
  ws: WebSocket,
  responseHeader: Uint8Array | null,
  retry: (() => Promise<void>) | null,
  log: Log,
): Promise<void> {
  let header = responseHeader;
  let sawData = false;

  const sink = new WritableStream({
    write(chunk: ArrayBuffer | Uint8Array, controller) {
      sawData = true;
      if (ws.readyState !== WS_OPEN) {
        controller.error(new Error('webSocket is not open'));
        return;
      }
      if (header) {
        ws.send(concatBytes(header, chunk));
        header = null;
      } else {
        ws.send(chunk as ArrayBuffer);
      }
    },
    close() { log(`remote readable closed, sawData=${sawData}`); },
    abort(reason) { log('remote readable aborted', String(reason)); safeCloseSocket(socket); },
  });

  try {
    await socket.readable.pipeTo(sink);
  } catch (e) {
    log('pumpToWebSocket exception', String(e));
    safeCloseSocket(socket);
    safeCloseWebSocket(ws);
  }

  if (!sawData && retry) await retry();
}
