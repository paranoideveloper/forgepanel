/**
 * WebSocket ⇄ stream plumbing shared by the VLESS and Trojan handlers.
 */

export const WS_OPEN = 1;
export const WS_CLOSING = 2;

/** Decode the `sec-websocket-protocol` early-data header (base64url, per `?ed=`). */
export function decodeEarlyData(header: string): { data: ArrayBuffer | null; error: Error | null } {
  if (!header) return { data: null, error: null };
  try {
    const normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(normalized);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return { data: bytes.buffer as ArrayBuffer, error: null };
  } catch (e) {
    return { data: null, error: e instanceof Error ? e : new Error(String(e)) };
  }
}

/** Wrap the server side of a WebSocketPair as a ReadableStream of chunks. */
export function readableFromWebSocket(
  ws: WebSocket,
  earlyDataHeader: string,
  log: (msg: string, extra?: string) => void,
): ReadableStream {
  let cancelled = false;

  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', (event: MessageEvent) => {
        if (cancelled) return;
        controller.enqueue(event.data);
      });

      ws.addEventListener('close', () => {
        safeCloseWebSocket(ws);
        if (cancelled) return;
        try { controller.close(); } catch { /* already closed */ }
      });

      ws.addEventListener('error', (err: Event) => {
        log('websocket error');
        controller.error(err);
      });

      const { data, error } = decodeEarlyData(earlyDataHeader);
      if (error) controller.error(error);
      else if (data) controller.enqueue(data);
    },
    cancel(reason) {
      if (cancelled) return;
      log(`readable cancelled: ${String(reason)}`);
      cancelled = true;
      safeCloseWebSocket(ws);
    },
  });
}

export function safeCloseWebSocket(ws: WebSocket): void {
  try {
    if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close();
  } catch (e) {
    console.error('safeCloseWebSocket', e);
  }
}

export function safeCloseSocket(socket: { close(): unknown } | null): void {
  if (!socket) return;
  try { socket.close(); } catch (e) { console.error('safeCloseSocket', e); }
}

/** Concatenate a header and a chunk without a Blob round-trip. */
export function concatBytes(head: Uint8Array, tail: ArrayBuffer | Uint8Array): Uint8Array {
  const t = tail instanceof Uint8Array ? tail : new Uint8Array(tail);
  const out = new Uint8Array(head.length + t.length);
  out.set(head, 0);
  out.set(t, head.length);
  return out;
}
