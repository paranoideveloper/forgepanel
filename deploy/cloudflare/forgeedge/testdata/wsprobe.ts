/**
 * Live data-path probe: speak real VLESS and real Trojan over a real WebSocket
 * to a running ForgeEdge Worker, and prove bytes reach an origin and come back.
 *
 * This is the check the unit tests cannot make. `test/framing.test.ts` proves
 * the parsers agree with the spec; this proves the whole path — WebSocket
 * upgrade, early-data header, header parse, `cloudflare:sockets` connect,
 * bidirectional pump — actually moves traffic under workerd.
 *
 *   bun run testdata/wsprobe.ts <worker-origin> <vless-uuid> <trojan-password>
 *
 * It starts its own origin server on a free port and asks the Worker to proxy
 * to it, so there is no external dependency and no ambiguity about what
 * answered.
 */

import { createHash } from 'node:crypto';

const [, , origin, uuid, trojanPassword] = process.argv;
if (!origin || !uuid || !trojanPassword) {
  console.error('usage: bun run testdata/wsprobe.ts <worker-origin> <uuid> <trojan-password>');
  process.exit(2);
}

const TE = new TextEncoder();
const TD = new TextDecoder();

function uuidToBytes(u: string): Uint8Array {
  const hex = u.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const be16 = (n: number) => new Uint8Array([(n >> 8) & 0xff, n & 0xff]);

/** VLESS: ver | uuid | optLen | cmd | port | atype | addr | payload */
function vlessRequest(host: string, port: number, payload: Uint8Array): Uint8Array {
  return concat(
    new Uint8Array([0]),
    uuidToBytes(uuid),
    new Uint8Array([0]),
    new Uint8Array([1]),
    be16(port),
    new Uint8Array([2, host.length]),
    TE.encode(host),
    payload,
  );
}

/** Trojan: hex(sha224(pw)) | CRLF | cmd | atype | addr | port | CRLF | payload */
function trojanRequest(host: string, port: number, payload: Uint8Array): Uint8Array {
  const digest = createHash('sha224').update(trojanPassword).digest('hex');
  return concat(
    TE.encode(digest),
    new Uint8Array([0x0d, 0x0a, 1, 3, host.length]),
    TE.encode(host),
    be16(port),
    new Uint8Array([0x0d, 0x0a]),
    payload,
  );
}

const MARKER = 'forgeedge-origin-ok';

/** A one-shot HTTP origin, so the reply is unmistakably ours. */
function startOrigin(): { port: number; stop: () => void } {
  const server = Bun.serve({
    port: 0,
    fetch: (req) => new Response(`${MARKER} path=${new URL(req.url).pathname}`, {
      headers: { 'content-type': 'text/plain' },
    }),
  });
  return { port: server.port, stop: () => server.stop(true) };
}

async function probe(label: string, wsPath: string, build: (h: string, p: number, b: Uint8Array) => Uint8Array) {
  const originServer = startOrigin();
  const target = `127.0.0.1`;
  const httpGet = TE.encode(`GET /probe HTTP/1.1\r\nHost: ${target}\r\nConnection: close\r\n\r\n`);
  const request = build(target, originServer.port, httpGet);

  const url = origin.replace(/^http/, 'ws') + wsPath;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  const received: Uint8Array[] = [];
  const done = new Promise<'ok' | 'timeout' | string>((resolve) => {
    const timer = setTimeout(() => resolve('timeout'), 8000);
    ws.onopen = () => ws.send(request);
    ws.onmessage = (ev) => {
      received.push(new Uint8Array(ev.data as ArrayBuffer));
      const text = TD.decode(concat(...received));
      if (text.includes(MARKER)) { clearTimeout(timer); resolve('ok'); }
    };
    ws.onerror = () => { clearTimeout(timer); resolve('websocket error'); };
    ws.onclose = (ev) => {
      clearTimeout(timer);
      const text = TD.decode(concat(...received));
      resolve(text.includes(MARKER) ? 'ok' : `closed ${ev.code} ${ev.reason || ''}`.trim());
    };
  });

  const result = await done;
  try { ws.close(); } catch { /* already closed */ }
  originServer.stop();

  const body = TD.decode(concat(...received));
  if (result === 'ok') {
    console.log(`  ${label}: OK — origin answered through the tunnel`);
    console.log(`    bytes back: ${body.length}, contains marker: true`);
    console.log(`    first line: ${body.split('\r\n')[0].replace(/^\0\0/, '[vless hdr]')}`);
    return true;
  }
  console.log(`  ${label}: FAILED — ${result}`);
  if (body) console.log(`    partial: ${JSON.stringify(body.slice(0, 120))}`);
  return false;
}

const okVless = await probe('VLESS  over WS', '/vl/livecheck', vlessRequest);
const okTrojan = await probe('Trojan over WS', '/tr/livecheck', trojanRequest);

console.log(okVless && okTrojan ? '\nDATA PATH: both protocols proxied real TCP.' : '\nDATA PATH: FAILED');
process.exit(okVless && okTrojan ? 0 : 1);
