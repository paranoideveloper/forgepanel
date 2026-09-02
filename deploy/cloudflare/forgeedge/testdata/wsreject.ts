/**
 * Negative data-path probe: a WebSocket that presents the WRONG credential must
 * be closed, not proxied.
 *
 * The VLESS/Trojan paths are the one part of ForgeEdge that is deliberately NOT
 * behind the secure path — they are handed to every subscriber inside their
 * config, so the credential is the only thing standing between an internet
 * scanner and an open proxy. This asserts that it holds.
 *
 *   bun run testdata/wsreject.ts <worker-origin>
 */

import { createHash } from 'node:crypto';

const [, , origin] = process.argv;
if (!origin) { console.error('usage: bun run testdata/wsreject.ts <worker-origin>'); process.exit(2); }

const TE = new TextEncoder();

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const be16 = (n: number) => new Uint8Array([(n >> 8) & 0xff, n & 0xff]);

function uuidToBytes(u: string): Uint8Array {
  const hex = u.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const host = 'example.com';

const cases: { label: string; path: string; payload: Uint8Array }[] = [
  {
    label: 'VLESS with a wrong UUID',
    path: '/vl/reject',
    payload: concat(
      new Uint8Array([0]), uuidToBytes('00000000-0000-4000-8000-000000000000'),
      new Uint8Array([0, 1]), be16(80), new Uint8Array([2, host.length]), TE.encode(host)),
  },
  {
    label: 'Trojan with a wrong password',
    path: '/tr/reject',
    payload: concat(
      TE.encode(createHash('sha224').update('definitely-not-the-password').digest('hex')),
      new Uint8Array([0x0d, 0x0a, 1, 3, host.length]), TE.encode(host), be16(80),
      new Uint8Array([0x0d, 0x0a])),
  },
  {
    label: 'VLESS with UDP to a non-DNS port',
    path: '/vl/reject',
    payload: concat(
      new Uint8Array([0]), uuidToBytes('00000000-0000-4000-8000-000000000000'),
      new Uint8Array([0, 2]), be16(4433), new Uint8Array([2, host.length]), TE.encode(host)),
  },
  { label: 'garbage bytes', path: '/vl/reject', payload: new Uint8Array(64).fill(0x41) },
];

let allRejected = true;

for (const c of cases) {
  const ws = new WebSocket(origin.replace(/^http/, 'ws') + c.path);
  ws.binaryType = 'arraybuffer';
  let gotData = false;

  const outcome = await new Promise<string>((resolve) => {
    const timer = setTimeout(() => resolve('still open after 4s'), 4000);
    ws.onopen = () => ws.send(c.payload);
    ws.onmessage = () => { gotData = true; };
    ws.onerror = () => { clearTimeout(timer); resolve('errored'); };
    ws.onclose = (ev) => { clearTimeout(timer); resolve(`closed ${ev.code}`); };
  });
  try { ws.close(); } catch { /* already closed */ }

  const rejected = !gotData && outcome !== 'still open after 4s';
  if (!rejected) allRejected = false;
  console.log(`  ${rejected ? 'REJECTED' : 'LEAKED  '} — ${c.label} (${outcome}, data forwarded: ${gotData})`);
}

console.log(allRejected ? '\nAUTH: every bad credential was refused.' : '\nAUTH: FAILED — something got through.');
process.exit(allRejected ? 0 : 1);
