/**
 * VLESS and Trojan wire-format parsers.
 *
 * The fixtures are built byte by byte from the protocol specs rather than
 * captured from a client, so a failure points at the exact field that moved.
 * Every rejection path is exercised too: these parse the first bytes off an
 * unauthenticated WebSocket, so "rejects garbage" is as load-bearing as
 * "accepts a valid header".
 */

import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
  parseVlessHeader, parseTrojanHeader, uuidFromBytes, uuidToBytes, vlessResponseHeader,
} from '../src/protocols/framing';

const UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811';
const TE = new TextEncoder();

function bytes(...parts: (number | number[] | Uint8Array | string)[]): ArrayBuffer {
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    if (typeof p === 'number') chunks.push(new Uint8Array([p]));
    else if (typeof p === 'string') chunks.push(TE.encode(p));
    else if (p instanceof Uint8Array) chunks.push(p);
    else chunks.push(new Uint8Array(p));
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out.buffer;
}

const be16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];

// --- VLESS ------------------------------------------------------------------

function vlessRequest(opts: {
  uuid?: string; command?: number; port?: number; atype?: number;
  address?: number[] | string; optLen?: number; payload?: string;
}): ArrayBuffer {
  const uuid = uuidToBytes(opts.uuid ?? UUID);
  const optLen = opts.optLen ?? 0;
  const addr = typeof opts.address === 'string'
    ? [opts.address.length, ...Array.from(TE.encode(opts.address))]
    : (opts.address ?? [1, 2, 3, 4]);
  return bytes(
    0,                                   // version
    uuid,
    optLen,
    new Uint8Array(optLen),              // addons
    opts.command ?? 1,
    be16(opts.port ?? 443),
    opts.atype ?? 1,
    addr,
    opts.payload ?? '',
  );
}

describe('VLESS header', () => {
  test('uuid round-trips through bytes', () => {
    expect(uuidFromBytes(uuidToBytes(UUID))).toBe(UUID);
  });

  test('parses an IPv4 CONNECT with payload', () => {
    const buf = vlessRequest({ atype: 1, address: [93, 184, 216, 34], port: 443, payload: 'GET / HTTP/1.1\r\n' });
    const r = parseVlessHeader(buf, UUID);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('93.184.216.34');
    expect(r.portRemote).toBe(443);
    expect(r.isUDP).toBe(false);
    expect(r.version).toBe(0);
    expect(new TextDecoder().decode(new Uint8Array(buf, r.rawDataIndex))).toBe('GET / HTTP/1.1\r\n');
  });

  test('parses a domain address', () => {
    const r = parseVlessHeader(vlessRequest({ atype: 2, address: 'example.com', port: 8443 }), UUID);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('example.com');
    expect(r.portRemote).toBe(8443);
  });

  test('parses an IPv6 address', () => {
    const v6 = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x84, 0xe5];
    const r = parseVlessHeader(vlessRequest({ atype: 3, address: v6 }), UUID);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('2606:4700:0:0:0:0:6810:84e5');
  });

  test('honours a non-zero addon length', () => {
    const r = parseVlessHeader(vlessRequest({ optLen: 7, atype: 2, address: 'example.com' }), UUID);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('example.com');
  });

  test('flags UDP for command 2', () => {
    const r = parseVlessHeader(vlessRequest({ command: 2, port: 53 }), UUID);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.isUDP).toBe(true);
  });

  test('rejects a wrong UUID', () => {
    const r = parseVlessHeader(vlessRequest({ uuid: '00000000-0000-4000-8000-000000000000' }), UUID);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toBe('invalid user');
  });

  test('rejects mux (command 3) and unknown commands', () => {
    for (const cmd of [0, 3, 9]) {
      const r = parseVlessHeader(vlessRequest({ command: cmd }), UUID);
      expect(r.ok).toBe(false);
    }
  });

  test('rejects an unknown address type', () => {
    const r = parseVlessHeader(vlessRequest({ atype: 9 }), UUID);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toContain('invalid addressType');
  });

  test('rejects a buffer shorter than the minimum header', () => {
    expect(parseVlessHeader(new ArrayBuffer(23), UUID).ok).toBe(false);
  });

  test('rejects a truncated address instead of reading past the buffer', () => {
    // Claims a 200-byte domain but supplies 4 bytes.
    const buf = bytes(0, uuidToBytes(UUID), 0, 1, be16(443), 2, 200, 'abcd');
    const r = parseVlessHeader(buf, UUID);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toContain('truncated');
  });

  test('rejects an addon length that runs off the end', () => {
    const buf = bytes(0, uuidToBytes(UUID), 250, new Uint8Array(6));
    expect(parseVlessHeader(buf, UUID).ok).toBe(false);
  });

  test('response header is [version, 0]', () => {
    expect(Array.from(vlessResponseHeader(0))).toEqual([0, 0]);
    expect(Array.from(vlessResponseHeader(1))).toEqual([1, 0]);
  });
});

// --- Trojan -----------------------------------------------------------------

function trojanRequest(opts: {
  password?: string; digest?: string; cmd?: number; atype?: number;
  address?: number[] | string; port?: number; payload?: string; crlf?: boolean;
}): ArrayBuffer {
  const digest = opts.digest
    ?? createHash('sha224').update(opts.password ?? 'secret').digest('hex');
  const addr = typeof opts.address === 'string'
    ? [opts.address.length, ...Array.from(TE.encode(opts.address))]
    : (opts.address ?? [1, 2, 3, 4]);
  return bytes(
    digest,
    opts.crlf === false ? [0x00, 0x00] : [0x0d, 0x0a],
    opts.cmd ?? 1,
    opts.atype ?? 1,
    addr,
    be16(opts.port ?? 443),
    [0x0d, 0x0a],
    opts.payload ?? '',
  );
}

describe('Trojan header', () => {
  test('parses an IPv4 CONNECT with payload', () => {
    const buf = trojanRequest({ password: 'secret', address: [93, 184, 216, 34], port: 443, payload: 'hello' });
    const r = parseTrojanHeader(buf, 'secret');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('93.184.216.34');
    expect(r.portRemote).toBe(443);
    expect(new TextDecoder().decode(new Uint8Array(buf, r.rawDataIndex))).toBe('hello');
  });

  test('parses a domain address (atype 3, unlike VLESS)', () => {
    const r = parseTrojanHeader(trojanRequest({ password: 'pw', atype: 3, address: 'example.com', port: 8443 }), 'pw');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('example.com');
    expect(r.portRemote).toBe(8443);
  });

  test('parses an IPv6 address (atype 4, unlike VLESS)', () => {
    const v6 = [0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x84, 0xe5];
    const r = parseTrojanHeader(trojanRequest({ password: 'pw', atype: 4, address: v6 }), 'pw');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.addressRemote).toBe('2606:4700:0:0:0:0:6810:84e5');
  });

  test('rejects a wrong password', () => {
    const r = parseTrojanHeader(trojanRequest({ password: 'secret' }), 'not-the-password');
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toBe('invalid password');
  });

  test('rejects a missing CRLF after the digest', () => {
    const r = parseTrojanHeader(trojanRequest({ password: 'pw', crlf: false }), 'pw');
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toContain('CR LF');
  });

  test('rejects UDP ASSOCIATE — a Worker has no UDP socket to serve it with', () => {
    const r = parseTrojanHeader(trojanRequest({ password: 'pw', cmd: 3 }), 'pw');
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.message).toContain('only TCP');
  });

  test('rejects a short buffer', () => {
    expect(parseTrojanHeader(new ArrayBuffer(59), 'pw').ok).toBe(false);
  });

  test('rejects a truncated address', () => {
    const digest = createHash('sha224').update('pw').digest('hex');
    const buf = bytes(digest, [0x0d, 0x0a], 1, 3, 200, 'abcd');
    const r = parseTrojanHeader(buf, 'pw');
    expect(r.ok).toBe(false);
  });

  test('the digest is a real SHA-224 of the password', () => {
    // Cross-check with node:crypto so a broken SHA-224 cannot pass by agreeing
    // with itself in both the fixture and the parser.
    const digest = createHash('sha224').update('correct horse').digest('hex');
    expect(digest.length).toBe(56);
    const r = parseTrojanHeader(trojanRequest({ digest }), 'correct horse');
    expect(r.ok).toBe(true);
  });
});
