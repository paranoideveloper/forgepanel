/**
 * VLESS and Trojan request-header parsers.
 *
 * These are deliberately PURE functions over an ArrayBuffer with no Worker
 * globals, so the wire format can be unit-tested without workerd
 * (`test/vless.test.ts`, `test/trojan.test.ts`). The socket plumbing that uses
 * them lives in vless.ts / trojan.ts.
 *
 * Both formats are parsed defensively: every length read is bounds-checked
 * against the buffer before it is used, because the first bytes off a
 * WebSocket are fully attacker-controlled.
 */

import { sha224Hex } from '../common/sha';

export interface ParsedHeader {
  ok: false;
  message: string;
}

export interface VlessHeader {
  ok: true;
  version: number;
  isUDP: boolean;
  addressType: number;
  addressRemote: string;
  portRemote: number;
  /** Offset in the original buffer where payload begins. */
  rawDataIndex: number;
}

export interface TrojanHeader {
  ok: true;
  command: number;
  addressType: number;
  addressRemote: string;
  portRemote: number;
  rawDataIndex: number;
}

const TD = new TextDecoder();

const BYTE_TO_HEX: string[] = [];
for (let i = 0; i < 256; i++) BYTE_TO_HEX.push((i + 256).toString(16).slice(1));

/** Canonical 8-4-4-4-12 lowercase rendering of 16 raw bytes. */
export function uuidFromBytes(a: Uint8Array, off = 0): string {
  const h = BYTE_TO_HEX;
  return (
    h[a[off]] + h[a[off + 1]] + h[a[off + 2]] + h[a[off + 3]] + '-' +
    h[a[off + 4]] + h[a[off + 5]] + '-' +
    h[a[off + 6]] + h[a[off + 7]] + '-' +
    h[a[off + 8]] + h[a[off + 9]] + '-' +
    h[a[off + 10]] + h[a[off + 11]] + h[a[off + 12]] + h[a[off + 13]] + h[a[off + 14]] + h[a[off + 15]]
  );
}

/** Pack a UUID string back into 16 bytes. Used by the tests to build fixtures. */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) throw new Error(`invalid uuid: ${uuid}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Read an address of `type` starting at `idx`.
 * Types: 1 = IPv4, 2 = domain (VLESS) , 3 = IPv6 (VLESS) — Trojan/SOCKS5 uses
 * 1 = IPv4, 3 = domain, 4 = IPv6, so the caller passes a mapping.
 */
function readAddress(
  view: DataView, bytes: Uint8Array, idx: number, kind: 'ipv4' | 'domain' | 'ipv6',
): { addr: string; next: number } | null {
  if (kind === 'ipv4') {
    if (idx + 4 > bytes.length) return null;
    return { addr: `${bytes[idx]}.${bytes[idx + 1]}.${bytes[idx + 2]}.${bytes[idx + 3]}`, next: idx + 4 };
  }
  if (kind === 'domain') {
    if (idx + 1 > bytes.length) return null;
    const len = bytes[idx];
    if (len === 0 || idx + 1 + len > bytes.length) return null;
    return { addr: TD.decode(bytes.subarray(idx + 1, idx + 1 + len)), next: idx + 1 + len };
  }
  if (idx + 16 > bytes.length) return null;
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) parts.push(view.getUint16(idx + i * 2).toString(16));
  return { addr: parts.join(':'), next: idx + 16 };
}

/**
 * VLESS request header (v0):
 *   1 byte version | 16 bytes UUID | 1 byte optLen | optLen bytes addons
 *   | 1 byte command | 2 bytes port (BE) | 1 byte atype | address | payload
 */
export function parseVlessHeader(buf: ArrayBuffer, expectedUUID: string): VlessHeader | ParsedHeader {
  if (buf.byteLength < 24) return { ok: false, message: 'invalid data' };
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);

  const version = bytes[0];
  const uuid = uuidFromBytes(bytes, 1);
  if (uuid !== expectedUUID.toLowerCase()) return { ok: false, message: 'invalid user' };

  const optLength = bytes[17];
  const cmdIndex = 18 + optLength;
  if (cmdIndex + 3 > bytes.length) return { ok: false, message: 'truncated header' };

  const command = bytes[cmdIndex];
  let isUDP = false;
  if (command === 2) isUDP = true;
  else if (command !== 1) {
    return { ok: false, message: `command ${command} is not supported, command 01-tcp,02-udp,03-mux` };
  }

  const portIndex = cmdIndex + 1;
  const portRemote = view.getUint16(portIndex);

  const atypeIndex = portIndex + 2;
  const addressType = bytes[atypeIndex];
  const kind = addressType === 1 ? 'ipv4' : addressType === 2 ? 'domain' : addressType === 3 ? 'ipv6' : null;
  if (!kind) return { ok: false, message: `invalid addressType is ${addressType}` };

  const read = readAddress(view, bytes, atypeIndex + 1, kind);
  if (!read) return { ok: false, message: `truncated address, addressType is ${addressType}` };
  if (!read.addr) return { ok: false, message: `addressValue is empty, addressType is ${addressType}` };

  return {
    ok: true, version, isUDP, addressType,
    addressRemote: read.addr, portRemote, rawDataIndex: read.next,
  };
}

/**
 * Trojan request header:
 *   56 bytes hex(SHA224(password)) | CR LF | 1 byte cmd | 1 byte atype
 *   | address | 2 bytes port (BE) | CR LF | payload
 *
 * Note the trailing CRLF after the port — the payload starts at port+2+2.
 */
export function parseTrojanHeader(buf: ArrayBuffer, password: string): TrojanHeader | ParsedHeader {
  if (buf.byteLength < 60) return { ok: false, message: 'invalid data' };
  const bytes = new Uint8Array(buf);
  const view = new DataView(buf);

  const digest = TD.decode(bytes.subarray(0, 56));
  if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
    return { ok: false, message: 'invalid header format (missing CR LF)' };
  }
  // Constant-time-ish compare: same length by construction, compare every byte.
  const expected = sha224Hex(password);
  let diff = digest.length ^ expected.length;
  for (let i = 0; i < Math.min(digest.length, expected.length); i++) {
    diff |= digest.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  if (diff !== 0) return { ok: false, message: 'invalid password' };

  const cmdIndex = 58;
  if (cmdIndex + 2 > bytes.length) return { ok: false, message: 'invalid SOCKS5 request data' };
  const command = bytes[cmdIndex];
  if (command !== 1) {
    return { ok: false, message: 'unsupported command, only TCP (CONNECT) is allowed' };
  }

  const atype = bytes[cmdIndex + 1];
  const kind = atype === 1 ? 'ipv4' : atype === 3 ? 'domain' : atype === 4 ? 'ipv6' : null;
  if (!kind) return { ok: false, message: `invalid addressType is ${atype}` };

  const read = readAddress(view, bytes, cmdIndex + 2, kind);
  if (!read) return { ok: false, message: `truncated address, addressType is ${atype}` };
  if (!read.addr) return { ok: false, message: `address is empty, addressType is ${atype}` };

  if (read.next + 2 > bytes.length) return { ok: false, message: 'truncated port' };
  const portRemote = view.getUint16(read.next);

  // Skip the port (2 bytes) and the trailing CRLF (2 bytes).
  return {
    ok: true, command, addressType: atype,
    addressRemote: read.addr, portRemote, rawDataIndex: read.next + 4,
  };
}

/**
 * Build the two-byte VLESS response header the server sends before the first
 * chunk of payload: `[version, addonLength=0]`.
 */
export function vlessResponseHeader(version: number): Uint8Array {
  return new Uint8Array([version, 0]);
}
