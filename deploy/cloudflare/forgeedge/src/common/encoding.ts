/**
 * Byte-exact mirrors of the Go encoders used by `internal/protocol/export`.
 *
 * The edge and the VPS panel emit entries into the SAME subscription. If the two
 * escape a path or order a query differently, the same node yields two different
 * links and dedup/golden tests fall apart. `URLSearchParams` is NOT a substitute
 * for `url.Values.Encode()`: it leaves `/`, `:` and `*` unescaped and does not
 * sort. So the Go rules are reimplemented here, exactly.
 */

const TE = new TextEncoder();
const TD = new TextDecoder();

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

const STD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function b64Encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63];
    if (pad) out += '==';
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63];
    if (pad) out += '=';
  }
  return out;
}

function b64Decode(s: string, alphabet: string): Uint8Array {
  const lookup = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) lookup[alphabet.charCodeAt(i)] = i;
  const clean = s.replace(/[=\s]/g, '');
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let acc = 0, bits = 0, o = 0;
  for (let i = 0; i < clean.length; i++) {
    const v = lookup[clean.charCodeAt(i)];
    if (v < 0) throw new Error(`invalid base64 character at ${i}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

/** Go `base64.StdEncoding.EncodeToString`. */
export const b64Std = (bytes: Uint8Array): string => b64Encode(bytes, STD_ALPHABET, true);
/** Go `base64.RawURLEncoding.EncodeToString`. */
export const b64RawURL = (bytes: Uint8Array): string => b64Encode(bytes, URL_ALPHABET, false);
/** Go `base64.StdEncoding.DecodeString` (padding optional, whitespace ignored). */
export const b64StdDecode = (s: string): Uint8Array => b64Decode(s, STD_ALPHABET);
/** Accepts both the std and the URL alphabet, with or without padding. */
export const b64AnyDecode = (s: string): Uint8Array =>
  b64Decode(s.replace(/-/g, '+').replace(/_/g, '/'), STD_ALPHABET);

export const b64EncodeUtf8 = (s: string): string => b64Std(TE.encode(s));
export const b64DecodeUtf8 = (s: string): string => TD.decode(b64AnyDecode(s));

// ---------------------------------------------------------------------------
// net/url escaping (Go net/url shouldEscape)
// ---------------------------------------------------------------------------

function isAlphaNum(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
}

/** Go's §2.3 unreserved marks: - _ . ~ */
function isUnreservedMark(c: number): boolean {
  return c === 0x2d || c === 0x5f || c === 0x2e || c === 0x7e;
}

/** Reserved set Go treats specially per encoding mode: $ & + , / : ; = ? @ */
const RESERVED = new Set([0x24, 0x26, 0x2b, 0x2c, 0x2f, 0x3a, 0x3b, 0x3d, 0x3f, 0x40]);

type Mode = 'query' | 'pathSegment';

function shouldEscape(c: number, mode: Mode): boolean {
  if (isAlphaNum(c)) return false;
  if (isUnreservedMark(c)) return false;
  if (RESERVED.has(c)) {
    if (mode === 'query') return true;
    // encodePathSegment: escape only / ; , ?
    return c === 0x2f || c === 0x3b || c === 0x2c || c === 0x3f;
  }
  return true;
}

function escape(s: string, mode: Mode): string {
  const bytes = TE.encode(s);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c === 0x20 && mode === 'query') {
      out += '+';
    } else if (shouldEscape(c, mode)) {
      out += '%' + c.toString(16).toUpperCase().padStart(2, '0');
    } else {
      out += String.fromCharCode(c);
    }
  }
  return out;
}

/** Go `url.QueryEscape`: everything but alphanumerics and `-_.~`; space becomes `+`. */
export const goQueryEscape = (s: string): string => escape(s, 'query');

/** Go `url.PathEscape`: also leaves `$ & + : = @` bare; escapes `/ ; , ?`; space becomes `%20`. */
export const goPathEscape = (s: string): string => escape(s, 'pathSegment');

/**
 * Go `url.Values.Encode()`: keys sorted lexicographically, values in insertion
 * order within a key, `QueryEscape(k)=QueryEscape(v)` joined with `&`.
 */
export function goEncodeQuery(values: Map<string, string[]>): string {
  const keys = [...values.keys()].sort();
  const parts: string[] = [];
  for (const k of keys) {
    const ek = goQueryEscape(k);
    for (const v of values.get(k)!) parts.push(`${ek}=${goQueryEscape(v)}`);
  }
  return parts.join('&');
}

/** Tiny builder with the `url.Values.Set` semantics the Go exporters use. */
export class Values {
  private m = new Map<string, string[]>();
  set(key: string, value: string): void { this.m.set(key, [value]); }
  add(key: string, value: string): void {
    const cur = this.m.get(key);
    if (cur) cur.push(value); else this.m.set(key, [value]);
  }
  get(key: string): string | undefined { return this.m.get(key)?.[0]; }
  has(key: string): boolean { return this.m.has(key); }
  get size(): number { return this.m.size; }
  /** Mirrors `export.encodeQuery`: an empty Values renders as the empty string. */
  encode(): string { return this.m.size === 0 ? '' : goEncodeQuery(this.m); }
}
