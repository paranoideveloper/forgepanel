/**
 * Synchronous SHA-256 / SHA-224.
 *
 * WHY hand-rolled instead of WebCrypto or `node:crypto`:
 *  - Trojan's wire format hashes the password with SHA-224 and compares the hex
 *    digest inside the first 56 bytes of the stream. WebCrypto has no SHA-224 at
 *    all, and `node:crypto` would pin the Worker to `nodejs_compat` for one hash.
 *  - `model.Normalize()` in Go derives the ShadowTLS inner PSK with a SHA-256
 *    call inside a synchronous function. Mirroring it faithfully requires a
 *    synchronous digest; WebCrypto's `subtle.digest` is async and would force
 *    normalize() to become async, which would then infect every renderer.
 *
 * SHA-224 is SHA-256 with a different IV and the digest truncated to 28 bytes
 * (FIPS 180-4 §6.3). Both are verified against `node:crypto` in the test suite.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const IV256 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const IV224 = new Uint32Array([
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** Core compression over the padded message; returns the 8 state words. */
function digestWords(msg: Uint8Array, iv: Uint32Array): Uint32Array {
  const bitLen = msg.length * 8;
  // Padding: 0x80, then zeros until length ≡ 56 (mod 64), then 64-bit big-endian length.
  const padded = new Uint8Array((((msg.length + 8) >> 6) + 1) << 6);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const dv = new DataView(padded.buffer);
  // JS numbers hold the full 53-bit range; a Worker will never hash 2^53 bits.
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);

  const h = new Uint32Array(iv);
  const w = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;

      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  return h;
}

function wordsToBytes(h: Uint32Array, words: number): Uint8Array {
  const out = new Uint8Array(words * 4);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < words; i++) dv.setUint32(i * 4, h[i]);
  return out;
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return wordsToBytes(digestWords(data, IV256), 8);
}

/** SHA-224: SHA-256's schedule with the FIPS 180-4 §5.3.2 IV, truncated to 224 bits. */
export function sha224Bytes(data: Uint8Array): Uint8Array {
  return wordsToBytes(digestWords(data, IV224), 7);
}

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

const TE = new TextEncoder();

export function sha256Hex(input: string | Uint8Array): string {
  return toHex(sha256Bytes(typeof input === 'string' ? TE.encode(input) : input));
}

/** Trojan's password digest: lowercase hex of SHA-224 over the UTF-8 password. */
export function sha224Hex(input: string | Uint8Array): string {
  return toHex(sha224Bytes(typeof input === 'string' ? TE.encode(input) : input));
}
