/**
 * Cloudflare WARP account provisioning.
 *
 * WARP is registered by POSTing an X25519 public key to the consumer API; the
 * reply carries the peer public key, the assigned IPv6 and the 4-byte client id
 * that becomes WireGuard's `reserved`. Keys are generated with WebCrypto
 * (X25519 is available both in workerd and in modern Node/Bun), so no crypto
 * dependency and no `nodejs_compat` requirement.
 *
 * The two accounts exist for a reason: WARP-on-WARP ("WoW") chains a second
 * account through the first, which is what gets a non-Iranian exit IP out of a
 * connection that Cloudflare would otherwise land back in-country.
 */

import { b64Std } from '../common/encoding';

export interface WarpAccount {
  privateKey: string;
  publicKey: string;
  /** The assigned tunnel address, with its /128. */
  warpIPv6: string;
  /** base64 client id; the first 3 bytes become WireGuard's `reserved`. */
  reserved: string;
}

export interface WarpKeyPair { publicKey: string; privateKey: string }

export async function generateWarpKeys(): Promise<WarpKeyPair> {
  // generateKey's typed overloads return CryptoKey | CryptoKeyPair; X25519 is an
  // asymmetric algorithm so it is always a pair at runtime. Cast through unknown
  // (what TS asks for) rather than the direct, rejected CryptoKeyPair assertion.
  const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']) as unknown as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey) as ArrayBuffer);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey) as ArrayBuffer);
  // PKCS#8 wraps the 32-byte scalar at the very end of the DER structure.
  return { publicKey: b64Std(rawPub), privateKey: b64Std(pkcs8.subarray(pkcs8.length - 32)) };
}

interface WarpRegistration {
  config: {
    client_id: string;
    interface: { addresses: { v4: string; v6: string } };
    peers: { public_key: string }[];
  };
}

async function registerAccount(key: WarpKeyPair): Promise<WarpRegistration> {
  const res = await fetch('https://api.cloudflareclient.com/v0a4005/reg', {
    method: 'POST',
    headers: { 'User-Agent': 'okhttp/3.12.1', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      install_id: '',
      fcm_token: '',
      tos: new Date().toISOString(),
      type: 'Android',
      model: 'PC',
      locale: 'en_US',
      warp_enabled: true,
      key: key.publicKey,
    }),
  });
  if (!res.ok) throw new Error(`WARP registration failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as WarpRegistration;
}

/**
 * Register two fresh accounts. Callers MUST handle the empty return: an
 * unreachable Cloudflare consumer API is common from some colos, and inventing
 * placeholder keys would produce a WireGuard config that silently never
 * connects. No account is better than a fake one.
 */
export async function fetchWarpAccounts(): Promise<WarpAccount[]> {
  const accounts: WarpAccount[] = [];
  for (let i = 0; i < 2; i++) {
    const key = await generateWarpKeys();
    const { config } = await registerAccount(key);
    accounts.push({
      privateKey: key.privateKey,
      publicKey: config.peers[0].public_key,
      warpIPv6: `${config.interface.addresses.v6}/128`,
      reserved: config.client_id,
    });
    // The API rate-limits back-to-back registrations from one IP.
    if (i === 0) await new Promise((r) => setTimeout(r, 2000));
  }
  return accounts;
}

/** base64 client id → the 3 decimal bytes WireGuard's `reserved` expects. */
export function reservedFromClientID(clientID: string): number[] {
  const bin = atob(clientID.replace(/-/g, '+').replace(/_/g, '/'));
  const out: number[] = [];
  for (let i = 0; i < Math.min(3, bin.length); i++) out.push(bin.charCodeAt(i));
  while (out.length < 3) out.push(0);
  return out;
}
