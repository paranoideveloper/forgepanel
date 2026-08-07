/**
 * WARP / WireGuard client-config generation.
 *
 * Two variants:
 *   plain — a standard wg-quick `.conf` any WireGuard client accepts.
 *   pro   — the same tunnel plus AmneziaWG's junk-packet obfuscation (Jc/Jmin/
 *           Jmax/S1/S2/H1..H4), which is what survives a DPI that fingerprints
 *           WireGuard's fixed 148-byte handshake. It needs an Amnezia-aware
 *           client (Amnezia, WG Tunnel, mihomo's amnezia-wg-option).
 *
 * The canonical model already has both shapes (`wireguard` / `amneziawg`), so
 * these also emit `model.Node`s and flow into the same subscription as
 * everything else.
 */

import type { Node } from '../model/node';
import { normalize } from '../model/normalize';
import type { WarpConfig } from '../config/schema';
import { parseHostPort } from '../common/net';
import { type WarpAccount, reservedFromClientID } from './account';

/** WARP's fixed client-side tunnel addresses. */
const WARP_V4 = '172.16.0.2/32';
/** 1280 keeps the tunnelled MTU inside every path Cloudflare's anycast may take. */
const WARP_MTU = 1280;

/**
 * The AmneziaWG parameters used for the "pro" variant. S1/S2 are 0 and H1..H4
 * are 1..4 because Cloudflare's WARP server is NOT AmneziaWG-aware: only the
 * junk packets (Jc/Jmin/Jmax), which are discarded by a standard peer, can be
 * used. Changing the header magics would make the server drop the handshake.
 */
export interface AmneziaTuning {
  jc: number; jmin: number; jmax: number;
  s1: number; s2: number;
  h1: number; h2: number; h3: number; h4: number;
}

export function amneziaTuning(w: WarpConfig): AmneziaTuning {
  return {
    jc: w.amneziaNoiseCount,
    jmin: w.amneziaNoiseSizeMin,
    jmax: w.amneziaNoiseSizeMax,
    s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4,
  };
}

/** wg-quick `.conf` text. `pro` adds the AmneziaWG lines. */
export function wireguardConf(
  account: WarpAccount, endpoint: string, w: WarpConfig, pro: boolean,
): string {
  const lines = [
    '[Interface]',
    `PrivateKey = ${account.privateKey}`,
    `Address = ${WARP_V4}, ${account.warpIPv6}`,
    `DNS = ${w.remoteDNS}`,
    `MTU = ${WARP_MTU}`,
  ];
  if (pro) {
    const a = amneziaTuning(w);
    lines.push(
      `Jc = ${a.jc}`, `Jmin = ${a.jmin}`, `Jmax = ${a.jmax}`,
      `S1 = ${a.s1}`, `S2 = ${a.s2}`,
      `H1 = ${a.h1}`, `H2 = ${a.h2}`, `H3 = ${a.h3}`, `H4 = ${a.h4}`,
    );
  }
  lines.push(
    '',
    '[Peer]',
    `PublicKey = ${account.publicKey}`,
    'AllowedIPs = 0.0.0.0/0, ::/0',
    `Endpoint = ${endpoint}`,
    'PersistentKeepalive = 25',
  );
  return lines.join('\n');
}

/**
 * The same tunnel as a canonical Node, so it can ride in the combined
 * subscription instead of being a separate download.
 *
 * `peer_private_key` carries the CLIENT key because that is the field every
 * renderer reads for a client-side config (see render/singbox.go's wireguard
 * branch); `private_key` is the server's and is deliberately left empty.
 */
export function warpNode(
  account: WarpAccount, endpoint: string, w: WarpConfig, pro: boolean, remark: string,
): Node {
  const { host, port } = parseHostPort(endpoint, false);
  const reserved = w.reservedBytes ? reservedFromClientID(account.reserved) : [0, 0, 0];

  const base = {
    peer_private_key: account.privateKey,
    private_key: account.privateKey,
    public_key: account.publicKey,
    local_address: [WARP_V4, account.warpIPv6],
    allowed_ips: ['0.0.0.0/0', '::/0'],
    mtu: WARP_MTU,
    persistent_keepalive: 25,
    reserved,
  };

  const node: Node = {
    tag: remark,
    remark,
    protocol: pro ? 'amneziawg' : 'wireguard',
    address: host,
    port: port || 2408,
    transport: { network: 'tcp' },
    security: { type: 'none' },
  };

  if (pro) node.amneziawg = { ...base, ...amneziaTuning(w) };
  else node.wireguard = { ...base };

  return normalize(node);
}

/** Every configured endpoint as a node, so url-test can pick the fastest. */
export function warpNodes(accounts: WarpAccount[], w: WarpConfig, pro: boolean): Node[] {
  if (accounts.length === 0) return [];
  const account = accounts[0];
  return w.endpoints.map((ep, i) =>
    warpNode(account, ep, w, pro, `WARP ${i + 1}${pro ? ' Pro' : ''}`));
}
