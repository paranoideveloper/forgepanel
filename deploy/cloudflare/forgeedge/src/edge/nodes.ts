/**
 * Minting the edge's own entries as canonical `model.Node`s.
 *
 * This is the join point of the whole design: the Worker does NOT have a special
 * "edge config" format. It emits the same canonical nodes the VPS emits, so the
 * combined subscription is one list rendered by one set of exporters, and a
 * client cannot tell which entry came from where except by its remark.
 */

import type { Node, Protocol } from '../model/node';
import { normalize } from '../model/normalize';
import type { EdgeConfig } from '../config/schema';
import { sha256Hex } from '../common/sha';
import { isDomain, isIPv4, isIPv6, randomUpperCase } from '../common/net';

export interface EdgeIdentity {
  vlessUUID: string;
  trojanPassword: string;
  /** Used to derive stable, unguessable WebSocket paths per subscriber. */
  subjectKey: string;
}

/**
 * Deterministic WebSocket path: stable across subscription refreshes (so a saved
 * config keeps working) but unguessable without the salt (so the path itself is
 * not a fingerprint anyone can enumerate). The Worker routes on the FIRST
 * segment only, so the digest is decoration for DPI — and that is deliberate:
 * making it stable is worth more to users than making it random.
 */
export function wsPath(kind: 'vl' | 'tr', salt: string, subject: string): string {
  const digest = sha256Hex(`${salt}|${subject}|${kind}`).slice(0, 24);
  return `/${kind}/${digest}`;
}

/** Which host/SNI pair to advertise for a given address. */
export function selectSniHost(cfg: EdgeConfig, address: string, workerHost: string): {
  host: string; sni: string; allowInsecure: boolean;
} {
  const isCustomCdn = cfg.customCdnAddrs.includes(address);
  if (isCustomCdn) {
    return {
      host: cfg.customCdnHost || workerHost,
      sni: cfg.customCdnSni || workerHost,
      // A custom CDN front usually presents its own certificate for a different
      // name, so the client must be told not to fail the handshake on it.
      allowInsecure: true,
    };
  }
  // Random casing of the SNI is free and defeats naive exact-match SNI filters.
  return { host: workerHost, sni: randomUpperCase(workerHost), allowInsecure: false };
}

function addressKind(cfg: EdgeConfig, address: string): string {
  if (cfg.cleanIPs.includes(address)) return 'Clean IP';
  if (isDomain(address)) return 'Domain';
  if (isIPv4(address)) return 'IPv4';
  if (isIPv6(address)) return 'IPv6';
  return 'Host';
}

/** Human-readable remark; also the node tag, which is what url-test groups key on. */
export function edgeRemark(
  cfg: EdgeConfig, index: number, protocol: Protocol, address: string, port: number, isCustomDomain: boolean,
): string {
  const proto = protocol === 'vless' ? 'VLESS' : 'Trojan';
  const custom = isCustomDomain ? 'D ' : '';
  const cdn = cfg.customCdnAddrs.includes(address) ? 'C ' : '';
  return `ForgeEdge ${index}. ${proto} ${custom}${cdn}- ${addressKind(cfg, address)} : ${port}`;
}

export interface BuildEdgeNodesInput {
  cfg: EdgeConfig;
  identity: EdgeIdentity;
  /** The Worker's own hostname for this request (workers.dev or a custom domain). */
  workerHost: string;
  /** Extra addresses to advertise (resolved IPs, clean IPs, custom CDN fronts). */
  addresses: string[];
}

/**
 * Build one canonical Node per (protocol × port × address).
 *
 * Only TLS ports are emitted for a custom domain: a plaintext WebSocket to a
 * custom hostname is trivially fingerprinted and, for Trojan, is not even a
 * valid client config. `*.workers.dev` may use the plain-HTTP ports because
 * Cloudflare fronts them with its own TLS on the way in.
 */
export function buildEdgeNodes(input: BuildEdgeNodesInput): Node[] {
  const { cfg, identity, workerHost, addresses } = input;
  const isWorkersDev = workerHost.endsWith('workers.dev') || workerHost.endsWith('pages.dev');
  const isCustomDomain = !!cfg.customDomain && workerHost === cfg.customDomain;

  const ports = cfg.ports.filter((p) => isWorkersDev || cfg.httpsPorts.includes(p));
  const uniqueAddrs = [...new Set([workerHost, ...addresses])].filter(Boolean);

  const out: Node[] = [];
  for (const protocol of cfg.protocols) {
    let index = 1;
    for (const port of ports) {
      for (const address of uniqueAddrs) {
        const tls = cfg.httpsPorts.includes(port);
        // Trojan without TLS is not a usable client config.
        if (protocol === 'trojan' && !tls) continue;

        const { host, sni, allowInsecure } = selectSniHost(cfg, address, workerHost);
        const remark = edgeRemark(cfg, index, protocol, address, port, isCustomDomain);
        const kind = protocol === 'vless' ? 'vl' : 'tr';

        const node: Node = {
          tag: remark,
          remark,
          protocol,
          address,
          port,
          transport: {
            network: 'ws',
            path: wsPath(kind, cfg.wsPathSalt, identity.subjectKey),
            host,
            // 0-RTT: the first client bytes ride in the WebSocket subprotocol
            // header, saving a round trip on every new connection.
            early_data: 2560,
            ed_header: 'Sec-WebSocket-Protocol',
          },
          security: tls
            ? {
              type: 'tls',
              server_name: sni,
              alpn: ['http/1.1'],
              fingerprint: cfg.fingerprint,
              ...(allowInsecure ? { allow_insecure: true } : {}),
              ...(cfg.enableECH ? { ech: { enabled: true, auto_fetch: !cfg.echServerName, config_list: '' } } : {}),
            }
            : { type: 'none' },
        };

        if (protocol === 'vless') {
          node.uuid = identity.vlessUUID;
          node.encryption = 'none';
        } else {
          node.password = identity.trojanPassword;
        }

        out.push(normalize(node));
        index++;
      }
    }
  }
  return out;
}
