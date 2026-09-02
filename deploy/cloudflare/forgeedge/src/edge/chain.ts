/**
 * Chain proxy: parse an operator-supplied share link into a canonical Node so it
 * can be emitted as a client-side dialer in front of every edge entry.
 *
 * WHY it exists: the Worker's exit IP is a Cloudflare IP, chosen by Cloudflare,
 * different on every colo. Services that geo-fence, rate-limit, or ban
 * datacentre ranges see that IP, not the user's. Chaining pins the exit to a
 * host the operator controls, so the visible IP is stable and theirs.
 *
 * The chain runs in the CLIENT (`dialerProxy` in Xray, `detour` in sing-box,
 * `dialer-proxy` in mihomo) — the Worker never dials it, because a Worker
 * dialing a second proxy would double the hop count for no benefit.
 */

import type { Node, Protocol } from '../model/node';
import { normalize } from '../model/normalize';
import { b64DecodeUtf8, b64AnyDecode } from '../common/encoding';
import { parseHostPort } from '../common/net';

const TD = new TextDecoder();

/** Supported chain schemes; anything else is rejected with a reason. */
const SCHEMES: Record<string, Protocol> = {
  vless: 'vless',
  vmess: 'vmess',
  trojan: 'trojan',
  ss: 'shadowsocks',
  shadowsocks: 'shadowsocks',
  socks: 'socks',
  socks5: 'socks',
  http: 'http',
  https: 'http',
};

export class ChainParseError extends Error {}

function applyQuery(node: Node, params: URLSearchParams): void {
  const type = params.get('type') ?? 'tcp';
  node.transport = { network: (type === 'raw' ? 'tcp' : type) as Node['transport']['network'] };

  const path = params.get('path');
  const host = params.get('host');
  const service = params.get('serviceName');
  if (path) node.transport.path = path;
  if (host) node.transport.host = host;
  if (service) node.transport.service_name = service;
  if (params.get('mode') === 'multi') node.transport.multi_mode = true;
  const ed = params.get('ed');
  if (ed) {
    node.transport.early_data = Number(ed) || undefined;
    node.transport.ed_header = params.get('eh') ?? 'Sec-WebSocket-Protocol';
  }
  if (params.get('headerType') === 'http') node.transport.header = { type: 'http' };

  const security = params.get('security') ?? 'none';
  if (security === 'tls' || security === 'reality') {
    node.security = {
      type: security,
      server_name: params.get('sni') ?? undefined,
      fingerprint: params.get('fp') ?? undefined,
      alpn: params.get('alpn')?.split(',').filter(Boolean),
    };
    if (params.get('allowInsecure') === '1') node.security.allow_insecure = true;
    if (security === 'reality') {
      node.security.reality = {
        public_key: params.get('pbk') ?? '',
        short_id: params.get('sid') ?? undefined,
        spider_x: params.get('spx') ?? undefined,
      };
    }
  } else {
    node.security = { type: 'none' };
  }
}

/** Parse a `vmess://` base64-JSON link into a canonical Node. */
function parseVmess(raw: string): Node {
  const json = JSON.parse(b64DecodeUtf8(raw.slice('vmess://'.length))) as Record<string, string>;
  const node: Node = {
    protocol: 'vmess',
    address: json.add ?? '',
    port: Number(json.port ?? 0),
    uuid: json.id ?? '',
    encryption: json.scy || 'auto',
    remark: json.ps,
    transport: { network: (json.net === 'kcp' ? 'kcp' : json.net || 'tcp') as Node['transport']['network'] },
    security: { type: 'none' },
  };
  if (json.host) node.transport.host = json.host;
  if (json.path) {
    if (node.transport.network === 'grpc') node.transport.service_name = json.path;
    else node.transport.path = json.path;
  }
  if (json.type === 'http') node.transport.header = { type: 'http' };
  if (json.tls === 'tls' || json.tls === 'reality') {
    node.security = {
      type: json.tls as 'tls' | 'reality',
      server_name: json.sni || undefined,
      fingerprint: json.fp || undefined,
      alpn: json.alpn ? json.alpn.split(',').filter(Boolean) : undefined,
    };
    if (json.tls === 'reality') {
      node.security.reality = { public_key: json.pbk ?? '', short_id: json.sid || undefined };
    }
  }
  return normalize(node);
}

/** Parse any supported chain-proxy share link into a canonical Node. */
export function parseChainProxy(uri: string): Node {
  const trimmed = uri.trim();
  if (!trimmed) throw new ChainParseError('empty chain proxy URI');
  if (trimmed.startsWith('vmess://')) return parseVmess(trimmed);

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new ChainParseError(`chain proxy is not a URL: ${trimmed.slice(0, 40)}`);
  }

  const scheme = url.protocol.replace(':', '').toLowerCase();
  const protocol = SCHEMES[scheme];
  if (!protocol) throw new ChainParseError(`unsupported chain proxy scheme "${scheme}"`);

  const { host, port } = parseHostPort(url.host, true);
  const node: Node = {
    protocol,
    address: host,
    port: port || Number(url.port) || 443,
    remark: url.hash ? decodeURIComponent(url.hash.slice(1)) : 'Chain proxy',
    transport: { network: 'tcp' },
    security: { type: 'none' },
  };

  switch (protocol) {
    case 'vless':
      node.uuid = decodeURIComponent(url.username);
      node.encryption = url.searchParams.get('encryption') ?? 'none';
      if (url.searchParams.get('flow')) node.flow = url.searchParams.get('flow')!;
      applyQuery(node, url.searchParams);
      break;

    case 'trojan':
      node.password = decodeURIComponent(url.username);
      applyQuery(node, url.searchParams);
      break;

    case 'shadowsocks': {
      // SIP002 userinfo is base64(method:password); some producers leave it plain.
      const userinfo = decodeURIComponent(url.username);
      let decoded: string;
      try { decoded = TD.decode(b64AnyDecode(userinfo)); } catch { decoded = userinfo; }
      const idx = decoded.indexOf(':');
      if (idx < 0) throw new ChainParseError('shadowsocks chain proxy has no method:password');
      node.method = decoded.slice(0, idx);
      node.password = decoded.slice(idx + 1);
      break;
    }

    case 'socks':
    case 'http': {
      // Either base64(user:pass)@ or plain user:pass@ — both are in the wild.
      const rawUser = decodeURIComponent(url.username);
      const rawPass = decodeURIComponent(url.password);
      if (rawUser && !rawPass) {
        try {
          const decoded = TD.decode(b64AnyDecode(rawUser));
          const idx = decoded.indexOf(':');
          if (idx >= 0) { node.username = decoded.slice(0, idx); node.password = decoded.slice(idx + 1); }
          else node.username = rawUser;
        } catch {
          node.username = rawUser;
        }
      } else if (rawUser || rawPass) {
        node.username = rawUser;
        node.password = rawPass;
      }
      if (scheme === 'https') node.security = { type: 'tls', server_name: host };
      break;
    }
  }

  if (!node.address) throw new ChainParseError('chain proxy has no host');
  return normalize(node);
}
