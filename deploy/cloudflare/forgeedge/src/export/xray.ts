/**
 * Mirror of `internal/protocol/render/xray.go` (outbound half): canonical Node →
 * Xray outbound object. Protocols that are not Xray protocols throw, so the
 * caller routes them elsewhere instead of shipping a config Xray will refuse.
 */

import { type Node, type Network, sni, usesTransport } from '../model/node';
import { normalized } from '../model/normalize';
import type { JSONValue } from './gojson';

export type JObj = Record<string, JSONValue>;

export class XrayUnsupportedError extends Error {}

const firstNonEmpty = (...vals: (string | undefined)[]): string => vals.find((v) => !!v) ?? '';
const tagOr = (tag: string | undefined, def: string): string => tag || def;
const splitOr = (s: string | undefined, def: string): string[] => (s ? [s] : [def]);
const defaultStrs = (v: string[] | undefined, def: string[]): string[] => (v && v.length ? v : def);

/** Go `render.networkName`. */
function networkName(n: Network): string {
  switch (n) {
    case 'kcp': return 'kcp';
    case 'h2': return 'http';
    default: return String(n);
  }
}

/** Go `xraySettings` (outbound branch only — the edge never renders VPS inbounds). */
function xraySettings(n: Node): JObj {
  switch (n.protocol) {
    case 'vless': {
      const user: JObj = { id: n.uuid ?? '', encryption: firstNonEmpty(n.encryption, 'none') };
      if (n.flow) user.flow = n.flow;
      return { vnext: [{ address: n.address, port: n.port, users: [user] }] };
    }

    case 'vmess':
      return {
        vnext: [{
          address: n.address, port: n.port,
          users: [{ id: n.uuid ?? '', alterId: 0, security: firstNonEmpty(n.encryption, 'auto') }],
        }],
      };

    case 'trojan':
      return { servers: [{ address: n.address, port: n.port, password: n.password ?? '' }] };

    case 'shadowsocks':
      return { servers: [{ address: n.address, port: n.port, method: n.method ?? '', password: n.password ?? '' }] };

    case 'socks': {
      const srv: JObj = { address: n.address, port: n.port };
      if (n.username) srv.users = [{ user: n.username, pass: n.password ?? '' }];
      return { servers: [srv] };
    }

    case 'http': {
      const srv: JObj = { address: n.address, port: n.port };
      if (n.username) srv.users = [{ user: n.username, pass: n.password ?? '' }];
      return { servers: [srv] };
    }

    case 'wireguard': {
      const w = n.wireguard!;
      const s: JObj = {
        secretKey: w.private_key ?? '',
        peers: [{
          publicKey: w.public_key ?? '',
          endpoint: `${n.address}:${n.port}`,
          allowedIPs: defaultStrs(w.allowed_ips, ['0.0.0.0/0', '::/0']),
        }],
      };
      if (w.local_address?.length) s.address = w.local_address;
      if ((w.mtu ?? 0) > 0) s.mtu = w.mtu!;
      if (w.reserved?.length === 3) s.reserved = w.reserved;
      return s;
    }

    default:
      throw new XrayUnsupportedError(
        `render/xray: protocol "${n.protocol}" is not an Xray protocol; use sing-box`);
  }
}

/** Go `xrayStreamSettings` with `inbound=false`. Null for protocols outside the transport stack. */
export function xrayStreamSettings(n: Node): JObj | null {
  if (!usesTransport(n.protocol)) return null;

  const t = n.transport;
  const ss: JObj = { network: networkName(t.network) };

  switch (t.network) {
    case 'tcp':
      if (t.header?.type === 'http') {
        ss.tcpSettings = {
          header: {
            type: 'http',
            request: { path: splitOr(t.path, '/'), headers: { Host: splitOr(t.host, '') } },
          },
        };
      }
      break;

    case 'ws': {
      const wsHeaders: JObj = {};
      if (t.host) wsHeaders.Host = t.host;
      const ws: JObj = { path: firstNonEmpty(t.path, '/') };
      if ((t.early_data ?? 0) > 0) ws.maxEarlyData = t.early_data!;
      if (t.ed_header) ws.earlyDataHeaderName = t.ed_header;
      if (Object.keys(wsHeaders).length > 0) ws.headers = wsHeaders;
      ss.wsSettings = ws;
      break;
    }

    case 'httpupgrade': {
      const hu: JObj = { path: firstNonEmpty(t.path, '/') };
      if (t.host) hu.host = t.host;
      ss.httpupgradeSettings = hu;
      break;
    }

    case 'grpc': {
      const g: JObj = { serviceName: t.service_name ?? '', multiMode: !!t.multi_mode };
      if ((t.idle_timeout ?? 0) > 0) g.idle_timeout = t.idle_timeout!;
      if ((t.initial_windows ?? 0) > 0) g.initial_windows_size = t.initial_windows!;
      if (t.permit_without_stream) g.permit_without_stream = true;
      ss.grpcSettings = g;
      break;
    }

    case 'xhttp': {
      const xh: JObj = { path: firstNonEmpty(t.path, '/'), mode: firstNonEmpty(t.xhttp_mode, 'auto') };
      if (t.host) xh.host = t.host;
      if (t.x_padding_bytes) xh.xPaddingBytes = t.x_padding_bytes;
      const x = t.xmux;
      if (x) {
        const xm: JObj = {};
        if (x.max_concurrency) xm.maxConcurrency = x.max_concurrency;
        if (x.max_connections) xm.maxConnections = x.max_connections;
        if (x.c_max_reuse_times) xm.cMaxReuseTimes = x.c_max_reuse_times;
        if (x.h_max_request_times) xm.hMaxRequestTimes = x.h_max_request_times;
        if (x.h_max_reusable_secs) xm.hMaxReusableSecs = x.h_max_reusable_secs;
        if ((x.h_keep_alive_period ?? 0) > 0) xm.hKeepAlivePeriod = x.h_keep_alive_period!;
        if (Object.keys(xm).length > 0) xh.xmux = xm;
      }
      ss.xhttpSettings = xh;
      break;
    }

    case 'h2': {
      const h2: JObj = { path: firstNonEmpty(t.path, '/') };
      if (t.host) h2.host = [t.host];
      ss.httpSettings = h2;
      break;
    }

    case 'kcp': {
      const k: JObj = { header: { type: 'none' } };
      if (t.seed) k.seed = t.seed;
      if (t.header?.type) k.header = { type: t.header.type };
      ss.kcpSettings = k;
      break;
    }

    case 'quic':
      ss.quicSettings = {
        security: firstNonEmpty(t.quic_security, 'none'),
        key: t.quic_key ?? '',
        header: { type: 'none' },
      };
      break;
  }

  switch (n.security.type) {
    case 'tls': {
      ss.security = 'tls';
      const tls: JObj = { serverName: sni(n) };
      if (n.security.alpn?.length) tls.alpn = n.security.alpn;
      if (n.security.fingerprint) tls.fingerprint = n.security.fingerprint;
      if (n.security.min_version) tls.minVersion = n.security.min_version;
      if (n.security.max_version) tls.maxVersion = n.security.max_version;
      if (n.security.cipher_suites) tls.cipherSuites = n.security.cipher_suites;
      // Xray 26 removed "allowInsecure"; skip-verify is pinnedPeerCertSha256.
      if (n.security.pin_sha256?.length) tls.pinnedPeerCertSha256 = n.security.pin_sha256[0];
      ss.tlsSettings = tls;
      break;
    }

    case 'reality': {
      ss.security = 'reality';
      const r = n.security.reality;
      const rs: JObj = { show: false, fingerprint: firstNonEmpty(n.security.fingerprint, 'chrome') };
      if (r) {
        // Client outbound carries publicKey only. Emitting dest/serverNames/
        // shortIds/privateKey makes Xray 26 treat the node as a server.
        if (r.public_key) rs.publicKey = r.public_key;
        rs.serverName = sni(n);
        let sid = r.short_id ?? '';
        if (!sid && r.short_ids?.length) sid = r.short_ids[0];
        if (sid) rs.shortId = sid;
        if (r.spider_x) rs.spiderX = r.spider_x;
      }
      ss.realitySettings = rs;
      break;
    }
  }

  return ss;
}

/** Mirror of `render.XrayOutbound`. */
export function xrayOutbound(n: Node): JObj {
  const c = normalized(n);
  const settings = xraySettings(c);
  const out: JObj = {
    tag: tagOr(c.tag, 'proxy'),
    protocol: String(c.protocol),
    settings,
  };
  const ss = xrayStreamSettings(c);
  if (ss) out.streamSettings = ss;
  return out;
}
