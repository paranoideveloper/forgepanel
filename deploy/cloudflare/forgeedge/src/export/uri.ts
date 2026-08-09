/**
 * Mirror of `internal/protocol/export/uri.go`: canonical Node → native client
 * share link. Server-only secrets (REALITY private key, ML-DSA seed, the WG
 * server key) are never emitted, exactly as in Go.
 */

import { type Node, type Network } from '../model/node';
import { normalized } from '../model/normalize';
import { Values, b64Std, b64RawURL, goPathEscape, goQueryEscape } from '../common/encoding';
import { hostPort } from '../common/net';
import { goMarshal, type JSONValue } from './gojson';

const TE = new TextEncoder();

/** Go `export.frag`. */
function frag(remark?: string): string {
  if (!remark) return '';
  return '#' + goPathEscape(remark);
}

/**
 * Go `export.transportSecurityParams` — the single source of truth for how the
 * canonical transport+security maps onto de-facto standard link parameters.
 */
export function transportSecurityParams(n: Node, v: Values): void {
  const t = n.transport;
  v.set('type', String(t.network));
  switch (t.network) {
    case 'ws':
    case 'httpupgrade':
      if (t.path) v.set('path', t.path);
      if (t.host) v.set('host', t.host);
      break;
    case 'grpc':
      if (t.service_name) v.set('serviceName', t.service_name);
      v.set('mode', t.multi_mode ? 'multi' : 'gun');
      break;
    case 'xhttp':
      if (t.path) v.set('path', t.path);
      if (t.host) v.set('host', t.host);
      if (t.xhttp_mode && t.xhttp_mode !== 'auto') v.set('mode', t.xhttp_mode);
      break;
    case 'h2':
      if (t.path) v.set('path', t.path);
      if (t.host) v.set('host', t.host);
      break;
    case 'kcp':
      if (t.seed) v.set('seed', t.seed);
      if (t.header?.type) v.set('headerType', t.header.type);
      break;
    case 'tcp':
      if (t.header?.type === 'http') {
        v.set('headerType', 'http');
        if (t.host) v.set('host', t.host);
        if (t.path) v.set('path', t.path);
      }
      break;
    case 'quic':
      if (t.quic_security && t.quic_security !== 'none') {
        v.set('quicSecurity', t.quic_security);
        v.set('key', t.quic_key ?? '');
      }
      if (t.header?.type) v.set('headerType', t.header.type);
      break;
  }

  const s = n.security;
  switch (s.type) {
    case 'none':
      v.set('security', 'none');
      break;
    case 'tls':
      v.set('security', 'tls');
      if (s.server_name) v.set('sni', s.server_name);
      if (s.alpn?.length) v.set('alpn', s.alpn.join(','));
      if (s.fingerprint) v.set('fp', s.fingerprint);
      if (s.allow_insecure) v.set('allowInsecure', '1');
      if (s.ech?.config_list) v.set('ech', s.ech.config_list);
      break;
    case 'reality': {
      v.set('security', 'reality');
      if (s.server_name) v.set('sni', s.server_name);
      v.set('fp', s.fingerprint || 'chrome');
      const r = s.reality;
      if (r) {
        v.set('pbk', r.public_key ?? '');
        if (r.short_id) v.set('sid', r.short_id);
        else if (r.short_ids?.length) v.set('sid', r.short_ids[0]);
        if (r.spider_x && r.spider_x !== '/') v.set('spx', r.spider_x);
        if (r.mldsa65_verify) v.set('pqv', r.mldsa65_verify);
      }
      if (s.alpn?.length) v.set('alpn', s.alpn.join(','));
      break;
    }
  }
}

function vlessURI(n: Node): string {
  const v = new Values();
  if (n.flow) v.set('flow', n.flow);
  if (n.encryption && n.encryption !== 'none') v.set('encryption', n.encryption);
  transportSecurityParams(n, v);
  return `vless://${n.uuid ?? ''}@${hostPort(n.address, n.port)}?${v.encode()}${frag(n.remark)}`;
}

function trojanURI(n: Node): string {
  const v = new Values();
  if (n.flow) v.set('flow', n.flow);
  transportSecurityParams(n, v);
  return `trojan://${goQueryEscape(n.password ?? '')}@${hostPort(n.address, n.port)}?${v.encode()}${frag(n.remark)}`;
}

function anytlsURI(n: Node): string {
  const v = new Values();
  transportSecurityParams(n, v);
  if (n.anytls?.padding_scheme?.length) v.set('padding_scheme', n.anytls.padding_scheme.join('\n'));
  return `anytls://${goQueryEscape(n.password ?? '')}@${hostPort(n.address, n.port)}?${v.encode()}${frag(n.remark)}`;
}

/** Go `netForVMess`. */
function netForVMess(nw: Network): string {
  switch (nw) {
    case 'h2': return 'h2';
    case 'httpupgrade': return 'httpupgrade';
    case 'kcp': return 'kcp';
    default: return String(nw);
  }
}

function vmessURI(n: Node): string {
  const m: Record<string, JSONValue> = {
    v: '2',
    ps: n.remark ?? '',
    add: n.address,
    port: String(n.port),
    id: n.uuid ?? '',
    aid: '0',
    scy: n.encryption ?? '',
    net: netForVMess(n.transport.network),
    type: 'none',
    host: '',
    path: '',
    tls: '',
    sni: '',
    alpn: '',
    fp: '',
  };
  switch (n.transport.network) {
    case 'ws':
    case 'httpupgrade':
      m.host = n.transport.host ?? '';
      m.path = n.transport.path ?? '';
      break;
    case 'grpc':
      m.path = n.transport.service_name ?? '';
      m.type = n.transport.multi_mode ? 'multi' : 'gun';
      break;
    case 'h2':
      m.host = n.transport.host ?? '';
      m.path = n.transport.path ?? '';
      break;
    case 'tcp':
      if (n.transport.header?.type === 'http') {
        m.type = 'http';
        m.host = n.transport.host ?? '';
        m.path = n.transport.path ?? '';
      }
      break;
    case 'kcp':
      if (n.transport.header) m.type = n.transport.header.type ?? '';
      m.path = n.transport.seed ?? '';
      break;
  }
  if (n.security.type === 'tls') {
    m.tls = 'tls';
    m.sni = n.security.server_name ?? '';
    m.fp = n.security.fingerprint ?? '';
    if (n.security.alpn?.length) m.alpn = n.security.alpn.join(',');
  } else if (n.security.type === 'reality') {
    m.tls = 'reality';
    m.sni = n.security.server_name ?? '';
    m.fp = n.security.fingerprint ?? '';
    if (n.security.reality) {
      m.pbk = n.security.reality.public_key ?? '';
      m.sid = n.security.reality.short_id ?? '';
    }
  }
  return 'vmess://' + b64Std(TE.encode(goMarshal(m)));
}

function ssURI(n: Node): string {
  // SIP002: ss://base64url(method:password)@host:port#tag
  const userinfo = b64RawURL(TE.encode(`${n.method ?? ''}:${n.password ?? ''}`));
  let uri = `ss://${userinfo}@${hostPort(n.address, n.port)}`;
  const q = new Values();
  if (n.ss_plugin?.name) {
    let plugin = n.ss_plugin.name;
    if (n.ss_plugin.opts) plugin += ';' + n.ss_plugin.opts;
    q.set('plugin', plugin);
  }
  const s = q.encode();
  if (s) uri += '?' + s;
  return uri + frag(n.remark);
}

function socksURI(n: Node): string {
  let uri = 'socks://';
  if (n.username || n.password) {
    uri += b64RawURL(TE.encode(`${n.username ?? ''}:${n.password ?? ''}`)) + '@';
  }
  return uri + hostPort(n.address, n.port) + frag(n.remark);
}

function httpURI(n: Node): string {
  let uri = n.security.type === 'tls' ? 'https://' : 'http://';
  if (n.username || n.password) {
    uri += `${goQueryEscape(n.username ?? '')}:${goQueryEscape(n.password ?? '')}@`;
  }
  return uri + hostPort(n.address, n.port) + frag(n.remark);
}

function hysteria2URI(n: Node): string {
  const v = new Values();
  if (n.security.server_name) v.set('sni', n.security.server_name);
  if (n.security.allow_insecure) v.set('insecure', '1');
  const h = n.hysteria2;
  if (h) {
    if (h.obfs_type) {
      v.set('obfs', h.obfs_type);
      v.set('obfs-password', h.obfs_password ?? '');
    }
    if (h.port_hopping) v.set('mport', h.port_hopping);
    if ((h.port_hop_interval ?? 0) > 0) v.set('hop_interval', String(h.port_hop_interval));
    if ((h.up_mbps ?? 0) > 0) v.set('up', String(h.up_mbps));
    if ((h.down_mbps ?? 0) > 0) v.set('down', String(h.down_mbps));
  }
  if (n.security.pin_sha256?.length) v.set('pinSHA256', n.security.pin_sha256[0]);
  let q = v.encode();
  if (q) q = '?' + q;
  return `hysteria2://${goQueryEscape(n.password ?? '')}@${hostPort(n.address, n.port)}${q}${frag(n.remark)}`;
}

function tuicURI(n: Node): string {
  const v = new Values();
  if (n.security.server_name) v.set('sni', n.security.server_name);
  if (n.security.alpn?.length) v.set('alpn', n.security.alpn.join(','));
  if (n.security.allow_insecure) v.set('allow_insecure', '1');
  const t = n.tuic;
  if (t) {
    if (t.congestion_control) v.set('congestion_control', t.congestion_control);
    if (t.udp_relay_mode) v.set('udp_relay_mode', t.udp_relay_mode);
  }
  return `tuic://${n.uuid ?? ''}:${goQueryEscape(n.password ?? '')}@${hostPort(n.address, n.port)}?${v.encode()}${frag(n.remark)}`;
}

function wireguardURI(n: Node): string {
  const v = new Values();
  const w = n.wireguard!;
  const priv = w.private_key || w.peer_private_key || '';
  v.set('publickey', w.public_key ?? '');
  if (w.pre_shared_key) v.set('presharedkey', w.pre_shared_key);
  if (w.local_address?.length) v.set('address', w.local_address.join(','));
  if ((w.mtu ?? 0) > 0) v.set('mtu', String(w.mtu));
  if (w.reserved?.length === 3) v.set('reserved', `${w.reserved[0]},${w.reserved[1]},${w.reserved[2]}`);
  return `wireguard://${goQueryEscape(priv)}@${hostPort(n.address, n.port)}?${v.encode()}${frag(n.remark)}`;
}

function brookURI(n: Node): string {
  const v = new Values();
  v.set('password', n.password ?? '');
  // Go uses net.JoinHostPort here, which always brackets an IPv6 literal.
  const addr = n.address.includes(':') && !n.address.startsWith('[') ? `[${n.address}]` : n.address;
  v.set('server', `${addr}:${n.port}`);
  const mode = n.brook?.mode || 'server';
  return `brook://${mode}?${v.encode()}${frag(n.remark)}`;
}

function sshURI(n: Node): string {
  let uri = 'ssh://';
  if (n.ssh?.user) uri += goQueryEscape(n.ssh.user) + '@';
  return uri + hostPort(n.address, n.port) + frag(n.remark);
}

function forgednsURI(n: Node): string {
  const v = new Values();
  const f = n.forgedns!;
  if (f.key) v.set('key', f.key);
  if (f.rrtype) v.set('rr', f.rrtype);
  if (f.ns_host) v.set('ns', f.ns_host);
  let q = v.encode();
  if (q) q = '?' + q;
  return `forgedns://${f.adapter ?? ''}@${f.zone ?? ''}${q}${frag(n.remark)}`;
}

/** Thrown for protocols with no standalone URI, mirroring Go's error returns. */
export class UnsupportedURIError extends Error {}

/** Mirror of `export.URI`. Clones + normalizes first, exactly like Go. */
export function nodeURI(n: Node): string {
  const c = normalized(n);
  switch (c.protocol) {
    case 'vless': return vlessURI(c);
    case 'vmess': return vmessURI(c);
    case 'trojan': return trojanURI(c);
    case 'shadowsocks': return ssURI(c);
    case 'socks': return socksURI(c);
    case 'http': return httpURI(c);
    case 'hysteria2': return hysteria2URI(c);
    case 'tuic': return tuicURI(c);
    case 'anytls': return anytlsURI(c);
    case 'wireguard': return wireguardURI(c);
    case 'brook': return brookURI(c);
    case 'ssh': return sshURI(c);
    case 'shadowtls':
      throw new UnsupportedURIError('shadowtls has no standalone URI; export the wrapped shadowsocks node');
    case 'forgedns': return forgednsURI(c);
    default:
      throw new UnsupportedURIError(`export: unsupported protocol "${c.protocol}"`);
  }
}

/** Mirror of `api.plainLinks`: one URI per line, unsupported nodes silently skipped. */
export function plainLinks(nodes: Node[]): string {
  return plainLinksMode(nodes, 'off');
}

// The unsafe-uTLS "pattern" (patterniha) params: fp=unsafe ships no ciphers of
// its own, so cs= must accompany it; fm= is the two-stage TLS fragment. Mirrors
// the Go side (internal/api/pattern.go) so the VPS and the edge emit the same
// variant. Only recent Xray cores read these; older clients ignore them.
export const PATTERN_CS =
  'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:' +
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:' +
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:' +
  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:' +
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:' +
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';
export const PATTERN_FM =
  '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["5","94","1"],"delays":["0"],"maxSplit":"0"}},' +
  '{"type":"fragment","settings":{"packets":"1-1","lengths":["109","1"],"delays":["1"],"maxSplit":"355"}}]}';

export type PatternMode = 'off' | 'only' | 'both';

// applyPattern stamps the unsafe-uTLS params onto a TLS VLESS/Trojan/VMess link.
export function applyPattern(uri: string): string {
  if (!uri.startsWith('vless://') && !uri.startsWith('trojan://') && !uri.startsWith('vmess://')) return uri;
  const hash = uri.indexOf('#');
  const body = hash >= 0 ? uri.slice(0, hash) : uri;
  const frag = hash >= 0 ? uri.slice(hash) : '';
  const q = body.indexOf('?');
  if (q < 0) return uri; // base64 vmess / no query
  const params = new URLSearchParams(body.slice(q + 1));
  if (params.get('security') !== 'tls') return uri;
  params.set('fp', 'unsafe');
  params.set('cs', PATTERN_CS);
  params.set('fm', PATTERN_FM);
  params.sort();
  return body.slice(0, q) + '?' + params.toString() + frag;
}

export function plainLinksMode(nodes: Node[], mode: PatternMode): string {
  let out = '';
  for (const n of nodes) {
    let uri: string;
    try {
      uri = nodeURI(n);
    } catch {
      continue; // a node with no link form is skipped, never fatal
    }
    if (mode === 'only') {
      out += applyPattern(uri) + '\n';
    } else if (mode === 'both') {
      out += uri + '\n';
      const p = applyPattern(uri);
      if (p !== uri) out += (p.includes('#') ? p + encodeURIComponent(' · Patt') : p) + '\n';
    } else {
      out += uri + '\n';
    }
  }
  return out;
}
