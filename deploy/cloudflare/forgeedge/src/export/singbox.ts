/**
 * Mirror of `internal/protocol/render/singbox.go` (outbound half).
 *
 * sing-box rejects unknown JSON keys outright, so a "close enough" translation
 * is a config that will not start. Every key emitted here exists in the schema
 * the Go renderer was verified against; anything the canonical model can express
 * but sing-box cannot (xhttp/mKCP transports, TCP http-obfuscation, Brook,
 * ForgeDNS) throws rather than being silently dropped.
 */

import { type Node, type Transport, type Multiplex, sni } from '../model/node';
import { normalized } from '../model/normalize';
import { validate } from '../model/validate';
import type { JSONValue } from './gojson';

export type JObj = Record<string, JSONValue>;

export class SingboxUnsupportedError extends Error {}

const firstNonEmpty = (...vals: (string | undefined)[]): string => vals.find((v) => !!v) ?? '';
const tagOr = (tag: string | undefined, def: string): string => tag || def;

/** Go `sbSeconds`: sing-box parses durations, not bare numbers. */
const sbSeconds = (sec: number): string => `${sec}s`;

/** Go `sbPortRanges`: "20000-50000" → ["20000:50000"]; malformed parts are skipped. */
export function sbPortRanges(spec: string | undefined): string[] {
  const s = (spec ?? '').trim();
  if (!s) return [];
  const out: string[] = [];
  for (let part of s.split(',')) {
    part = part.trim();
    if (!part) continue;
    part = part.replace(/-/g, ':');
    const idx = part.indexOf(':');
    if (idx < 0) {
      if (!/^\d+$/.test(part)) continue;
      out.push(`${part}:${part}`);
      continue;
    }
    const lo = part.slice(0, idx).trim();
    const hi = part.slice(idx + 1).trim();
    if (!/^\d+$/.test(lo) || !/^\d+$/.test(hi)) continue;
    out.push(`${lo}:${hi}`);
  }
  return out;
}

/** Go `sbHeaders`. */
function sbHeaders(t: Transport, withHost: boolean): JObj | null {
  const h: JObj = {};
  for (const [k, v] of Object.entries(t.headers ?? {})) h[k] = v;
  if (withHost && t.host && !('Host' in h)) h.Host = t.host;
  return Object.keys(h).length === 0 ? null : h;
}

/** Go `sbTransport`. A null result means plain TCP, which sing-box expresses by omitting the key. */
export function sbTransport(t: Transport): JObj | null {
  switch (t.network) {
    case 'tcp':
      if (t.header?.type && t.header.type !== 'none') {
        throw new SingboxUnsupportedError(
          `render/singbox: tcp header obfuscation "${t.header.type}" has no sing-box equivalent`);
      }
      return null;

    case 'ws': {
      const ws: JObj = { type: 'ws', path: firstNonEmpty(t.path, '/') };
      const h = sbHeaders(t, true);
      if (h) ws.headers = h;
      if ((t.early_data ?? 0) > 0) {
        ws.max_early_data = t.early_data!;
        ws.early_data_header_name = firstNonEmpty(t.ed_header, 'Sec-WebSocket-Protocol');
      }
      return ws;
    }

    case 'httpupgrade': {
      const hu: JObj = { type: 'httpupgrade', path: firstNonEmpty(t.path, '/') };
      if (t.host) hu.host = t.host;
      const h = sbHeaders(t, false);
      if (h) hu.headers = h;
      return hu;
    }

    case 'grpc': {
      const g: JObj = { type: 'grpc', service_name: t.service_name ?? '' };
      if ((t.idle_timeout ?? 0) > 0) g.idle_timeout = sbSeconds(t.idle_timeout!);
      if (t.permit_without_stream) g.permit_without_stream = true;
      return g;
    }

    case 'h2': {
      const h: JObj = { type: 'http', path: firstNonEmpty(t.path, '/') };
      let hosts = t.h2_hosts ?? [];
      if (hosts.length === 0 && t.host) hosts = [t.host];
      if (hosts.length > 0) h.host = hosts;
      const hh = sbHeaders(t, false);
      if (hh) h.headers = hh;
      return h;
    }

    case 'quic':
      return { type: 'quic' };

    default:
      throw new SingboxUnsupportedError(
        `render/singbox: transport "${t.network}" is not supported by sing-box; use xray`);
  }
}

/** Go `sbTLS`. `force` is for the protocols that are TLS/QUIC by construction. */
export function sbTLS(n: Node, force: boolean): JObj | null {
  const s = n.security;
  if (s.type === 'none' && !force) return null;

  const tls: JObj = { enabled: true, server_name: sni(n) };
  if (s.alpn?.length) tls.alpn = s.alpn;
  if (s.allow_insecure) tls.insecure = true;
  if (s.min_version) tls.min_version = s.min_version;
  if (s.max_version) tls.max_version = s.max_version;

  let fp = s.fingerprint ?? '';
  if (s.type === 'reality') {
    const r: JObj = { enabled: true };
    const rr = s.reality;
    if (rr) {
      if (rr.public_key) r.public_key = rr.public_key;
      let sid = rr.short_id ?? '';
      if (!sid && rr.short_ids?.length) sid = rr.short_ids[0];
      r.short_id = sid;
    }
    tls.reality = r;
    // REALITY is a uTLS-only handshake in sing-box.
    fp = firstNonEmpty(fp, 'chrome');
  }
  if (fp) tls.utls = { enabled: true, fingerprint: fp };

  const e = s.ech;
  if (e && (e.enabled || e.config_list || e.auto_fetch)) {
    const ech: JObj = { enabled: true };
    if (e.config_list) ech.config = [e.config_list];
    tls.ech = ech;
  }
  return tls;
}

/** Go `sbMultiplex`. */
function sbMultiplex(m: Multiplex | undefined): JObj | null {
  if (!m || !m.enabled) return null;
  const o: JObj = { enabled: true };
  if (m.protocol) o.protocol = m.protocol;
  if ((m.max_connections ?? 0) > 0) o.max_connections = m.max_connections!;
  if ((m.min_streams ?? 0) > 0) o.min_streams = m.min_streams!;
  if ((m.max_streams ?? 0) > 0) o.max_streams = m.max_streams!;
  if (m.padding) o.padding = true;
  const b = m.brutal;
  if (b && b.enabled) o.brutal = { enabled: true, up_mbps: b.up_mbps ?? 0, down_mbps: b.down_mbps ?? 0 };
  return o;
}

/** Go `sbSupportsMultiplex`. */
function sbSupportsMultiplex(p: Node['protocol']): boolean {
  return p === 'vless' || p === 'vmess' || p === 'trojan' || p === 'shadowsocks';
}

function sbApplyStream(n: Node, o: JObj, forceTLS: boolean): void {
  const tr = sbTransport(n.transport);
  if (tr) o.transport = tr;
  const tls = sbTLS(n, forceTLS);
  if (tls) o.tls = tls;
}

/** Go `singboxProtocol`. */
function singboxProtocol(n: Node): JObj {
  switch (n.protocol) {
    case 'vless': {
      const o: JObj = {
        type: 'vless', server: n.address, server_port: n.port,
        uuid: n.uuid ?? '',
        // xudp is sing-box's default and the only encoding Xray's VLESS server
        // understands for UDP-over-VLESS; make it explicit.
        packet_encoding: 'xudp',
      };
      if (n.flow) o.flow = n.flow;
      sbApplyStream(n, o, false);
      return o;
    }

    case 'vmess': {
      const o: JObj = {
        type: 'vmess', server: n.address, server_port: n.port,
        uuid: n.uuid ?? '', security: firstNonEmpty(n.encryption, 'auto'),
        alter_id: 0,
      };
      sbApplyStream(n, o, false);
      return o;
    }

    case 'trojan': {
      const o: JObj = { type: 'trojan', server: n.address, server_port: n.port, password: n.password ?? '' };
      sbApplyStream(n, o, false);
      return o;
    }

    case 'shadowsocks': {
      if (n.transport.network !== 'tcp') {
        throw new SingboxUnsupportedError(
          `render/singbox: shadowsocks over "${n.transport.network}" is expressed as a SIP003 plugin in sing-box, not a transport`);
      }
      const o: JObj = {
        type: 'shadowsocks', server: n.address, server_port: n.port,
        method: n.method ?? '', password: n.password ?? '',
      };
      const p = n.ss_plugin;
      if (p?.name) {
        o.plugin = p.name;
        if (p.opts) o.plugin_opts = p.opts;
      }
      return o;
    }

    case 'socks': {
      const o: JObj = { type: 'socks', server: n.address, server_port: n.port, version: '5' };
      if (n.username) { o.username = n.username; o.password = n.password ?? ''; }
      return o;
    }

    case 'http': {
      const o: JObj = { type: 'http', server: n.address, server_port: n.port };
      if (n.username) { o.username = n.username; o.password = n.password ?? ''; }
      const tls = sbTLS(n, false);
      if (tls) o.tls = tls;
      return o;
    }

    case 'hysteria2': {
      const o: JObj = { type: 'hysteria2', server: n.address, server_port: n.port, password: n.password ?? '' };
      const h = n.hysteria2;
      if (h) {
        if ((h.up_mbps ?? 0) > 0) o.up_mbps = h.up_mbps!;
        if ((h.down_mbps ?? 0) > 0) o.down_mbps = h.down_mbps!;
        if (h.obfs_type) o.obfs = { type: h.obfs_type, password: h.obfs_password ?? '' };
        const ports = sbPortRanges(h.port_hopping);
        if (ports.length > 0) {
          o.server_ports = ports;
          if ((h.port_hop_interval ?? 0) > 0) o.hop_interval = sbSeconds(h.port_hop_interval!);
        }
      }
      o.tls = sbTLS(n, true)!;
      return o;
    }

    case 'tuic': {
      const o: JObj = {
        type: 'tuic', server: n.address, server_port: n.port,
        uuid: n.uuid ?? '', password: n.password ?? '',
      };
      const tls = sbTLS(n, true)!;
      const t = n.tuic;
      if (t) {
        if (t.congestion_control) o.congestion_control = t.congestion_control;
        if (t.udp_relay_mode) o.udp_relay_mode = t.udp_relay_mode;
        if (t.zero_rtt_handshake) o.zero_rtt_handshake = true;
        if ((t.heartbeat ?? 0) > 0) o.heartbeat = sbSeconds(t.heartbeat!);
        if (t.disable_sni) tls.disable_sni = true;
      }
      o.tls = tls;
      return o;
    }

    case 'anytls': {
      const o: JObj = { type: 'anytls', server: n.address, server_port: n.port, password: n.password ?? '' };
      const a = n.anytls;
      if (a) {
        if (a.padding_scheme?.length) o.padding_scheme = a.padding_scheme;
        if ((a.idle_session_check_interval ?? 0) > 0) o.idle_session_check_interval = sbSeconds(a.idle_session_check_interval!);
        if ((a.idle_session_timeout ?? 0) > 0) o.idle_session_timeout = sbSeconds(a.idle_session_timeout!);
        if ((a.min_idle_sessions ?? 0) > 0) o.min_idle_session = a.min_idle_sessions!;
      }
      o.tls = sbTLS(n, true)!;
      return o;
    }

    case 'shadowtls': {
      const s = n.shadowtls!;
      const o: JObj = {
        type: 'shadowtls', server: n.address, server_port: n.port,
        version: s.version ?? 3, password: s.password ?? '',
      };
      const tls = sbTLS(n, true)!;
      if (s.handshake_host) tls.server_name = s.handshake_host;
      if (s.strict_mode && s.version === 3) o.strict_mode = true;
      o.tls = tls;
      return o;
    }

    case 'wireguard': {
      const w = n.wireguard!;
      const o: JObj = {
        // A CLIENT outbound uses the client's key; w.private_key is the server's
        // and must never be shipped to a client.
        type: 'wireguard', server: n.address, server_port: n.port,
        private_key: w.peer_private_key ?? '', peer_public_key: w.public_key ?? '',
      };
      if (w.pre_shared_key) o.pre_shared_key = w.pre_shared_key;
      if (w.local_address?.length) o.local_address = w.local_address;
      if ((w.mtu ?? 0) > 0) o.mtu = w.mtu!;
      if (w.reserved?.length === 3) o.reserved = w.reserved;
      if ((w.workers ?? 0) > 0) o.workers = w.workers!;
      // allowed_ips / keepalive belong to the newer endpoint form, not the 1.11
      // wireguard outbound; sing-box rejects unknown keys.
      return o;
    }

    case 'ssh': {
      const s = n.ssh!;
      const o: JObj = { type: 'ssh', server: n.address, server_port: n.port, user: s.user ?? '' };
      if (s.password) o.password = s.password;
      if (s.private_key) o.private_key = s.private_key;
      if (s.private_key_passphrase) o.private_key_passphrase = s.private_key_passphrase;
      if (s.host_key_algorithms?.length) o.host_key_algorithms = s.host_key_algorithms;
      if (s.client_version) o.client_version = s.client_version;
      return o;
    }

    default:
      throw new SingboxUnsupportedError(
        `render/singbox: protocol "${n.protocol}" is not a sing-box protocol`);
  }
}

/** Mirror of `render.SingboxOutbound`. Clones, normalizes and validates first. */
export function singboxOutbound(n: Node): JObj {
  const c = normalized(n);
  const err = validate(c);
  if (err) throw new SingboxUnsupportedError(err);
  const out = singboxProtocol(c);
  out.tag = tagOr(c.tag, 'proxy');
  if (sbSupportsMultiplex(c.protocol)) {
    const m = sbMultiplex(c.multiplex);
    if (m) out.multiplex = m;
  }
  return out;
}
