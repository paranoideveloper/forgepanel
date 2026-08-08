/**
 * Mirror of `internal/protocol/export/clash.go`: canonical Node → Clash.Meta
 * (mihomo) proxy mapping, plus the same deterministic YAML emitter.
 *
 * The Go file's reasoning applies verbatim here: mihomo's schema is a different
 * vocabulary for the same facts (SNI is "servername" for VLESS/VMess and "sni"
 * everywhere else; httpupgrade is ws-plus-a-flag; REALITY has its own sub-map),
 * so the mapping is hand-written and auditable rather than a struct dump. Nodes
 * mihomo genuinely cannot express are reported with ClashUnsupportedError so a
 * subscription skips them instead of shipping a config the client refuses.
 */

import { type Node, sni } from '../model/node';
import { normalized } from '../model/normalize';
import { hostPort } from '../common/net';

export type YValue = string | number | boolean | null | YValue[] | { [k: string]: YValue };

export class ClashUnsupportedError extends Error {}

const firstNonEmptyStr = (...vals: (string | undefined)[]): string => vals.find((v) => !!v) ?? '';

/** Go `clashName`. */
function clashName(n: Node): string {
  const remark = (n.remark ?? '').trim();
  if (remark) return remark;
  const tag = (n.tag ?? '').trim();
  if (tag) return tag;
  return `${n.protocol}-${hostPort(n.address, n.port)}`;
}

/** Go `uniqueClashName`: deterministic " #N" suffixing. */
export function uniqueClashName(base: string, seen: Map<string, number>): string {
  if (!seen.has(base)) {
    seen.set(base, 1);
    return base;
  }
  for (let i = seen.get(base)! + 1; ; i++) {
    const cand = `${base} #${i}`;
    if (!seen.has(cand)) {
      seen.set(base, i);
      seen.set(cand, 1);
      return cand;
    }
  }
}

/** Go `clashTransport`. */
function clashTransport(n: Node, p: Record<string, YValue>): void {
  const t = n.transport;
  switch (t.network) {
    case 'tcp':
      // Plain TCP is Clash's default and needs no "network" key.
      if (t.header?.type === 'http') {
        p.network = 'http';
        const opts: Record<string, YValue> = {
          method: 'GET',
          path: [firstNonEmptyStr(t.path, '/')],
        };
        if (t.host) opts.headers = { Host: [t.host] };
        p['http-opts'] = opts;
      }
      break;

    case 'ws':
    case 'httpupgrade': {
      p.network = 'ws';
      const ws: Record<string, YValue> = { path: firstNonEmptyStr(t.path, '/') };
      const headers: Record<string, YValue> = {};
      if (t.host) headers.Host = t.host;
      for (const [k, v] of Object.entries(t.headers ?? {})) headers[k] = v;
      if (Object.keys(headers).length > 0) ws.headers = headers;
      if ((t.early_data ?? 0) > 0) {
        ws['max-early-data'] = t.early_data!;
        ws['early-data-header-name'] = firstNonEmptyStr(t.ed_header, 'Sec-WebSocket-Protocol');
      }
      if (t.network === 'httpupgrade') {
        ws['v2ray-http-upgrade'] = true;
        ws['v2ray-http-upgrade-fast-open'] = true;
      }
      p['ws-opts'] = ws;
      break;
    }

    case 'grpc':
      p.network = 'grpc';
      p['grpc-opts'] = { 'grpc-service-name': t.service_name ?? '' };
      break;

    case 'h2': {
      p.network = 'h2';
      const h2: Record<string, YValue> = { path: firstNonEmptyStr(t.path, '/') };
      if (t.host) h2.host = [t.host];
      p['h2-opts'] = h2;
      break;
    }

    default:
      throw new ClashUnsupportedError(
        `export/clash: not representable in Clash.Meta: transport "${t.network}"`);
  }
}

/** Go `clashTLS`. */
function clashTLS(n: Node, p: Record<string, YValue>, sniKey: string, emitFlag: boolean): void {
  const s = n.security;
  if (s.type === 'none') return;
  if (emitFlag) p.tls = true;

  // SNI() falls back to the address; a literal IP as server name is noise at
  // best and a handshake failure at worst.
  const sn = sni(n);
  if (sn && sn !== n.address) p[sniKey] = sn;

  if (s.alpn?.length) p.alpn = [...s.alpn];
  if (s.allow_insecure) p['skip-cert-verify'] = true;
  // mihomo's "fingerprint" is the pinned certificate hash, not uTLS.
  if (s.pin_sha256?.length) p.fingerprint = s.pin_sha256[0];

  if (s.type === 'tls') {
    if (s.fingerprint) p['client-fingerprint'] = s.fingerprint;
    const e = s.ech;
    if (e && (e.enabled || e.config_list)) {
      const ech: Record<string, YValue> = { enable: true };
      if (e.config_list) ech.config = e.config_list;
      p['ech-opts'] = ech;
    }
  } else if (s.type === 'reality') {
    p['client-fingerprint'] = firstNonEmptyStr(s.fingerprint, 'chrome');
    const ro: Record<string, YValue> = {};
    const r = s.reality;
    if (r) {
      ro['public-key'] = r.public_key ?? '';
      let sid = r.short_id ?? '';
      if (!sid && r.short_ids?.length) sid = r.short_ids[0];
      if (sid) ro['short-id'] = sid;
    }
    p['reality-opts'] = ro;
  }
}

/** Go `parsePluginOpts`: SIP003 "k=v;k=v"; a bare key becomes true. */
export function parsePluginOpts(s: string): Record<string, YValue> {
  const out: Record<string, YValue> = {};
  for (let part of s.split(';')) {
    part = part.trim();
    if (!part) continue;
    const idx = part.indexOf('=');
    if (idx >= 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1);
    else out[part] = true;
  }
  return out;
}

/** Go `clashSSPlugin`. */
function clashSSPlugin(n: Node, p: Record<string, YValue>): void {
  const pl = n.ss_plugin;
  if (!pl || !pl.name) return;
  let name = pl.name;
  if (name === 'obfs-local' || name === 'simple-obfs') name = 'obfs';
  p.plugin = name;
  const opts = parsePluginOpts(pl.opts ?? '');
  if (Object.keys(opts).length > 0) p['plugin-opts'] = opts;
}

/** Go `clashMux`. */
function clashMux(n: Node, p: Record<string, YValue>): void {
  const m = n.multiplex;
  if (!m || !m.enabled) return;
  const smux: Record<string, YValue> = {
    enabled: true,
    protocol: firstNonEmptyStr(m.protocol, 'smux'),
  };
  if ((m.max_connections ?? 0) > 0) smux['max-connections'] = m.max_connections!;
  if ((m.min_streams ?? 0) > 0) smux['min-streams'] = m.min_streams!;
  if ((m.max_streams ?? 0) > 0) smux['max-streams'] = m.max_streams!;
  if (m.padding) smux.padding = true;
  p.smux = smux;
}

/** Mirror of `export.ClashProxy`. */
export function clashProxy(n: Node): Record<string, YValue> {
  const c = normalized(n);
  const p: Record<string, YValue> = { name: clashName(c), server: c.address, port: c.port };

  switch (c.protocol) {
    case 'vless':
      p.type = 'vless';
      p.uuid = c.uuid ?? '';
      p.udp = true;
      if (c.flow) p.flow = c.flow;
      clashTransport(c, p);
      clashTLS(c, p, 'servername', true);
      clashMux(c, p);
      break;

    case 'vmess':
      p.type = 'vmess';
      p.uuid = c.uuid ?? '';
      p.alterId = c.alter_id ?? 0;
      p.cipher = firstNonEmptyStr(c.encryption, 'auto');
      p.udp = true;
      clashTransport(c, p);
      clashTLS(c, p, 'servername', true);
      clashMux(c, p);
      break;

    case 'trojan':
      p.type = 'trojan';
      p.password = c.password ?? '';
      p.udp = true;
      if (c.flow) p.flow = c.flow;
      clashTransport(c, p);
      // Trojan is TLS by definition in Clash.Meta: no "tls" key, SNI is "sni".
      clashTLS(c, p, 'sni', false);
      clashMux(c, p);
      break;

    case 'shadowsocks':
      p.type = 'ss';
      p.cipher = c.method ?? '';
      p.password = c.password ?? '';
      p.udp = true;
      clashSSPlugin(c, p);
      clashMux(c, p);
      break;

    case 'socks':
      p.type = 'socks5';
      p.udp = true;
      if (c.username) p.username = c.username;
      if (c.password) p.password = c.password;
      clashTLS(c, p, 'sni', true);
      break;

    case 'http':
      p.type = 'http';
      if (c.username) p.username = c.username;
      if (c.password) p.password = c.password;
      clashTLS(c, p, 'sni', true);
      break;

    case 'hysteria2': {
      p.type = 'hysteria2';
      p.password = c.password ?? '';
      p.udp = true;
      const h = c.hysteria2;
      if (h) {
        // mihomo parses these as bandwidth STRINGS ("30 Mbps"); a bare integer
        // fails to unmarshal into its string field.
        if ((h.up_mbps ?? 0) > 0) p.up = `${h.up_mbps} Mbps`;
        if ((h.down_mbps ?? 0) > 0) p.down = `${h.down_mbps} Mbps`;
        if (h.obfs_type) { p.obfs = h.obfs_type; p['obfs-password'] = h.obfs_password ?? ''; }
        if (h.port_hopping) p.ports = h.port_hopping;
        if ((h.port_hop_interval ?? 0) > 0) p['hop-interval'] = h.port_hop_interval!;
      }
      clashTLS(c, p, 'sni', false);
      break;
    }

    case 'tuic': {
      p.type = 'tuic';
      p.uuid = c.uuid ?? '';
      p.password = c.password ?? '';
      p.udp = true;
      const t = c.tuic;
      if (t) {
        if (t.congestion_control) p['congestion-controller'] = t.congestion_control;
        if (t.udp_relay_mode) p['udp-relay-mode'] = t.udp_relay_mode;
        if (t.zero_rtt_handshake) p['reduce-rtt'] = true;
        // mihomo's heartbeat-interval is milliseconds.
        if ((t.heartbeat ?? 0) > 0) p['heartbeat-interval'] = t.heartbeat! * 1000;
        if (t.disable_sni) p['disable-sni'] = true;
      }
      clashTLS(c, p, 'sni', false);
      break;
    }

    case 'anytls': {
      p.type = 'anytls';
      p.password = c.password ?? '';
      p.udp = true;
      const a = c.anytls;
      if (a) {
        if ((a.idle_session_check_interval ?? 0) > 0) p['idle-session-check-interval'] = a.idle_session_check_interval!;
        if ((a.idle_session_timeout ?? 0) > 0) p['idle-session-timeout'] = a.idle_session_timeout!;
        if ((a.min_idle_sessions ?? 0) > 0) p['min-idle-session'] = a.min_idle_sessions!;
      }
      clashTLS(c, p, 'sni', false);
      break;
    }

    case 'wireguard': {
      const w = c.wireguard;
      if (!w) throw new ClashUnsupportedError('export/clash: not representable in Clash.Meta: wireguard node without keys');
      p.type = 'wireguard';
      p['private-key'] = w.private_key ?? '';
      p['public-key'] = w.public_key ?? '';
      p.udp = true;
      if (w.pre_shared_key) p['pre-shared-key'] = w.pre_shared_key;
      // mihomo splits the tunnel address into ip / ipv6.
      for (const addr of w.local_address ?? []) {
        if (addr.includes(':')) p.ipv6 = addr; else p.ip = addr;
      }
      if (w.allowed_ips?.length) p['allowed-ips'] = [...w.allowed_ips];
      if ((w.mtu ?? 0) > 0) p.mtu = w.mtu!;
      if ((w.persistent_keepalive ?? 0) > 0) p['persistent-keepalive'] = w.persistent_keepalive!;
      if (w.reserved?.length === 3) p.reserved = [w.reserved[0], w.reserved[1], w.reserved[2]];
      break;
    }

    case 'amneziawg': {
      // mihomo (Clash.Meta) expresses AmneziaWG as a wireguard proxy carrying an
      // `amnezia-wg-option` block — the junk-packet params that survive a DPI
      // fingerprinting WireGuard's fixed handshake. Without this case an
      // AmneziaWG node was dropped from every Clash subscription entirely.
      const w = c.amneziawg;
      if (!w) throw new ClashUnsupportedError('export/clash: not representable in Clash.Meta: amneziawg node without keys');
      p.type = 'wireguard';
      p['private-key'] = w.private_key ?? '';
      p['public-key'] = w.public_key ?? '';
      p.udp = true;
      if (w.pre_shared_key) p['pre-shared-key'] = w.pre_shared_key;
      for (const addr of w.local_address ?? []) {
        if (addr.includes(':')) p.ipv6 = addr; else p.ip = addr;
      }
      if (w.allowed_ips?.length) p['allowed-ips'] = [...w.allowed_ips];
      if ((w.mtu ?? 0) > 0) p.mtu = w.mtu!;
      if ((w.persistent_keepalive ?? 0) > 0) p['persistent-keepalive'] = w.persistent_keepalive!;
      if (w.reserved?.length === 3) p.reserved = [w.reserved[0], w.reserved[1], w.reserved[2]];
      p['amnezia-wg-option'] = {
        jc: w.jc ?? 0, jmin: w.jmin ?? 0, jmax: w.jmax ?? 0,
        s1: w.s1 ?? 0, s2: w.s2 ?? 0,
        h1: w.h1 ?? 0, h2: w.h2 ?? 0, h3: w.h3 ?? 0, h4: w.h4 ?? 0,
      };
      break;
    }

    case 'shadowtls':
      throw new ClashUnsupportedError(
        'export/clash: not representable in Clash.Meta: shadowtls; export the wrapped shadowsocks node');

    case 'ssh':
    case 'brook':
    case 'forgedns':
      throw new ClashUnsupportedError(
        `export/clash: not representable in Clash.Meta: protocol "${c.protocol}"`);

    default:
      throw new ClashUnsupportedError(`export/clash: unsupported protocol "${c.protocol}"`);
  }

  return p;
}

// ---------------------------------------------------------------------------
// minimal deterministic YAML emitter (Go export/clash.go, same rules)
// ---------------------------------------------------------------------------

const YAML_PREFERRED_ORDER: Record<string, number> = { name: -5, type: -4, server: -3, port: -2 };

const yamlRank = (k: string): number => YAML_PREFERRED_ORDER[k] ?? 0;

function yamlKeys(m: Record<string, YValue>): string[] {
  // Sort by key first (Go's SortedKeys), then a STABLE sort by rank — this is
  // exactly Go's sort.SliceStable over an already-sorted slice.
  const ks = Object.keys(m).sort();
  return ks
    .map((k, i) => [k, i] as const)
    .sort((a, b) => yamlRank(a[0]) - yamlRank(b[0]) || a[1] - b[1])
    .map(([k]) => k);
}

const yamlPad = (depth: number): string => '  '.repeat(depth);

function yamlNeedsQuote(s: string): boolean {
  if (s === '' || s.trim() !== s) return true;
  switch (s.toLowerCase()) {
    case 'true': case 'false': case 'yes': case 'no':
    case 'on': case 'off': case 'null': case '~': case 'y': case 'n':
      return true;
  }
  // Go: strconv.ParseFloat accepts ints, floats, exponents, Inf and NaN.
  if (/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(s)) return true;
  if (/^[+-]?(inf|infinity|nan)$/i.test(s)) return true;
  if (/[:#,[\]{}&*!|>'"%@`\\\n\r\t]/.test(s)) return true;
  if (s[0] === '-' || s[0] === '?') return true;
  return false;
}

function yamlQuote(s: string): string {
  let b = '"';
  for (const r of s) {
    switch (r) {
      case '"': b += '\\"'; continue;
      case '\\': b += '\\\\'; continue;
      case '\n': b += '\\n'; continue;
      case '\r': b += '\\r'; continue;
      case '\t': b += '\\t'; continue;
    }
    const c = r.codePointAt(0)!;
    if (c < 0x20 || c === 0x7f) b += '\\u' + c.toString(16).padStart(4, '0');
    else b += r;
  }
  return b + '"';
}

function yamlScalar(v: YValue): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return yamlNeedsQuote(v) ? yamlQuote(v) : v;
  return yamlQuote(String(v));
}

function yamlValue(out: string[], v: YValue, depth: number): void {
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    const m = v as Record<string, YValue>;
    if (Object.keys(m).length === 0) { out.push(' {}\n'); return; }
    out.push('\n');
    yamlMap(out, m, depth + 1, false);
    return;
  }
  if (Array.isArray(v)) {
    if (v.length === 0) { out.push(' []\n'); return; }
    out.push('\n');
    yamlSeq(out, v, depth + 1);
    return;
  }
  out.push(' ', yamlScalar(v), '\n');
}

function yamlSeq(out: string[], s: YValue[], depth: number): void {
  for (const item of s) {
    out.push(yamlPad(depth), '-');
    if (item !== null && typeof item === 'object' && !Array.isArray(item)
      && Object.keys(item as Record<string, YValue>).length > 0) {
      out.push(' ');
      yamlMap(out, item as Record<string, YValue>, depth + 1, true);
      continue;
    }
    yamlValue(out, item, depth);
  }
}

function yamlMap(out: string[], m: Record<string, YValue>, depth: number, dashed: boolean): void {
  const keys = yamlKeys(m);
  for (let i = 0; i < keys.length; i++) {
    if (!dashed || i > 0) out.push(yamlPad(depth));
    out.push(yamlScalar(keys[i]), ':');
    yamlValue(out, m[keys[i]], depth);
  }
}

/** Public: render any plain object with the same deterministic emitter. */
export function toYAML(doc: Record<string, YValue>): string {
  const out: string[] = [];
  yamlMap(out, doc, 0, false);
  return out.join('');
}
