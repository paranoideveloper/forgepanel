/**
 * Mirror of `(*model.Node).Normalize()` in `internal/protocol/model/model.go`.
 *
 * Normalize is what makes node equality well-defined: it lowercases enum-ish
 * fields, applies protocol defaults, and zeroes every field that is meaningless
 * for the selected protocol/transport/security. The edge MUST apply the same
 * normalization the VPS panel does, or the two sides will emit different links
 * for the same node and the round-trip property test in spec §15 stops meaning
 * anything across the boundary.
 */

import {
  type Node, type Transport, type Protocol, type Network,
  SS2022_AES128, keySizeForMethod, usesTransport, isQUICBased,
} from './node';
import { sha256Bytes } from '../common/sha';
import { b64Std, b64RawURL } from '../common/encoding';

const TE = new TextEncoder();

/** Mirror of Go `deriveInnerPSK`: a stable, valid SS2022 PSK from the handshake password. */
export function deriveInnerPSK(seed: string, method: string): string {
  let size = keySizeForMethod(method).size;
  if (size <= 0) size = 16;
  const sum = sha256Bytes(TE.encode('forgepanel-shadowtls-inner:' + seed));
  return b64Std(sum.subarray(0, size));
}

/** Mirror of `(*Transport).clearIrrelevant()`. */
function clearIrrelevantTransport(t: Transport): Transport {
  let keepHeaderObfs = false;
  let out: Transport;

  switch (t.network) {
    case 'ws':
    case 'httpupgrade':
      out = {
        network: t.network, path: t.path, host: t.host,
        headers: t.headers, early_data: t.early_data, ed_header: t.ed_header,
      };
      break;
    case 'grpc':
      out = {
        network: t.network, service_name: t.service_name, multi_mode: t.multi_mode,
        idle_timeout: t.idle_timeout, health_check: t.health_check,
        initial_windows: t.initial_windows, permit_without_stream: t.permit_without_stream,
        host: t.host,
      };
      break;
    case 'xhttp':
      out = {
        network: t.network, path: t.path, host: t.host, headers: t.headers,
        xhttp_mode: t.xhttp_mode || 'auto', x_padding_bytes: t.x_padding_bytes, xmux: t.xmux,
      };
      break;
    case 'h2':
      out = { network: t.network, path: t.path, host: t.host, h2_hosts: t.h2_hosts, headers: t.headers };
      break;
    case 'kcp':
      keepHeaderObfs = true;
      out = {
        network: t.network, seed: t.seed, mtu: t.mtu, tti: t.tti,
        uplink_capacity: t.uplink_capacity, downlink_capacity: t.downlink_capacity,
        congestion: t.congestion, read_buffer_size: t.read_buffer_size,
        write_buffer_size: t.write_buffer_size, header: t.header,
      };
      break;
    case 'quic':
      keepHeaderObfs = true;
      out = { network: t.network, quic_security: t.quic_security, quic_key: t.quic_key, header: t.header };
      break;
    case 'tcp':
    default:
      keepHeaderObfs = true;
      out = { network: t.network, header: t.header, host: t.host, path: t.path };
      break;
  }

  if (!keepHeaderObfs) delete out.header;
  if (out.header && !out.header.type) delete out.header;
  if (out.headers && Object.keys(out.headers).length === 0) delete out.headers;

  // Go's omitempty drops zero values; do the same so JSON round-trips match.
  for (const k of Object.keys(out) as (keyof Transport)[]) {
    const v = out[k];
    if (k === 'network') continue;
    if (v === undefined || v === '' || v === 0 || v === false) delete out[k];
  }
  return out;
}

/** Mirror of `(*Node).clearIrrelevantProtocolBlocks()`. */
function clearIrrelevantProtocolBlocks(n: Node): void {
  const keep = (p: Protocol) => n.protocol === p;
  if (!keep('hysteria2')) delete n.hysteria2;
  if (!keep('tuic')) delete n.tuic;
  if (!keep('anytls')) delete n.anytls;
  if (!keep('wireguard')) delete n.wireguard;
  if (!keep('shadowtls')) delete n.shadowtls;
  if (!keep('ssh')) delete n.ssh;
  if (!keep('brook')) delete n.brook;
  if (!keep('forgedns')) delete n.forgedns;
  if (!keep('shadowsocks')) { delete n.ss_plugin; n.method = ''; }

  const blank = (...keys: (keyof Node)[]) => {
    for (const k of keys) {
      if (k === 'alter_id') n.alter_id = 0;
      else (n as unknown as Record<string, unknown>)[k] = '';
    }
  };

  switch (n.protocol) {
    case 'vless': blank('password', 'username', 'alter_id'); break;
    case 'vmess': blank('password', 'username'); break;
    case 'trojan': case 'anytls': case 'brook': case 'hysteria2':
      blank('uuid', 'username', 'flow', 'encryption', 'alter_id'); break;
    case 'tuic': blank('username', 'flow', 'encryption', 'alter_id'); break;
    case 'shadowsocks': blank('uuid', 'username', 'flow', 'encryption', 'alter_id'); break;
    case 'socks': case 'http': blank('uuid', 'flow', 'encryption', 'alter_id'); break;
    case 'wireguard': case 'ssh': case 'shadowtls': case 'forgedns':
      blank('uuid', 'password', 'username', 'flow', 'encryption', 'alter_id'); break;
  }
}

/** Strip the fields Go's `omitempty` would have dropped, so JSON compares equal. */
function dropEmptyTopLevel(n: Node): void {
  const optional: (keyof Node)[] = [
    'tag', 'remark', 'uuid', 'password', 'username', 'method', 'flow', 'encryption', 'alter_id',
  ];
  for (const k of optional) {
    const v = n[k];
    if (v === undefined || v === '' || v === 0) delete n[k];
  }
  if (n.multiplex && !n.multiplex.enabled) delete n.multiplex;
}

/** Mirror of `(*Node).Normalize()`. Mutates and returns the node. */
export function normalize(n: Node): Node {
  n.protocol = String(n.protocol).toLowerCase() as Protocol;
  n.address = (n.address ?? '').trim();
  n.method = (n.method ?? '').trim().toLowerCase();
  n.flow = (n.flow ?? '').trim();

  // --- transport ---
  if (!n.transport) n.transport = { network: 'tcp' };
  if (!n.transport.network) n.transport.network = 'tcp';
  n.transport.network = String(n.transport.network).toLowerCase() as Network;
  switch (String(n.transport.network)) {
    case 'splithttp': n.transport.network = 'xhttp'; break;
    case 'http': n.transport.network = 'h2'; break;
    case 'mkcp': n.transport.network = 'kcp'; break;
  }
  if (!usesTransport(n.protocol)) {
    n.transport = { network: 'tcp' };
  } else {
    n.transport = clearIrrelevantTransport(n.transport);
  }

  // --- security ---
  if (!n.security) n.security = { type: 'none' };
  if (!n.security.type) n.security.type = 'none';
  n.security.type = String(n.security.type).toLowerCase() as Security_;
  if ((n.security.type as string) === 'xtls') n.security.type = 'tls';

  // QUIC-based and AnyTLS protocols are TLS by definition; a security=none there
  // makes the client connect plain while the server serves TLS. ShadowTLS is
  // EXCLUDED — sing-box rejects a shadowtls inbound carrying a top-level tls block.
  if ((isQUICBased(n.protocol) || n.protocol === 'anytls') && n.security.type === 'none') {
    n.security.type = 'tls';
  }

  switch (n.security.type) {
    case 'none':
      n.security = { type: 'none' };
      break;
    case 'tls':
      delete n.security.reality;
      if (n.security.ech && !n.security.ech.enabled && !n.security.ech.config_list && !n.security.ech.auto_fetch) {
        delete n.security.ech;
      }
      break;
    case 'reality': {
      delete n.security.ech;
      n.security.allow_insecure = false;
      const r = n.security.reality;
      if (r) {
        if (r.server_names) r.server_names = [...r.server_names].sort();
        if (r.short_ids) r.short_ids = [...r.short_ids].sort();
        if (!r.spider_x) r.spider_x = '/';
        if (!n.security.server_name && r.server_names && r.server_names.length === 1) {
          n.security.server_name = r.server_names[0];
        }
      }
      break;
    }
  }
  if (n.security.alpn) n.security.alpn = [...n.security.alpn].sort();
  if (n.security.allow_insecure === false) delete n.security.allow_insecure;

  // --- protocol-specific ---
  clearIrrelevantProtocolBlocks(n);

  switch (n.protocol) {
    case 'vmess':
      n.alter_id = 0; // VMessAEAD only
      if (!n.encryption) n.encryption = 'auto';
      break;

    case 'vless':
      if (!n.encryption) n.encryption = 'none';
      // Vision needs a TLS-ish layer over raw TCP; it is meaningless over
      // ws/grpc/xhttp, so drop it rather than emit a broken link.
      if (n.flow && n.transport.network !== 'tcp') n.flow = '';
      break;

    case 'hysteria2': {
      if (!n.hysteria2) n.hysteria2 = {};
      if (!n.security.alpn || n.security.alpn.length === 0) n.security.alpn = ['h3'];
      const h = n.hysteria2;
      if (!h.masquerade && h.masquerade_type) {
        h.masquerade = { type: h.masquerade_type, url: h.masquerade_url };
      }
      delete h.masquerade_type;
      delete h.masquerade_url;
      break;
    }

    case 'tuic':
      if (!n.tuic) n.tuic = {};
      if (!n.tuic.congestion_control) n.tuic.congestion_control = 'bbr';
      if (!n.tuic.udp_relay_mode) n.tuic.udp_relay_mode = 'native';
      if (!n.security.alpn || n.security.alpn.length === 0) n.security.alpn = ['h3'];
      break;

    case 'anytls':
      if (!n.anytls) n.anytls = {};
      break;

    case 'wireguard':
      if (n.wireguard && !n.wireguard.mtu) n.wireguard.mtu = 1420;
      break;

    case 'amneziawg': {
      if (!n.amneziawg) n.amneziawg = {};
      const a = n.amneziawg;
      if (!a.mtu) a.mtu = 1420;
      if (!a.jc) a.jc = 8;
      if (!a.jmin) a.jmin = 50;
      if (!a.jmax) a.jmax = 1000;
      if (!a.s1) a.s1 = 86;
      if (!a.s2) a.s2 = 574;
      if (!a.h1) a.h1 = 1234567;
      if (!a.h2) a.h2 = 2345678;
      if (!a.h3) a.h3 = 3456789;
      if (!a.h4) a.h4 = 4567890;
      break;
    }

    case 'shadowtls': {
      if (!n.shadowtls) n.shadowtls = {};
      const s = n.shadowtls;
      if (!s.version) s.version = 3;
      if (!s.password) {
        const sum = sha256Bytes(TE.encode(`forgepanel-shadowtls-hs:${n.port}`));
        s.password = b64RawURL(sum.subarray(0, 12));
      }
      if (!s.inner_method) s.inner_method = SS2022_AES128;
      if (!s.inner_password) s.inner_password = deriveInnerPSK(s.password, s.inner_method);
      break;
    }

    case 'forgedns':
      if (n.forgedns) {
        n.forgedns.adapter = (n.forgedns.adapter ?? '').toLowerCase();
        n.forgedns.zone = (n.forgedns.zone ?? '').toLowerCase().replace(/\.$/, '');
        if (!n.forgedns.rrtype) n.forgedns.rrtype = 'TXT';
        n.forgedns.rrtype = n.forgedns.rrtype.toUpperCase();
        if (!n.forgedns.edns_buffer) n.forgedns.edns_buffer = 1232;
      }
      break;
  }

  if (n.multiplex && !n.multiplex.enabled) delete n.multiplex;
  dropEmptyTopLevel(n);
  return n;
}

// Local alias so the cast above stays readable without importing the union twice.
type Security_ = Node['security']['type'];

/** Clone-then-normalize, matching the `c := n.Clone(); c.Normalize()` prologue of every Go renderer. */
export function normalized(n: Node): Node {
  return normalize(JSON.parse(JSON.stringify(n)) as Node);
}
