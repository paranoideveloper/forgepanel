/**
 * Mirror of `(*model.Node).Validate()`.
 *
 * Deliberately strict, exactly like the Go original: a node that fails here is a
 * node the engine would refuse, and it is better to skip it out of a
 * subscription with a reason than to ship a config the client cannot load.
 * Returns null when valid, or the same message text Go produces.
 */

import {
  type Node, ALL_SHADOWSOCKS_METHODS, VALID_FINGERPRINTS,
  keySizeForMethod, usesTransport, SS_NONE,
} from './node';
import { b64AnyDecode } from '../common/encoding';

function isHex(s: string): boolean {
  return s.length > 0 && /^[0-9a-fA-F]+$/.test(s);
}

/** Mirror of Go `validateSS2022PSK` (model/ss2022.go): base64 whose decoded length is the key size. */
function validateSS2022PSK(psk: string, size: number): string | null {
  if (!psk) return 'shadowsocks: credential is required for this protocol';
  // SIP022 allows the "identity:psk" form for multi-user servers; validate the last part.
  const last = psk.split(':').pop() as string;
  let raw: Uint8Array;
  try {
    raw = b64AnyDecode(last);
  } catch {
    return `shadowsocks: 2022 PSK must be base64 (want ${size} bytes)`;
  }
  if (raw.length !== size) {
    return `shadowsocks: 2022 PSK must decode to ${size} bytes, got ${raw.length}`;
  }
  return null;
}

export function validate(n: Node): string | null {
  if (!n.address || !n.address.trim()) return 'address is required';
  if (!Number.isInteger(n.port) || n.port < 1 || n.port > 65535) {
    return `port must be in 1..65535: got ${n.port}`;
  }

  switch (n.protocol) {
    case 'vless':
      if (!n.uuid) return 'vless: credential is required for this protocol';
      if (n.flow && n.flow !== 'xtls-rprx-vision') return `vless: unsupported flow "${n.flow}"`;
      break;

    case 'vmess':
      if (!n.uuid) return 'vmess: credential is required for this protocol';
      break;

    case 'trojan': case 'anytls': case 'brook':
      if (!n.password) return `${n.protocol}: credential is required for this protocol`;
      break;

    case 'hysteria2':
      if (!n.password) return 'hysteria2: credential is required for this protocol';
      break;

    case 'tuic':
      if (!n.uuid || !n.password) return 'tuic: credential is required for this protocol (needs uuid and password)';
      break;

    case 'shadowsocks': {
      const method = n.method ?? '';
      if (!method) return 'unknown shadowsocks method';
      if (!ALL_SHADOWSOCKS_METHODS.includes(method)) return `unknown shadowsocks method: "${method}"`;
      if (method !== SS_NONE && !n.password) return 'shadowsocks: credential is required for this protocol';
      const { size, is2022 } = keySizeForMethod(method);
      if (is2022) {
        const err = validateSS2022PSK(n.password ?? '', size);
        if (err) return err;
      }
      break;
    }

    case 'socks': case 'http':
      // Credentials optional — an open proxy is legal, though Config Doctor warns.
      break;

    case 'wireguard': {
      const w = n.wireguard;
      if (!w || !w.private_key || !w.public_key) {
        return 'wireguard: credential is required for this protocol (needs private and peer public key)';
      }
      if (w.mtu && (w.mtu < 576 || w.mtu > 1500)) return `wireguard: MTU ${w.mtu} out of range 576..1500`;
      if (w.reserved && w.reserved.length !== 0 && w.reserved.length !== 3) {
        return 'wireguard: reserved must be exactly 3 bytes';
      }
      break;
    }

    case 'amneziawg': {
      const a = n.amneziawg;
      if (!a || !a.private_key || !a.public_key) {
        return 'amneziawg: credential is required for this protocol (needs private and peer public key)';
      }
      if (a.jmax && (a.jmin ?? 0) >= a.jmax) return 'amneziawg: Jmin must be less than Jmax';
      if (a.s1 && a.s2 && a.s1 + 56 === a.s2) return 'amneziawg: S1+56 must not equal S2';
      break;
    }

    case 'shadowtls': {
      const s = n.shadowtls;
      if (!s || !s.password) return 'shadowtls: credential is required for this protocol';
      const v = s.version ?? 0;
      if (v < 1 || v > 3) return `shadowtls: version must be 1..3, got ${v}`;
      break;
    }

    case 'ssh': {
      const s = n.ssh;
      if (!s || !s.user) return 'ssh: credential is required for this protocol (needs user)';
      if (!s.password && !s.private_key) return 'ssh: credential is required for this protocol (needs password or private key)';
      break;
    }

    case 'forgedns':
      if (!n.forgedns || !n.forgedns.zone) return 'forgedns: zone is required';
      if (!n.forgedns.adapter) return 'forgedns: adapter is required';
      break;

    default:
      return `unknown protocol: "${n.protocol}"`;
  }

  // Transport guards for the Xray family — h2/quic/mKCP were removed in Xray 26
  // and yield an unstartable config.
  if (usesTransport(n.protocol)) {
    switch (n.transport?.network) {
      case 'h2': return 'transport h2 was removed in Xray 26 — use xhttp (or ws/grpc)';
      case 'quic': return 'transport quic was removed in Xray 26 — use xhttp or a QUIC protocol (hysteria2/tuic)';
      case 'kcp': return 'transport mKCP was removed in Xray 26 — use ws/grpc/xhttp';
    }
  }

  if (n.security?.type === 'reality') {
    switch (n.transport?.network) {
      case 'tcp': case 'xhttp': case 'grpc': case undefined: break;
      default:
        return `REALITY only supports tcp, xhttp or grpc transport, not "${n.transport.network}"`;
    }
    const r = n.security.reality;
    if (!r) return 'reality requires a public key (client) or private key (server)';
    if (!r.public_key && !r.private_key) return 'reality requires a public key (client) or private key (server)';
    if ((!r.server_names || r.server_names.length === 0) && !n.security.server_name && !r.dest) {
      return 'reality requires a dest/serverName';
    }
    for (const sid of [...(r.short_ids ?? []), r.short_id ?? '']) {
      if (!sid) continue;
      if (sid.length > 16 || sid.length % 2 !== 0 || !isHex(sid)) {
        return `reality: invalid shortId "${sid}" (must be even-length hex, <=16 chars)`;
      }
    }
  }

  const fp = n.security?.fingerprint;
  if (fp && !VALID_FINGERPRINTS.includes(fp)) return `unknown uTLS fingerprint "${fp}"`;

  return null;
}
