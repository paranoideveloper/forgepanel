/**
 * Address helpers shared by the proxy data path and the exporters.
 * `hostPort` mirrors Go `export.hostPort` so links bracket IPv6 identically.
 */

export function isDomain(address: string): boolean {
  if (!address) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(address);
}

export function isIPv4(address: string): boolean {
  return /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/.test(address);
}

/** True for a bracketed IPv6 literal, e.g. `[2606:4700::1]` — the form used in links. */
export function isIPv6(address: string): boolean {
  return /^\[[0-9a-fA-F:.]+\](?:\/\d{1,3})?$/.test(address) && address.includes(':');
}

/** Go `export.hostPort`: bracket a bare IPv6 literal, leave everything else alone. */
export function hostPort(addr: string, port: number): string {
  if (addr.includes(':') && !addr.startsWith('[')) return `[${addr}]:${port}`;
  return `${addr}:${port}`;
}

/** Split `host:port`, `[v6]:port`, `host` or `[v6]`. `brackets` keeps the `[]` on IPv6. */
export function parseHostPort(input: string, brackets = false): { host: string; port: number } {
  const m = input.match(/^(?:\[(?<ipv6>.+?)\]|(?<host>[^:]+))(?::(?<port>\d+))?$/);
  if (!m || !m.groups) return { host: '', port: 0 };
  const { ipv6, host: plain, port } = m.groups;
  let host = ipv6 ?? plain ?? '';
  if (brackets && ipv6) host = `[${ipv6}]`;
  return { host, port: port ? Number(port) : 0 };
}

/**
 * Map an IPv4 address into a NAT64 prefix, producing the IPv6 literal a Worker
 * can `connect()` to when the direct IPv4 path is blocked. `prefix` is a
 * bracketed /64 such as `[2602:fc59:b0:64::]`.
 *
 * Returns null for a malformed input rather than throwing, so the caller can
 * fall through to the next strategy instead of killing the tunnel.
 */
export function toNAT64(ipv4: string, prefix: string): string | null {
  const parts = ipv4.split('.');
  if (parts.length !== 4) return null;
  const hex: string[] = [];
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    hex.push(n.toString(16).padStart(2, '0'));
  }
  const m = prefix.match(/^\[([0-9A-Fa-f:]+)\]$/);
  if (!m) return null;
  return `[${m[1]}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
}

/** Randomly upper-case letters of a hostname — a cheap SNI-casing jitter. */
export function randomUpperCase(s: string): string {
  let out = '';
  for (const ch of s) out += Math.random() < 0.5 ? ch.toUpperCase() : ch;
  return out;
}

const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Cryptographically random alphanumeric string of length in [min, max]. */
export function randomString(min: number, max: number): string {
  const len = min + Math.floor(Math.random() * (max - min + 1));
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < len; i++) out += CHARSET[bytes[i] % CHARSET.length];
  return out;
}

export function isValidUUID(uuid: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}
