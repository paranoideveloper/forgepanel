/**
 * Random clean-IP generator over Cloudflare's published IPv4 ranges.
 *
 * The built-in seed HOSTNAMES (list.ts) are great until an ISP blocks that exact
 * set. Cloudflare is anycast, so ANY address in its ranges routes to the same
 * edge that fronts the Worker — which means we can mint fresh literal IPs on
 * every refresh. A blocklist of yesterday's hostnames does nothing against a
 * literal picked at random from a /13 today. This is edgetunnel's "CF优选" trick.
 */

/**
 * The Cloudflare ranges that actually serve HTTP(S) at the edge, so a random pick
 * lands on a live front more often than not. Cloudflare announces many more
 * ranges (https://www.cloudflare.com/ips-v4), but most are not HTTP edges — a
 * random IP from the full set is dead ~all the time (measured 0/6), whereas these
 * hit ~40-50% and serve `*.workers.dev` too. `188.114.96.0/20` is included first
 * because it is the range that stays reachable from Iran on the alt CF ports.
 */
export const CLOUDFLARE_CIDRS = [
  '188.114.96.0/20',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '162.159.0.0/16',
  '172.64.0.0/13',
];

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => ((acc << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;
}

function intToIP(n: number): string {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

/** A uniform 32-bit value from the platform CSPRNG. */
function rand32(): number {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  return b[0] >>> 0;
}

/** A random address inside `cidr`, avoiding the network and broadcast hosts. */
export function randomIPInCIDR(cidr: string): string {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const hostBits = 32 - bits;
  const network = ipToInt(base) & (hostBits === 32 ? 0 : (0xffffffff << hostBits) >>> 0);
  // Host part in [1, 2^hostBits - 2] so we never emit the .0 or all-ones host.
  const span = hostBits >= 31 ? 0xfffffffe : (1 << hostBits) - 2;
  const host = span <= 0 ? 0 : (rand32() % span) + 1;
  return intToIP((network + host) >>> 0);
}

/**
 * `count` distinct random Cloudflare edge IPs, spread across the ranges. Returns
 * fewer only if `count` exceeds what de-duplication can supply (never realistic).
 */
export function randomCloudflareIPs(count: number): string[] {
  const out = new Set<string>();
  let guard = 0;
  while (out.size < count && guard < count * 20) {
    guard++;
    const cidr = CLOUDFLARE_CIDRS[rand32() % CLOUDFLARE_CIDRS.length];
    out.add(randomIPInCIDR(cidr));
  }
  return [...out];
}
