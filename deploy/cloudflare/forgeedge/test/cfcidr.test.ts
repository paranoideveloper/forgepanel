import { describe, expect, test } from 'bun:test';
import { CLOUDFLARE_CIDRS, randomIPInCIDR, randomCloudflareIPs } from '../src/cleanip/cfcidr';
import { isValidCleanEntry } from '../src/cleanip/list';

function ipToInt(ip: string): number {
  return ip.split('.').reduce((a, o) => ((a << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;
}
function inCIDR(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split('/');
  const mask = Number(bits) === 0 ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

describe('CF-CIDR clean-IP randomizer', () => {
  test('randomIPInCIDR always lands inside its range, never network/broadcast', () => {
    for (const cidr of CLOUDFLARE_CIDRS) {
      for (let i = 0; i < 50; i++) {
        const ip = randomIPInCIDR(cidr);
        expect(inCIDR(ip, cidr)).toBe(true);
        const host = ipToInt(ip) & ~((0xffffffff << (32 - Number(cidr.split('/')[1]))) >>> 0);
        expect(host).toBeGreaterThan(0); // not the network address
      }
    }
  });

  test('randomCloudflareIPs returns the requested count of distinct, valid entries', () => {
    const ips = randomCloudflareIPs(6);
    expect(ips.length).toBe(6);
    expect(new Set(ips).size).toBe(6);
    for (const ip of ips) {
      expect(isValidCleanEntry(ip)).toBe(true);
      expect(CLOUDFLARE_CIDRS.some((c) => inCIDR(ip, c))).toBe(true);
    }
  });

  test('successive calls rotate (astronomically unlikely to repeat the whole set)', () => {
    const a = randomCloudflareIPs(8).join(',');
    const b = randomCloudflareIPs(8).join(',');
    expect(a).not.toBe(b);
  });
});
