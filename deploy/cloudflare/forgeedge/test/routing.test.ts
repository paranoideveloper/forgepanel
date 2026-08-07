/**
 * Routing-rule emission.
 *
 * The invariant these tests hold: a toggle that is ON must reach ALL THREE
 * cores. A rule that exists for Xray but silently vanishes for Clash is how a
 * "bypass Iran" switch ends up sending a user's Iranian banking traffic through
 * the proxy, which is exactly the failure this product cannot have.
 */

import { describe, expect, test } from 'bun:test';
import { DEFAULT_ROUTING, type RoutingConfig } from '../src/config/schema';
import {
  RULE_CATALOGUE, SANCTION_RULES, activeRules, accumulate,
  singboxRuleSets, clashRuleProviders,
} from '../src/routing/rules';
import { xrayRouting, singboxRoute, clashRules } from '../src/routing/emit';

const allOn: RoutingConfig = {
  bypassLAN: true,
  bypassIran: true,
  bypassChina: true,
  bypassRussia: true,
  bypassSanctions: true,
  blockQUIC: true,
  blockAds: true,
  blockMalware: true,
  blockPhishing: true,
  blockCryptominers: true,
  blockPorn: true,
  customBypassRules: ['bank.ir', '10.0.0.0/8'],
  customBypassSanctionRules: ['openai.com'],
  customBlockRules: ['ads.example.com', '198.51.100.7'],
};

const allOff: RoutingConfig = {
  ...allOn,
  bypassLAN: false,
  bypassIran: false, bypassChina: false, bypassRussia: false, bypassSanctions: false,
  blockQUIC: false, blockAds: false, blockMalware: false, blockPhishing: false,
  blockCryptominers: false, blockPorn: false,
  customBypassRules: [], customBypassSanctionRules: [], customBlockRules: [],
};

const jsonOf = (v: unknown): string => JSON.stringify(v);

describe('rule catalogue', () => {
  test('every catalogue row has all three core spellings for its geosite', () => {
    for (const r of [...RULE_CATALOGUE, ...SANCTION_RULES]) {
      expect(r.xrayGeosite, `${r.id} xray`).toBeTruthy();
      expect(r.sbGeosite, `${r.id} sing-box`).toBeTruthy();
      expect(r.sbGeositeURL, `${r.id} sing-box url`).toBeTruthy();
      expect(r.clGeosite, `${r.id} clash`).toBeTruthy();
      expect(r.clGeositeURL, `${r.id} clash url`).toBeTruthy();
    }
  });

  test('a row with a geoip has it for all three cores', () => {
    for (const r of [...RULE_CATALOGUE, ...SANCTION_RULES]) {
      const any = r.xrayGeoip || r.sbGeoip || r.clGeoip;
      if (!any) continue;
      expect(r.xrayGeoip, `${r.id} xray geoip`).toBeTruthy();
      expect(r.sbGeoip, `${r.id} sing-box geoip`).toBeTruthy();
      expect(r.clGeoip, `${r.id} clash geoip`).toBeTruthy();
    }
  });

  test('sanctioned services resolve through the anti-sanction DNS, not the local one', () => {
    for (const r of SANCTION_RULES) expect(r.dns).toBe('antiSanction');
  });

  test('activeRules honours the toggles', () => {
    expect(activeRules(allOff)).toHaveLength(0);
    expect(activeRules(allOn).length).toBe(RULE_CATALOGUE.length + SANCTION_RULES.length);
    const onlyIran = activeRules({ ...allOff, bypassIran: true });
    expect(onlyIran).toHaveLength(1);
    expect(onlyIran[0].id).toBe('bypassIran');
  });
});

describe('cross-core completeness', () => {
  test('every enabled rule appears in all three emitted rule lists', () => {
    const xray = jsonOf(xrayRouting(allOn, { finalTag: 'proxy' }));
    const sb = jsonOf(singboxRoute(allOn, { finalTag: 'proxy' }));
    const cl = clashRules(allOn, 'PROXY').join('\n');

    for (const r of activeRules(allOn)) {
      expect(xray, `${r.id} missing from xray`).toContain(r.xrayGeosite!);
      expect(sb, `${r.id} missing from sing-box`).toContain(r.sbGeosite!);
      expect(cl, `${r.id} missing from clash`).toContain(`RULE-SET,${r.clGeosite},`);
      if (r.xrayGeoip) {
        expect(xray, `${r.id} geoip missing from xray`).toContain(r.xrayGeoip);
        expect(sb, `${r.id} geoip missing from sing-box`).toContain(r.sbGeoip!);
        expect(cl, `${r.id} geoip missing from clash`).toContain(`RULE-SET,${r.clGeoip},`);
      }
    }
  });

  test('every enabled rule is downloadable: sing-box rule_set and clash rule-providers', () => {
    const sets = new Set(singboxRuleSets(allOn).map((s) => s.tag));
    const providers = clashRuleProviders(allOn);
    for (const r of activeRules(allOn)) {
      expect(sets.has(r.sbGeosite!), `${r.id} has no sing-box rule_set`).toBe(true);
      expect(providers[r.clGeosite!], `${r.id} has no clash rule-provider`).toBeTruthy();
      if (r.sbGeoip) expect(sets.has(r.sbGeoip)).toBe(true);
      if (r.clGeoip) expect(providers[r.clGeoip]).toBeTruthy();
    }
  });

  test('every rule-set URL is https', () => {
    for (const s of singboxRuleSets(allOn)) expect(s.url.startsWith('https://')).toBe(true);
    for (const p of Object.values(clashRuleProviders(allOn))) {
      expect(String(p.url).startsWith('https://')).toBe(true);
    }
  });
});

describe('block vs bypass separation', () => {
  test('block rules are rejected and bypass rules are direct in every core', () => {
    const acc = accumulate(allOn, 'xray');
    expect(acc.block.geosites).toContain('geosite:category-ads-all');
    expect(acc.bypass.geosites).toContain('geosite:category-ir');
    expect(acc.bypass.domains).toContain('bank.ir');
    expect(acc.bypass.domains).toContain('openai.com');
    expect(acc.bypass.ips).toContain('10.0.0.0/8');
    expect(acc.block.domains).toContain('ads.example.com');
    expect(acc.block.ips).toContain('198.51.100.7');
  });

  test('clash renders custom IPs as IP-CIDR with an explicit mask', () => {
    const rules = clashRules(allOn, 'PROXY');
    expect(rules).toContain('IP-CIDR,198.51.100.7/32,REJECT');
    expect(rules).toContain('IP-CIDR,10.0.0.0/8,DIRECT');
  });

  test('a block rule is emitted before the matching bypass rule', () => {
    const rules = clashRules(allOn, 'PROXY');
    const firstBlock = rules.findIndex((r) => r.endsWith(',REJECT'));
    const firstBypass = rules.findIndex((r) => r.endsWith(',DIRECT') && !r.startsWith('GEOIP,lan'));
    expect(firstBlock).toBeGreaterThanOrEqual(0);
    expect(firstBlock).toBeLessThan(firstBypass);
  });
});

describe('LAN and QUIC toggles', () => {
  test('bypassLAN emits a private-address rule per core', () => {
    expect(jsonOf(xrayRouting(allOn, { finalTag: 'p' }))).toContain('geoip:private');
    expect(jsonOf(singboxRoute(allOn, { finalTag: 'p' }))).toContain('ip_is_private');
    expect(clashRules(allOn, 'P')).toContain('GEOIP,lan,DIRECT,no-resolve');
  });

  test('bypassLAN off removes it everywhere', () => {
    const off = { ...allOff, bypassLAN: false };
    expect(jsonOf(xrayRouting(off, { finalTag: 'p' }))).not.toContain('geoip:private');
    expect(jsonOf(singboxRoute(off, { finalTag: 'p' }))).not.toContain('ip_is_private');
    expect(clashRules(off, 'P').some((r) => r.includes('lan'))).toBe(false);
  });

  test('blockQUIC rejects UDP/443 in each core', () => {
    const xray = xrayRouting(allOn, { finalTag: 'p' });
    expect(xray.some((r) => r.port === 443 && r.network === 'udp' && r.outboundTag === 'block')).toBe(true);
    const sb = singboxRoute(allOn, { finalTag: 'p' }) as { rules: Record<string, unknown>[] };
    expect(sb.rules.some((r) => r.network === 'udp' && r.port === 443 && r.action === 'reject')).toBe(true);
    expect(clashRules(allOn, 'P')).toContain('AND,((NETWORK,udp),(DST-PORT,443)),REJECT');
  });
});

describe('final / fallthrough behaviour', () => {
  test('xray ends with the catch-all pointing at the final tag', () => {
    const rules = xrayRouting(DEFAULT_ROUTING, { finalTag: 'Best Ping' });
    const last = rules[rules.length - 1];
    expect(last.network).toBe('tcp,udp');
    expect(last.outboundTag).toBe('Best Ping');
  });

  test('xray uses balancerTag instead of outboundTag when balancing', () => {
    const rules = xrayRouting(DEFAULT_ROUTING, { finalTag: 'Best Ping', balancer: true });
    const last = rules[rules.length - 1];
    expect(last.balancerTag).toBe('Best Ping');
    expect(last.outboundTag).toBeUndefined();
  });

  test('sing-box sets final and auto_detect_interface', () => {
    const route = singboxRoute(DEFAULT_ROUTING, { finalTag: 'proxy' }) as Record<string, unknown>;
    expect(route.final).toBe('proxy');
    expect(route.auto_detect_interface).toBe(true);
  });

  test('clash ends with MATCH', () => {
    const rules = clashRules(DEFAULT_ROUTING, 'PROXY');
    expect(rules[rules.length - 1]).toBe('MATCH,PROXY');
  });

  test('DNS rules come before the catch-all in xray', () => {
    const rules = xrayRouting(allOn, { finalTag: 'p' });
    const dnsIdx = rules.findIndex((r) => r.outboundTag === 'dns-out');
    const catchAll = rules.length - 1;
    expect(dnsIdx).toBeGreaterThanOrEqual(0);
    expect(dnsIdx).toBeLessThan(catchAll);
  });

  test('an all-off config still produces a usable rule list', () => {
    expect(clashRules(allOff, 'PROXY')).toEqual(['MATCH,PROXY']);
    expect(singboxRuleSets(allOff)).toHaveLength(0);
    expect(Object.keys(clashRuleProviders(allOff))).toHaveLength(0);
    const xray = xrayRouting(allOff, { finalTag: 'p' });
    expect(xray[xray.length - 1].outboundTag).toBe('p');
  });
});
