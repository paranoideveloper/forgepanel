/**
 * Routing-rule emission, one function per client core.
 *
 * Each takes the same `RoutingConfig` and produces that core's native rule list.
 * The invariant the tests hold them to: for any config, every rule that
 * `activeRules()` reports must be present in ALL THREE outputs (a geosite token
 * in the Xray list, a rule_set reference in the sing-box list, a RULE-SET line
 * in the Clash list). A toggle that reaches two cores out of three is a bug that
 * silently sends traffic the wrong way.
 */

import type { RoutingConfig } from '../config/schema';
import { accumulate, singboxRuleSets, clashRuleProviders } from './rules';
import { isIPv4, isIPv6 } from '../common/net';
import type { JSONValue } from '../export/gojson';

export type JObj = Record<string, JSONValue>;

// ---------------------------------------------------------------------------
// Xray
// ---------------------------------------------------------------------------

export interface XrayRoutingOptions {
  /** Tag traffic falls through to. */
  finalTag: string;
  /** Emit `balancerTag` instead of `outboundTag` for the final rule. */
  balancer?: boolean;
}

export function xrayRouting(cfg: RoutingConfig, opts: XrayRoutingOptions): JObj[] {
  const acc = accumulate(cfg, 'xray');
  const rules: JObj[] = [];

  const push = (r: JObj) => rules.push({ type: 'field', ...r });

  // DNS first: a DNS rule below a catch-all never fires.
  push({ inboundTag: ['dns-in'], outboundTag: 'dns-out' });
  push({ port: 53, network: 'udp', outboundTag: 'dns-out' });

  if (cfg.bypassLAN) {
    push({ domain: ['geosite:private'], outboundTag: 'direct' });
    push({ ip: ['geoip:private'], outboundTag: 'direct' });
  }

  if (cfg.blockQUIC) {
    push({ port: 443, network: 'udp', outboundTag: 'block' });
  }

  const blockDomains = [...acc.block.geosites, ...acc.block.domains.map((d) => `domain:${d}`)];
  if (blockDomains.length) push({ domain: blockDomains, outboundTag: 'block' });

  const blockIPs = [...acc.block.geoips, ...acc.block.ips];
  if (blockIPs.length) push({ ip: blockIPs, outboundTag: 'block' });

  const bypassDomains = [...acc.bypass.geosites, ...acc.bypass.domains.map((d) => `domain:${d}`)];
  if (bypassDomains.length) push({ domain: bypassDomains, outboundTag: 'direct' });

  const bypassIPs = [...acc.bypass.geoips, ...acc.bypass.ips];
  if (bypassIPs.length) push({ ip: bypassIPs, outboundTag: 'direct' });

  if (opts.balancer) push({ network: 'tcp,udp', balancerTag: opts.finalTag });
  else push({ network: 'tcp,udp', outboundTag: opts.finalTag });

  return rules;
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

export interface SingboxRouteOptions {
  /** Outbound tag traffic falls through to (usually the selector). */
  finalTag: string;
}

export function singboxRoute(cfg: RoutingConfig, opts: SingboxRouteOptions): JObj {
  const acc = accumulate(cfg, 'sing-box');
  const rules: JObj[] = [
    { action: 'sniff' },
    { protocol: 'dns', action: 'hijack-dns' },
    { clash_mode: 'Direct', outbound: 'direct' },
    { clash_mode: 'Global', outbound: opts.finalTag },
  ];

  if (cfg.bypassLAN) rules.push({ ip_is_private: true, outbound: 'direct' });
  if (cfg.blockQUIC) rules.push({ network: 'udp', port: 443, action: 'reject' });

  if (acc.block.geosites.length) rules.push({ rule_set: acc.block.geosites, action: 'reject' });
  if (acc.block.domains.length) rules.push({ domain_suffix: acc.block.domains, action: 'reject' });
  if (acc.block.geoips.length) rules.push({ rule_set: acc.block.geoips, action: 'reject' });
  if (acc.block.ips.length) rules.push({ ip_cidr: acc.block.ips, action: 'reject' });

  if (acc.bypass.geosites.length) rules.push({ rule_set: acc.bypass.geosites, action: 'route', outbound: 'direct' });
  if (acc.bypass.domains.length) rules.push({ domain_suffix: acc.bypass.domains, action: 'route', outbound: 'direct' });
  if (acc.bypass.geoips.length) rules.push({ rule_set: acc.bypass.geoips, action: 'route', outbound: 'direct' });
  if (acc.bypass.ips.length) rules.push({ ip_cidr: acc.bypass.ips, action: 'route', outbound: 'direct' });

  const route: JObj = { rules, auto_detect_interface: true, final: opts.finalTag };
  const sets = singboxRuleSets(cfg);
  if (sets.length) route.rule_set = sets as unknown as JSONValue;
  return route;
}

// ---------------------------------------------------------------------------
// Clash / mihomo
// ---------------------------------------------------------------------------

function ipCidrRule(ip: string, target: string): string {
  const bare = isIPv6(ip) ? ip.replace(/[[\]]/g, '') : ip;
  const cidr = bare.includes('/') ? '' : isIPv4(bare) ? '/32' : '/128';
  return `IP-CIDR,${bare}${cidr},${target}`;
}

export function clashRules(cfg: RoutingConfig, finalTag: string): string[] {
  const acc = accumulate(cfg, 'clash');
  const rules: string[] = [];

  if (cfg.bypassLAN) rules.push('GEOIP,lan,DIRECT,no-resolve');
  if (cfg.blockQUIC) rules.push('AND,((NETWORK,udp),(DST-PORT,443)),REJECT');

  for (const g of acc.block.geosites) rules.push(`RULE-SET,${g},REJECT`);
  for (const d of acc.block.domains) rules.push(`DOMAIN-SUFFIX,${d},REJECT`);
  for (const g of acc.block.geoips) rules.push(`RULE-SET,${g},REJECT`);
  for (const ip of acc.block.ips) rules.push(ipCidrRule(ip, 'REJECT'));

  for (const g of acc.bypass.geosites) rules.push(`RULE-SET,${g},DIRECT`);
  for (const d of acc.bypass.domains) rules.push(`DOMAIN-SUFFIX,${d},DIRECT`);
  for (const g of acc.bypass.geoips) rules.push(`RULE-SET,${g},DIRECT`);
  for (const ip of acc.bypass.ips) rules.push(ipCidrRule(ip, 'DIRECT'));

  rules.push(`MATCH,${finalTag}`);
  return rules;
}

export { clashRuleProviders };
