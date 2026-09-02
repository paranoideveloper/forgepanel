/**
 * The single routing-ruleset table. Every toggle in `RoutingConfig` maps to one
 * row here, and each row knows how it is spelled for each client core.
 *
 * WHY one table instead of three: a rule that exists for Xray but silently
 * vanishes for Clash is the most common way a "bypass Iran" switch turns into a
 * user's Iranian bank traffic going through the proxy. Keeping the three
 * spellings adjacent makes an omission visible in review and testable in one
 * assertion (`test/routing.test.ts` enforces that every enabled rule reaches
 * every core).
 */

import type { RoutingConfig } from '../config/schema';

export type RuleAction = 'direct' | 'block';

/** Which DNS a bypassed rule should resolve through. */
export type RuleDNS = 'local' | 'antiSanction' | 'remote';

export interface GeoRule {
  /** Stable identifier; also the RoutingConfig key that toggles it. */
  id: keyof RoutingConfig;
  action: RuleAction;
  dns: RuleDNS;
  /** Xray geosite/geoip tokens, e.g. "geosite:category-ir". */
  xrayGeosite?: string;
  xrayGeoip?: string;
  /** sing-box remote rule-set tags + .srs URLs. */
  sbGeosite?: string;
  sbGeositeURL?: string;
  sbGeoip?: string;
  sbGeoipURL?: string;
  /** Clash rule-provider names, URLs and formats. */
  clGeosite?: string;
  clGeositeURL?: string;
  clGeoip?: string;
  clGeoipURL?: string;
  clFormat?: 'text' | 'yaml';
}

const SB = 'https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set';
const CL = 'https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release';
const MC = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo';

/**
 * The full catalogue. `bypassSanctions` is a single toggle covering the
 * services that geo-block Iranian IPs (OpenAI, Google DeepMind, Microsoft,
 * Oracle, Docker, Adobe, Epic, Intel, AMD, NVIDIA) — one switch, many geosites,
 * because operators reason about "sanctioned services", not about Adobe.
 */
export const RULE_CATALOGUE: GeoRule[] = [
  {
    id: 'blockAds', action: 'block', dns: 'local',
    xrayGeosite: 'geosite:category-ads-all',
    sbGeosite: 'geosite-category-ads-all', sbGeositeURL: `${SB}/geosite-category-ads-all.srs`,
    clGeosite: 'category-ads-all', clGeositeURL: `${CL}/category-ads-all.txt`, clFormat: 'text',
  },
  {
    id: 'blockMalware', action: 'block', dns: 'local',
    xrayGeosite: 'geosite:malware', xrayGeoip: 'geoip:malware',
    sbGeosite: 'geosite-malware', sbGeositeURL: `${SB}/geosite-malware.srs`,
    sbGeoip: 'geoip-malware', sbGeoipURL: `${SB}/geoip-malware.srs`,
    clGeosite: 'malware', clGeositeURL: `${CL}/malware.txt`,
    clGeoip: 'malware-cidr', clGeoipURL: `${CL}/malware-ip.txt`, clFormat: 'text',
  },
  {
    id: 'blockPhishing', action: 'block', dns: 'local',
    xrayGeosite: 'geosite:phishing', xrayGeoip: 'geoip:phishing',
    sbGeosite: 'geosite-phishing', sbGeositeURL: `${SB}/geosite-phishing.srs`,
    sbGeoip: 'geoip-phishing', sbGeoipURL: `${SB}/geoip-phishing.srs`,
    clGeosite: 'phishing', clGeositeURL: `${CL}/phishing.txt`,
    clGeoip: 'phishing-cidr', clGeoipURL: `${CL}/phishing-ip.txt`, clFormat: 'text',
  },
  {
    id: 'blockCryptominers', action: 'block', dns: 'local',
    xrayGeosite: 'geosite:cryptominers',
    sbGeosite: 'geosite-cryptominers', sbGeositeURL: `${SB}/geosite-cryptominers.srs`,
    clGeosite: 'cryptominers', clGeositeURL: `${CL}/cryptominers.txt`, clFormat: 'text',
  },
  {
    id: 'blockPorn', action: 'block', dns: 'local',
    xrayGeosite: 'geosite:category-porn',
    sbGeosite: 'geosite-nsfw', sbGeositeURL: `${SB}/geosite-nsfw.srs`,
    clGeosite: 'nsfw', clGeositeURL: `${CL}/nsfw.txt`, clFormat: 'text',
  },
  {
    id: 'bypassIran', action: 'direct', dns: 'local',
    xrayGeosite: 'geosite:category-ir', xrayGeoip: 'geoip:ir',
    sbGeosite: 'geosite-ir', sbGeositeURL: `${SB}/geosite-ir.srs`,
    sbGeoip: 'geoip-ir', sbGeoipURL: `${SB}/geoip-ir.srs`,
    clGeosite: 'ir', clGeositeURL: `${CL}/ir.txt`,
    clGeoip: 'ir-cidr', clGeoipURL: `${CL}/ircidr.txt`, clFormat: 'text',
  },
  {
    id: 'bypassChina', action: 'direct', dns: 'local',
    xrayGeosite: 'geosite:cn', xrayGeoip: 'geoip:cn',
    sbGeosite: 'geosite-cn', sbGeositeURL: `${SB}/geosite-cn.srs`,
    sbGeoip: 'geoip-cn', sbGeoipURL: `${SB}/geoip-cn.srs`,
    clGeosite: 'cn', clGeositeURL: `${MC}/geosite/cn.yaml`,
    clGeoip: 'cn-cidr', clGeoipURL: `${MC}/geoip/cn.yaml`, clFormat: 'yaml',
  },
  {
    id: 'bypassRussia', action: 'direct', dns: 'local',
    xrayGeosite: 'geosite:category-ru', xrayGeoip: 'geoip:ru',
    sbGeosite: 'geosite-category-ru', sbGeositeURL: `${SB}/geosite-category-ru.srs`,
    sbGeoip: 'geoip-ru', sbGeoipURL: `${SB}/geoip-ru.srs`,
    clGeosite: 'ru', clGeositeURL: `${MC}/geosite/category-ru.yaml`,
    clGeoip: 'ru-cidr', clGeoipURL: `${MC}/geoip/ru.yaml`, clFormat: 'yaml',
  },
];

/** The sanctioned-service geosites, expanded from the single `bypassSanctions` toggle. */
const SANCTIONED = [
  { name: 'openai', mc: 'openai' },
  { name: 'google-deepmind', mc: 'google-deepmind' },
  { name: 'microsoft', mc: 'microsoft' },
  { name: 'oracle', mc: 'oracle' },
  { name: 'docker', mc: 'docker' },
  { name: 'adobe', mc: 'adobe' },
  { name: 'epicgames', mc: 'epicgames' },
  { name: 'intel', mc: 'intel' },
  { name: 'amd', mc: 'amd' },
  { name: 'nvidia', mc: 'nvidia' },
];

export const SANCTION_RULES: GeoRule[] = SANCTIONED.map(({ name, mc }) => ({
  id: 'bypassSanctions' as const,
  action: 'direct' as const,
  dns: 'antiSanction' as const,
  xrayGeosite: `geosite:${name}`,
  sbGeosite: `geosite-${name}`,
  sbGeositeURL: `${SB}/geosite-${name}.srs`,
  clGeosite: name,
  clGeositeURL: `${MC}/geosite/${mc}.yaml`,
  clFormat: 'yaml' as const,
}));

/** Every rule the operator has switched on, in catalogue order. */
export function activeRules(cfg: RoutingConfig): GeoRule[] {
  const out: GeoRule[] = [];
  for (const r of RULE_CATALOGUE) if (cfg[r.id] === true) out.push(r);
  if (cfg.bypassSanctions) out.push(...SANCTION_RULES);
  return out;
}

export interface AccumulatedRules {
  bypass: { geosites: string[]; geoips: string[]; domains: string[]; ips: string[] };
  block: { geosites: string[]; geoips: string[]; domains: string[]; ips: string[] };
}

const isDomainRule = (s: string): boolean =>
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(s);

/**
 * Split the active rules into the four buckets every core needs, using the
 * requested `core` spelling for geosite/geoip tokens.
 */
export function accumulate(cfg: RoutingConfig, core: 'xray' | 'sing-box' | 'clash'): AccumulatedRules {
  const rules = activeRules(cfg);
  const pick = (r: GeoRule, kind: 'site' | 'ip'): string | undefined => {
    if (core === 'xray') return kind === 'site' ? r.xrayGeosite : r.xrayGeoip;
    if (core === 'sing-box') return kind === 'site' ? r.sbGeosite : r.sbGeoip;
    return kind === 'site' ? r.clGeosite : r.clGeoip;
  };

  const acc: AccumulatedRules = {
    bypass: { geosites: [], geoips: [], domains: [], ips: [] },
    block: { geosites: [], geoips: [], domains: [], ips: [] },
  };

  for (const r of rules) {
    const bucket = r.action === 'direct' ? acc.bypass : acc.block;
    const site = pick(r, 'site');
    const ip = pick(r, 'ip');
    if (site) bucket.geosites.push(site);
    if (ip) bucket.geoips.push(ip);
  }

  acc.bypass.domains = [
    ...cfg.customBypassRules.filter(isDomainRule),
    ...cfg.customBypassSanctionRules.filter(isDomainRule),
  ];
  acc.bypass.ips = cfg.customBypassRules.filter((s) => !isDomainRule(s));
  acc.block.domains = cfg.customBlockRules.filter(isDomainRule);
  acc.block.ips = cfg.customBlockRules.filter((s) => !isDomainRule(s));

  return acc;
}

/** sing-box remote rule_set entries for every active rule. */
export function singboxRuleSets(cfg: RoutingConfig): { type: string; tag: string; format: string; url: string; download_detour: string }[] {
  const out: { type: string; tag: string; format: string; url: string; download_detour: string }[] = [];
  for (const r of activeRules(cfg)) {
    if (r.sbGeosite && r.sbGeositeURL) {
      out.push({ type: 'remote', tag: r.sbGeosite, format: 'binary', url: r.sbGeositeURL, download_detour: 'direct' });
    }
    if (r.sbGeoip && r.sbGeoipURL) {
      out.push({ type: 'remote', tag: r.sbGeoip, format: 'binary', url: r.sbGeoipURL, download_detour: 'direct' });
    }
  }
  return out;
}

/** Clash rule-providers for every active rule. */
export function clashRuleProviders(cfg: RoutingConfig): Record<string, Record<string, string | number>> {
  const out: Record<string, Record<string, string | number>> = {};
  for (const r of activeRules(cfg)) {
    const fmt = r.clFormat ?? 'text';
    const ext = fmt === 'text' ? 'txt' : fmt;
    if (r.clGeosite && r.clGeositeURL) {
      out[r.clGeosite] = {
        type: 'http', format: fmt, behavior: 'domain',
        path: `./ruleset/${r.clGeosite}.${ext}`, interval: 86400, url: r.clGeositeURL,
      };
    }
    if (r.clGeoip && r.clGeoipURL) {
      out[r.clGeoip] = {
        type: 'http', format: fmt, behavior: 'ipcidr',
        path: `./ruleset/${r.clGeoip}.${ext}`, interval: 86400, url: r.clGeoipURL,
      };
    }
  }
  return out;
}
