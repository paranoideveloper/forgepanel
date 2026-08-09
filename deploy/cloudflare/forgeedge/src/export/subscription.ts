/**
 * Subscription generation — one user, one list, five renderings.
 *
 * The node list is the union of the VPS inbounds (from the canonical feed), the
 * edge Worker entries, and any ForgeDNS tunnels. It is assembled ONCE and then
 * rendered by the per-core exporters, which are byte-compatible mirrors of the
 * Go ones. That is the whole point: a subscriber's URL yields the same nodes in
 * whichever format their client asks for, and an entry looks identical whether
 * the panel or the edge produced it.
 *
 * Formats mirror `internal/api/sub.go`: links, v2ray (base64 of links), clash,
 * sing-box, xray, json.
 */

import type { Node } from '../model/node';
import type { EdgeConfig } from '../config/schema';
import { plainLinksMode, type PatternMode } from './uri';
import { singboxOutbound, SingboxUnsupportedError, type JObj } from './singbox';
import { xrayOutbound, XrayUnsupportedError } from './xray';
import { clashProxy, toYAML, uniqueClashName, ClashUnsupportedError, type YValue } from './clash';
import { goMarshalIndent, type JSONValue } from './gojson';
import { b64EncodeUtf8 } from '../common/encoding';
import { singboxRoute, clashRules, clashRuleProviders, xrayRouting } from '../routing/emit';
import { applyXrayFinalMask, applySingboxFragment, applyXrayECH } from './fragment';

export type SubFormat = 'links' | 'v2ray' | 'clash' | 'sing-box' | 'xray' | 'json';

/** Mirror of `api.canonicalSubFormat`, including every alias the Go side accepts. */
export function canonicalSubFormat(f: string): SubFormat | null {
  switch (f.trim().toLowerCase()) {
    case 'v2ray': case 'v2rayn': case 'v2rayng': case 'base64': case 'shadowrocket': return 'v2ray';
    case 'clash': case 'clash-meta': case 'clashmeta': case 'mihomo': return 'clash';
    case 'sing-box': case 'singbox': case 'sb': return 'sing-box';
    case 'xray': case 'xray-json': case 'v2ray-json': return 'xray';
    case 'links': case 'raw': case 'uri': case 'plain': return 'links';
    case 'json': return 'json';
    default: return null;
  }
}

/** Mirror of `api.detectFormat`. */
export function detectFormat(ua: string): SubFormat {
  const u = (ua ?? '').toLowerCase();
  if (u.includes('clash')) return 'clash';
  if (u.includes('sing-box') || u.includes('singbox')) return 'sing-box';
  return 'v2ray';
}

/** Where a node came from — drives the failover groups. */
export type NodeOrigin = 'edge' | 'vps' | 'forgedns' | 'external';

export interface OriginTaggedNode {
  node: Node;
  origin: NodeOrigin;
}

export function classify(nodes: Node[], origin: NodeOrigin): OriginTaggedNode[] {
  return nodes.map((node) => ({
    node,
    origin: node.protocol === 'forgedns' ? 'forgedns' : origin,
  }));
}

export interface SubscriptionInput {
  cfg: EdgeConfig;
  nodes: OriginTaggedNode[];
  /** Shown in Profile-Title and as the config remark. */
  title: string;
  /** unsafe-uTLS pattern variant for link/v2ray formats. */
  pattern?: PatternMode;
}

const URLTEST_URL = 'https://www.gstatic.com/generate_204';

const GROUP_ALL = 'Best Ping';
const GROUP_EDGE = 'Edge';
const GROUP_VPS = 'VPS';
const GROUP_DNS = 'ForgeDNS';
const GROUP_EXT = 'External';
const SELECTOR = 'proxy';
const DIRECT = 'direct';

/**
 * Deduplicate tags the way both Go renderers do: pre-reserve the tags the
 * document emits itself, then suffix collisions `name-2`, `name-3`, …
 */
function tagAllocator(reserved: string[]): (want: string, fallback: string) => string {
  const seen = new Map<string, number>();
  for (const r of reserved) seen.set(r, 1);
  return (want: string, fallback: string): string => {
    let tag = want || fallback;
    const k = seen.get(tag);
    if (k !== undefined) {
      seen.set(tag, k + 1);
      tag = `${tag}-${k + 1}`;
    }
    seen.set(tag, 1);
    return tag;
  };
}

function groupFor(origin: NodeOrigin): string {
  if (origin === 'edge') return GROUP_EDGE;
  if (origin === 'forgedns') return GROUP_DNS;
  if (origin === 'external') return GROUP_EXT;
  return GROUP_VPS;
}

// ---------------------------------------------------------------------------
// links / v2ray / json
// ---------------------------------------------------------------------------

export function renderLinks(input: SubscriptionInput): string {
  return plainLinksMode(input.nodes.map((n) => n.node), input.pattern ?? 'off');
}

export function renderV2Ray(input: SubscriptionInput): string {
  return b64EncodeUtf8(renderLinks(input));
}

export function renderJSON(input: SubscriptionInput): string {
  return goMarshalIndent(input.nodes.map((n) => n.node) as unknown as JSONValue, '  ');
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

export function renderSingbox(input: SubscriptionInput): string {
  const { cfg } = input;
  const alloc = tagAllocator([SELECTOR, DIRECT, GROUP_ALL, GROUP_EDGE, GROUP_VPS, GROUP_DNS, GROUP_EXT]);
  const outbounds: JObj[] = [];
  const byGroup = new Map<string, string[]>();
  const allTags: string[] = [];
  const skipped: string[] = [];

  input.nodes.forEach(({ node, origin }, i) => {
    let o: JObj;
    try {
      o = singboxOutbound(node);
    } catch (e) {
      if (e instanceof SingboxUnsupportedError) { skipped.push(`${node.remark ?? node.protocol}: ${e.message}`); return; }
      throw e;
    }
    const tag = alloc(String(o.tag ?? ''), `node-${i}`);
    o.tag = tag;
    applySingboxFragment(o, cfg.fragment);
    outbounds.push(o);
    allTags.push(tag);
    const g = groupFor(origin);
    if (!byGroup.has(g)) byGroup.set(g, []);
    byGroup.get(g)!.push(tag);
  });

  const groups: JObj[] = [];
  if (allTags.length > 1) {
    groups.push({
      type: 'urltest', tag: GROUP_ALL, outbounds: allTags,
      url: URLTEST_URL, interval: `${cfg.bestPingInterval}s`, interrupt_exist_connections: false,
    });
  }
  for (const [name, tags] of byGroup) {
    if (tags.length < 1) continue;
    groups.push({
      type: 'urltest', tag: name, outbounds: tags,
      url: URLTEST_URL, interval: `${cfg.bestPingInterval}s`, interrupt_exist_connections: false,
    });
  }

  const selectorMembers = [...groups.map((g) => String(g.tag)), ...allTags, DIRECT];
  const doc: JObj = {
    log: { level: cfg.logLevel === 'warning' ? 'warn' : cfg.logLevel, timestamp: true },
    outbounds: [
      ...outbounds,
      ...groups,
      {
        type: 'selector', tag: SELECTOR, outbounds: selectorMembers,
        default: selectorMembers[0] ?? DIRECT, interrupt_exist_connections: false,
      },
      { type: 'direct', tag: DIRECT },
    ] as unknown as JSONValue,
    route: singboxRoute(cfg.routing, { finalTag: SELECTOR }) as unknown as JSONValue,
    experimental: {
      cache_file: { enabled: true, store_fakeip: cfg.fakeDNS },
      clash_api: { external_controller: '127.0.0.1:9090', default_mode: 'Rule' },
    },
  };
  if (skipped.length) doc.forgeedge_skipped = skipped;
  return goMarshalIndent(doc as unknown as JSONValue, '  ');
}

// ---------------------------------------------------------------------------
// xray
// ---------------------------------------------------------------------------

export function renderXray(input: SubscriptionInput): string {
  const { cfg } = input;
  const alloc = tagAllocator(['direct', 'block', 'dns-out']);
  const outbounds: JObj[] = [];
  const allTags: string[] = [];
  const byGroup = new Map<string, string[]>();
  const skipped: string[] = [];

  input.nodes.forEach(({ node, origin }, i) => {
    let o: JObj;
    try {
      o = xrayOutbound(node) as JObj;
    } catch (e) {
      if (e instanceof XrayUnsupportedError) { skipped.push(`${node.remark ?? node.protocol}: ${e.message}`); return; }
      throw e;
    }
    const tag = alloc(String(o.tag ?? ''), `proxy-${i}`);
    o.tag = tag;
    applyXrayFinalMask(o, { fragment: cfg.fragment, udpNoises: cfg.udpNoises });
    applyXrayECH(o, cfg.enableECH, cfg.echServerName, cfg.localDNS);
    outbounds.push(o);
    allTags.push(tag);
    const g = groupFor(origin);
    if (!byGroup.has(g)) byGroup.set(g, []);
    byGroup.get(g)!.push(tag);
  });

  // Xray expresses failover as a balancer with a leastPing strategy fed by the
  // observatory. `selector` entries are tag PREFIXES, so exact tags are listed.
  const balancers: JObj[] = [];
  if (allTags.length > 1) {
    balancers.push({ tag: GROUP_ALL, selector: allTags, strategy: { type: 'leastPing' } });
    for (const [name, tags] of byGroup) {
      if (tags.length > 1) balancers.push({ tag: name, selector: tags, strategy: { type: 'leastPing' } });
    }
  }

  const finalTag = balancers.length ? GROUP_ALL : (allTags[0] ?? 'direct');
  const doc: JObj = {
    log: { loglevel: cfg.logLevel === 'warning' ? 'warning' : cfg.logLevel },
    inbounds: [
      { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { udp: true, auth: 'noauth' } },
      { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http' },
      { tag: 'dns-in', port: 10853, listen: '127.0.0.1', protocol: 'dokodemo-door', settings: { address: '1.1.1.1', port: 53, network: 'tcp,udp' } },
    ] as unknown as JSONValue,
    outbounds: [
      ...outbounds,
      { protocol: 'dns', tag: 'dns-out', settings: { rules: [{ action: 'hijack' }] } },
      { protocol: 'freedom', tag: 'direct', settings: { domainStrategy: cfg.enableIPv6 ? 'UseIPv4v6' : 'UseIPv4' } },
      { protocol: 'blackhole', tag: 'block', settings: { response: { type: 'http' } } },
    ] as unknown as JSONValue,
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: xrayRouting(cfg.routing, { finalTag, balancer: balancers.length > 0 }) as unknown as JSONValue,
      ...(balancers.length ? { balancers: balancers as unknown as JSONValue } : {}),
    },
    ...(balancers.length ? {
      observatory: {
        subjectSelector: allTags,
        probeURL: URLTEST_URL,
        probeInterval: `${cfg.bestPingInterval}s`,
        enableConcurrency: true,
      },
    } : {}),
    remarks: input.title,
  };
  if (skipped.length) doc.forgeedge_skipped = skipped;
  return goMarshalIndent(doc as unknown as JSONValue, '  ');
}

// ---------------------------------------------------------------------------
// clash / mihomo
// ---------------------------------------------------------------------------

export function renderClash(input: SubscriptionInput): string {
  const { cfg } = input;
  const seen = new Map<string, number>();
  // Reserve the group names so a node remark can never shadow a proxy-group.
  for (const g of ['PROXY', GROUP_ALL, GROUP_EDGE, GROUP_VPS, GROUP_DNS, GROUP_EXT]) seen.set(g, 1);

  const proxies: YValue[] = [];
  const allNames: YValue[] = [];
  const byGroup = new Map<string, YValue[]>();

  for (const { node, origin } of input.nodes) {
    let p: Record<string, YValue>;
    try {
      p = clashProxy(node);
    } catch (e) {
      if (e instanceof ClashUnsupportedError) continue;
      throw e;
    }
    const name = uniqueClashName(String(p.name), seen);
    p.name = name;
    proxies.push(p);
    allNames.push(name);
    const g = groupFor(origin);
    if (!byGroup.has(g)) byGroup.set(g, []);
    byGroup.get(g)!.push(name);
  }

  const groups: YValue[] = [];
  if (allNames.length > 1) {
    groups.push({
      name: GROUP_ALL, type: 'url-test', proxies: allNames,
      url: URLTEST_URL, interval: cfg.bestPingInterval, tolerance: 50,
    });
  }
  for (const [name, names] of byGroup) {
    if (names.length > 1) {
      groups.push({
        name, type: 'url-test', proxies: names,
        url: URLTEST_URL, interval: cfg.bestPingInterval, tolerance: 50,
      });
    }
  }

  const selectorMembers: YValue[] = [
    ...groups.map((g) => (g as Record<string, YValue>).name),
    ...allNames,
    'DIRECT',
  ];

  const doc: Record<string, YValue> = {
    'mixed-port': 7890,
    'allow-lan': false,
    'mode': 'rule',
    'log-level': cfg.logLevel === 'none' ? 'silent' : cfg.logLevel,
    'ipv6': cfg.enableIPv6,
    'external-controller': '127.0.0.1:9090',
    'profile': { 'store-selected': true, 'store-fake-ip': cfg.fakeDNS },
    'proxies': proxies,
    'proxy-groups': [
      { name: 'PROXY', type: 'select', proxies: selectorMembers },
      ...groups,
    ],
    'rules': clashRules(cfg.routing, 'PROXY'),
  };
  const providers = clashRuleProviders(cfg.routing);
  if (Object.keys(providers).length) doc['rule-providers'] = providers as unknown as YValue;

  return toYAML(doc);
}

// ---------------------------------------------------------------------------

export interface RenderedSubscription {
  body: string;
  contentType: string;
  filename: string;
}

export function renderSubscription(format: SubFormat, input: SubscriptionInput): RenderedSubscription {
  switch (format) {
    case 'links':
      return { body: renderLinks(input), contentType: 'text/plain; charset=utf-8', filename: 'forgeedge-links.txt' };
    case 'clash':
      return { body: renderClash(input), contentType: 'text/yaml; charset=utf-8', filename: 'forgeedge-clash.yaml' };
    case 'sing-box':
      return { body: renderSingbox(input), contentType: 'application/json; charset=utf-8', filename: 'forgeedge-sing-box.json' };
    case 'xray':
      return { body: renderXray(input), contentType: 'application/json; charset=utf-8', filename: 'forgeedge-xray.json' };
    case 'json':
      return { body: renderJSON(input), contentType: 'application/json; charset=utf-8', filename: 'forgeedge-nodes.json' };
    default:
      return { body: renderV2Ray(input), contentType: 'text/plain; charset=utf-8', filename: 'forgeedge-sub.txt' };
  }
}
