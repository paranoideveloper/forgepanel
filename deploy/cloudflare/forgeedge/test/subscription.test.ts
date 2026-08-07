/**
 * Subscription generation.
 *
 * The product claim under test: ONE user, ONE subscription, carrying the VPS
 * inbounds, the edge Worker entries and the ForgeDNS tunnels together, rendered
 * correctly for each client core with failover groups across the sources. Each
 * assertion below maps to a way that claim could quietly be false — a source
 * silently dropped, a group missing, a tag collision that makes sing-box refuse
 * the whole document.
 */

import { describe, expect, test } from 'bun:test';
import { defaultConfig, type EdgeConfig } from '../src/config/schema';
import type { Node } from '../src/model/node';
import { buildEdgeNodes, wsPath, edgeRemark, selectSniHost } from '../src/edge/nodes';
import {
  renderSubscription, canonicalSubFormat, detectFormat, classify,
  renderLinks, renderV2Ray, renderSingbox, renderXray, renderClash, renderJSON,
  type OriginTaggedNode,
} from '../src/export/subscription';
import { b64DecodeUtf8 } from '../src/common/encoding';
import { sanitizeFeed, findUser, userinfoHeader, type CanonicalFeed } from '../src/edge/feed';
import { parseChainProxy, ChainParseError } from '../src/edge/chain';

function cfg(overrides: Partial<EdgeConfig> = {}): EdgeConfig {
  return {
    ...defaultConfig(),
    vlessUUID: 'b831381d-6324-4d53-ad4f-8cda48b30811',
    trojanPassword: 'trojan-pw',
    wsPathSalt: 'salt123',
    ports: [443, 8443],
    ...overrides,
  };
}

const IDENTITY = {
  vlessUUID: 'b831381d-6324-4d53-ad4f-8cda48b30811',
  trojanPassword: 'trojan-pw',
  subjectKey: 'user-1',
};

/** A VPS inbound the edge could never terminate itself — proves it is merged, not re-derived. */
const VPS_HYSTERIA2: Node = {
  tag: 'VPS Hysteria2',
  remark: 'VPS Hysteria2',
  protocol: 'hysteria2',
  address: 'vps.example.com',
  port: 8443,
  password: 'hy2pass',
  transport: { network: 'tcp' },
  security: { type: 'tls', server_name: 'vps.example.com', alpn: ['h3'] },
  hysteria2: { up_mbps: 50, down_mbps: 200 },
};

const VPS_REALITY: Node = {
  tag: 'VPS REALITY',
  remark: 'VPS REALITY',
  protocol: 'vless',
  address: '203.0.113.10',
  port: 443,
  uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
  flow: 'xtls-rprx-vision',
  transport: { network: 'tcp' },
  security: {
    type: 'reality',
    fingerprint: 'chrome',
    reality: { public_key: 'pubkey', short_id: 'aabb', server_names: ['www.datadoghq.com'] },
  },
};

const FORGEDNS: Node = {
  tag: 'ForgeDNS tunnel',
  remark: 'ForgeDNS tunnel',
  protocol: 'forgedns',
  address: 'ns1.tunnel.example.com',
  port: 53,
  transport: { network: 'tcp' },
  security: { type: 'none' },
  forgedns: { adapter: 'stormdns', zone: 't.example.com', rrtype: 'TXT' },
};

function combined(c = cfg()): OriginTaggedNode[] {
  const edge = buildEdgeNodes({
    cfg: c,
    identity: IDENTITY,
    workerHost: 'forgeedge.workers.dev',
    addresses: ['104.16.0.1', 'cf.example.com'],
  });
  return [
    ...classify(edge, 'edge'),
    ...classify([VPS_REALITY, VPS_HYSTERIA2], 'vps'),
    ...classify([FORGEDNS], 'vps'),
  ];
}

describe('edge node minting', () => {
  test('produces one node per protocol × port × address', () => {
    const c = cfg({ protocols: ['vless', 'trojan'], ports: [443, 8443] });
    const nodes = buildEdgeNodes({
      cfg: c, identity: IDENTITY, workerHost: 'forgeedge.workers.dev',
      addresses: ['104.16.0.1', 'cf.example.com'],
    });
    // 2 protocols × 2 TLS ports × 3 addresses (host + 2 supplied).
    expect(nodes).toHaveLength(12);
    expect(nodes.every((n) => n.transport.network === 'ws')).toBe(true);
    expect(nodes.every((n) => n.security.type === 'tls')).toBe(true);
  });

  test('a plaintext CDN port is offered to VLESS but never to Trojan', () => {
    const c = cfg({ protocols: ['vless', 'trojan'], ports: [80, 443] });
    const nodes = buildEdgeNodes({
      cfg: c, identity: IDENTITY, workerHost: 'forgeedge.workers.dev', addresses: [],
    });
    const plain = nodes.filter((n) => n.port === 80);
    expect(plain.length).toBe(1);
    expect(plain[0].protocol).toBe('vless');
    expect(plain[0].security.type).toBe('none');
    expect(nodes.some((n) => n.protocol === 'trojan' && n.port === 80)).toBe(false);
  });

  test('a custom domain gets TLS ports only', () => {
    const c = cfg({ customDomain: 'edge.example.com', ports: [80, 443, 8443] });
    const nodes = buildEdgeNodes({
      cfg: c, identity: IDENTITY, workerHost: 'edge.example.com', addresses: [],
    });
    expect(nodes.every((n) => n.port !== 80)).toBe(true);
  });

  test('the WS path is stable for a subject and different across subjects', () => {
    expect(wsPath('vl', 'salt', 'user-1')).toBe(wsPath('vl', 'salt', 'user-1'));
    expect(wsPath('vl', 'salt', 'user-1')).not.toBe(wsPath('vl', 'salt', 'user-2'));
    expect(wsPath('vl', 'salt', 'user-1')).not.toBe(wsPath('tr', 'salt', 'user-1'));
    expect(wsPath('vl', 'salt-a', 'u')).not.toBe(wsPath('vl', 'salt-b', 'u'));
    // The first segment is what the router dispatches on.
    expect(wsPath('vl', 's', 'u').split('/')[1]).toBe('vl');
    expect(wsPath('tr', 's', 'u').split('/')[1]).toBe('tr');
  });

  test('per-user credentials from the feed override the shared edge identity', () => {
    const nodes = buildEdgeNodes({
      cfg: cfg({ protocols: ['vless'], ports: [443] }),
      identity: { ...IDENTITY, vlessUUID: '11111111-2222-4333-8444-555555555555' },
      workerHost: 'forgeedge.workers.dev', addresses: [],
    });
    expect(nodes[0].uuid).toBe('11111111-2222-4333-8444-555555555555');
  });

  test('a custom CDN front carries its own Host/SNI and allows the mismatch', () => {
    const c = cfg({
      customCdnAddrs: ['cdn.front.example'], customCdnHost: 'real.example', customCdnSni: 'sni.example',
    });
    const sel = selectSniHost(c, 'cdn.front.example', 'forgeedge.workers.dev');
    expect(sel).toEqual({ host: 'real.example', sni: 'sni.example', allowInsecure: true });
    const plain = selectSniHost(c, '104.16.0.1', 'forgeedge.workers.dev');
    expect(plain.host).toBe('forgeedge.workers.dev');
    expect(plain.allowInsecure).toBe(false);
    // The SNI is case-jittered but must still be the same hostname.
    expect(plain.sni.toLowerCase()).toBe('forgeedge.workers.dev');
  });

  test('remarks label the address kind so a user can tell entries apart', () => {
    const c = cfg({ cleanIPs: ['cf.example.com'] });
    expect(edgeRemark(c, 1, 'vless', 'cf.example.com', 443, false)).toContain('Clean IP');
    expect(edgeRemark(c, 2, 'trojan', '104.16.0.1', 443, false)).toContain('IPv4');
    expect(edgeRemark(c, 3, 'vless', 'a.example.com', 443, true)).toContain('D ');
  });
});

describe('format negotiation', () => {
  test('every alias the Go panel accepts maps to the same canonical format', () => {
    expect(canonicalSubFormat('v2rayng')).toBe('v2ray');
    expect(canonicalSubFormat('shadowrocket')).toBe('v2ray');
    expect(canonicalSubFormat('mihomo')).toBe('clash');
    expect(canonicalSubFormat('singbox')).toBe('sing-box');
    expect(canonicalSubFormat('XRAY-JSON')).toBe('xray');
    expect(canonicalSubFormat(' raw ')).toBe('links');
    expect(canonicalSubFormat('nonsense')).toBeNull();
  });

  test('User-Agent sniffing matches api.detectFormat', () => {
    expect(detectFormat('ClashMetaForAndroid/2.11')).toBe('clash');
    expect(detectFormat('sing-box 1.12')).toBe('sing-box');
    expect(detectFormat('v2rayNG/1.8')).toBe('v2ray');
    expect(detectFormat('')).toBe('v2ray');
  });
});

describe('combined subscription', () => {
  const nodes = combined();
  const input = { cfg: cfg(), nodes, title: 'ForgeEdge' };

  test('the links list contains edge, VPS and ForgeDNS entries', () => {
    const links = renderLinks(input);
    expect(links).toContain('vless://');
    expect(links).toContain('trojan://');
    expect(links).toContain('hysteria2://');
    expect(links).toContain('forgedns://');
    expect(links.split('\n').filter(Boolean).length).toBe(nodes.length);
  });

  test('v2ray format is base64 of exactly the links list', () => {
    expect(b64DecodeUtf8(renderV2Ray(input))).toBe(renderLinks(input));
  });

  test('json format round-trips the canonical nodes', () => {
    const parsed = JSON.parse(renderJSON(input)) as Node[];
    expect(parsed).toHaveLength(nodes.length);
    expect(parsed.some((n) => n.protocol === 'hysteria2')).toBe(true);
    expect(parsed.some((n) => n.protocol === 'forgedns')).toBe(true);
  });

  describe('sing-box', () => {
    const doc = JSON.parse(renderSingbox(input)) as {
      outbounds: Record<string, unknown>[]; route: Record<string, unknown>;
      forgeedge_skipped?: string[];
    };

    test('carries VLESS, Trojan and Hysteria2 outbounds', () => {
      const types = new Set(doc.outbounds.map((o) => o.type));
      expect(types.has('vless')).toBe(true);
      expect(types.has('trojan')).toBe(true);
      expect(types.has('hysteria2')).toBe(true);
    });

    test('skips ForgeDNS with a stated reason rather than silently', () => {
      expect(doc.forgeedge_skipped?.some((s) => s.includes('ForgeDNS'))).toBe(true);
    });

    test('every outbound tag is unique — a collision makes sing-box refuse the config', () => {
      const tags = doc.outbounds.map((o) => o.tag as string);
      expect(new Set(tags).size).toBe(tags.length);
    });

    test('emits url-test groups for all, edge and VPS, plus a selector and direct', () => {
      const byTag = new Map(doc.outbounds.map((o) => [o.tag as string, o]));
      expect(byTag.get('Best Ping')?.type).toBe('urltest');
      expect(byTag.get('Edge')?.type).toBe('urltest');
      expect(byTag.get('VPS')?.type).toBe('urltest');
      expect(byTag.get('proxy')?.type).toBe('selector');
      expect(byTag.get('direct')?.type).toBe('direct');
    });

    test('the Edge group holds only edge tags and the VPS group only VPS tags', () => {
      const byTag = new Map(doc.outbounds.map((o) => [o.tag as string, o]));
      const edge = byTag.get('Edge')!.outbounds as string[];
      const vps = byTag.get('VPS')!.outbounds as string[];
      expect(edge.every((t) => t.startsWith('ForgeEdge'))).toBe(true);
      expect(vps.every((t) => t.startsWith('VPS'))).toBe(true);
      expect(edge.some((t) => vps.includes(t))).toBe(false);
    });

    test('routing falls through to the selector', () => {
      expect(doc.route.final).toBe('proxy');
    });
  });

  describe('clash', () => {
    const yaml = renderClash(input);

    test('is valid-looking YAML with proxies, groups and rules', () => {
      expect(yaml).toContain('proxies:');
      expect(yaml).toContain('proxy-groups:');
      expect(yaml).toContain('rules:');
      // Rule strings contain commas, so the emitter quotes them — same rule as
      // Go's yamlNeedsQuote. The catch-all is always last.
      expect(yaml.trimEnd().endsWith('- "MATCH,PROXY"')).toBe(true);
    });

    test('carries the representable protocols and drops ForgeDNS', () => {
      expect(yaml).toContain('type: vless');
      expect(yaml).toContain('type: trojan');
      expect(yaml).toContain('type: hysteria2');
      expect(yaml).not.toContain('forgedns');
    });

    test('emits url-test groups alongside the select group', () => {
      expect(yaml).toContain('name: PROXY');
      expect(yaml).toContain('type: url-test');
      expect(yaml).toContain('name: Best Ping');
      expect(yaml).toContain('name: Edge');
    });

    test('mihomo bandwidth fields are strings, not integers', () => {
      expect(yaml).toContain('up: 50 Mbps');
      expect(yaml).toContain('down: 200 Mbps');
    });

    test('a proxy name can never collide with a group name', () => {
      const collide = {
        cfg: cfg(),
        title: 'ForgeEdge',
        nodes: classify([{ ...VPS_REALITY, remark: 'Best Ping', tag: 'Best Ping' }], 'vps'),
      };
      const out = renderClash(collide);
      // The node had to be renamed; the group keeps the bare name.
      expect(out).toContain('name: "Best Ping #2"');
    });
  });

  describe('xray', () => {
    const doc = JSON.parse(renderXray(input)) as {
      outbounds: Record<string, unknown>[];
      routing: { rules: Record<string, unknown>[]; balancers?: Record<string, unknown>[] };
      observatory?: Record<string, unknown>;
      forgeedge_skipped?: string[];
    };

    test('carries the Xray-native protocols', () => {
      const protocols = new Set(doc.outbounds.map((o) => o.protocol));
      expect(protocols.has('vless')).toBe(true);
      expect(protocols.has('trojan')).toBe(true);
      expect(protocols.has('freedom')).toBe(true);
      expect(protocols.has('blackhole')).toBe(true);
    });

    test('skips Hysteria2 and ForgeDNS with a reason — Xray has neither', () => {
      expect(doc.forgeedge_skipped?.length).toBeGreaterThanOrEqual(2);
      expect(doc.forgeedge_skipped!.join(' ')).toContain('Hysteria2');
      expect(doc.forgeedge_skipped!.join(' ')).toContain('ForgeDNS');
    });

    test('failover is a leastPing balancer fed by the observatory', () => {
      expect(doc.routing.balancers?.some((b) => b.tag === 'Best Ping')).toBe(true);
      const balancer = doc.routing.balancers!.find((b) => b.tag === 'Best Ping')!;
      expect((balancer.strategy as { type: string }).type).toBe('leastPing');
      expect(doc.observatory).toBeTruthy();
    });

    test('the catch-all rule targets the balancer, not an outbound', () => {
      const last = doc.routing.rules[doc.routing.rules.length - 1];
      expect(last.balancerTag).toBe('Best Ping');
      expect(last.outboundTag).toBeUndefined();
    });

    test('reserved tags are never taken by a node', () => {
      const nodeTags = doc.outbounds
        .filter((o) => !['freedom', 'blackhole', 'dns'].includes(o.protocol as string))
        .map((o) => o.tag as string);
      expect(nodeTags).not.toContain('direct');
      expect(nodeTags).not.toContain('block');
      expect(nodeTags).not.toContain('dns-out');
      expect(new Set(nodeTags).size).toBe(nodeTags.length);
    });

    test('fragment settings appear only when fragmentation is enabled', () => {
      const off = JSON.parse(renderXray({ ...input, cfg: cfg({ udpNoises: [] }) })) as { outbounds: Record<string, unknown>[] };
      expect(JSON.stringify(off)).not.toContain('"fragment"');

      const on = JSON.parse(renderXray({
        ...input,
        cfg: cfg({ fragment: { ...defaultConfig().fragment, enabled: true, lengthMin: 10, lengthMax: 20 } }),
      })) as { outbounds: Record<string, unknown>[] };
      const withMask = on.outbounds.find((o) => (o.streamSettings as Record<string, unknown>)?.finalmask);
      expect(withMask).toBeTruthy();
      const mask = (withMask!.streamSettings as { finalmask: { tcp: { settings: { length: string } }[] } }).finalmask;
      expect(mask.tcp[0].settings.length).toBe('10-20');
    });

    test('UDP noise is emitted when configured', () => {
      const doc2 = JSON.parse(renderXray(input)) as { outbounds: Record<string, unknown>[] };
      expect(JSON.stringify(doc2)).toContain('"noise"');
    });
  });

  test('renderSubscription dispatches to the right renderer and content type', () => {
    expect(renderSubscription('clash', input).contentType).toContain('yaml');
    expect(renderSubscription('sing-box', input).contentType).toContain('json');
    expect(renderSubscription('links', input).body).toBe(renderLinks(input));
    expect(renderSubscription('v2ray', input).body).toBe(renderV2Ray(input));
  });

  test('an empty node list still renders a loadable document for every format', () => {
    const empty = { cfg: cfg(), nodes: [], title: 'ForgeEdge' };
    expect(renderLinks(empty)).toBe('');
    const sb = JSON.parse(renderSingbox(empty)) as { outbounds: Record<string, unknown>[] };
    expect(sb.outbounds.some((o) => o.tag === 'direct')).toBe(true);
    const cl = renderClash(empty);
    expect(cl).toContain('MATCH,PROXY');
    const xr = JSON.parse(renderXray(empty)) as { routing: { rules: Record<string, unknown>[] } };
    expect(xr.routing.rules.length).toBeGreaterThan(0);
  });
});

describe('canonical feed', () => {
  const raw: CanonicalFeed = {
    version: 1,
    generated_at: '2026-08-07T00:00:00Z',
    users: [
      {
        id: 'u1', sub_token: 'tok-1', enabled: true, nodes: [VPS_REALITY],
        used_traffic: 1024, data_limit: 4096, expires_at: '2026-12-31T00:00:00Z',
      },
      { id: 'u2', sub_token: 'tok-2', enabled: false, nodes: [] },
    ],
    shared_nodes: [FORGEDNS],
  };

  test('sanitize keeps well-formed users and shared nodes', () => {
    const { feed, warnings } = sanitizeFeed(raw);
    expect(feed.users).toHaveLength(2);
    expect(feed.shared_nodes).toHaveLength(1);
    expect(warnings).toHaveLength(0);
  });

  test('sanitize drops malformed users and nodes, and says so', () => {
    const { feed, warnings } = sanitizeFeed({
      version: 1,
      users: [
        { id: 'ok', sub_token: 't', enabled: true, nodes: [VPS_REALITY, { junk: true }, null] },
        { id: 'no-token', enabled: true, nodes: [] },
        'not-an-object',
      ],
    });
    expect(feed.users).toHaveLength(1);
    expect(feed.users[0].nodes).toHaveLength(1);
    expect(warnings.length).toBeGreaterThanOrEqual(2);
  });

  test('sanitize survives complete garbage', () => {
    expect(sanitizeFeed(null).feed.users).toHaveLength(0);
    expect(sanitizeFeed('nope').feed.users).toHaveLength(0);
    expect(sanitizeFeed({ users: 'nope' }).warnings.length).toBeGreaterThan(0);
  });

  test('a disabled user resolves to null, so their subscription empties out', () => {
    const { feed } = sanitizeFeed(raw);
    expect(findUser(feed, 'tok-1')?.id).toBe('u1');
    expect(findUser(feed, 'tok-2')).toBeNull();
    expect(findUser(feed, 'unknown')).toBeNull();
  });

  test('Subscription-Userinfo matches the Go panel format', () => {
    const { feed } = sanitizeFeed(raw);
    const info = userinfoHeader(findUser(feed, 'tok-1'));
    expect(info).toBe('upload=0; download=1024; total=4096; expire=1798675200');
    expect(userinfoHeader(null)).toBe('upload=0; download=0; total=0; expire=0');
  });
});

describe('chain proxy parsing', () => {
  test('parses a VLESS chain with transport and REALITY', () => {
    const n = parseChainProxy(
      'vless://b831381d-6324-4d53-ad4f-8cda48b30811@chain.example.com:443?type=grpc&serviceName=svc&security=reality&pbk=KEY&sid=aabb&fp=chrome#My%20chain');
    expect(n.protocol).toBe('vless');
    expect(n.address).toBe('chain.example.com');
    expect(n.transport.network).toBe('grpc');
    expect(n.transport.service_name).toBe('svc');
    expect(n.security.type).toBe('reality');
    expect(n.security.reality?.public_key).toBe('KEY');
    expect(n.remark).toBe('My chain');
  });

  test('parses trojan, ss, socks and http chains', () => {
    expect(parseChainProxy('trojan://pw@c.example:443?security=tls&sni=c.example').protocol).toBe('trojan');

    const ss = parseChainProxy(`ss://${Buffer.from('aes-256-gcm:sspw').toString('base64url')}@c.example:8388`);
    expect(ss.protocol).toBe('shadowsocks');
    expect(ss.method).toBe('aes-256-gcm');
    expect(ss.password).toBe('sspw');

    const socks = parseChainProxy(`socks://${Buffer.from('u:p').toString('base64url')}@c.example:1080`);
    expect(socks.protocol).toBe('socks');
    expect(socks.username).toBe('u');
    expect(socks.password).toBe('p');

    const http = parseChainProxy('http://u:p@c.example:8080');
    expect(http.protocol).toBe('http');
    expect(http.username).toBe('u');
  });

  test('parses a vmess base64-JSON chain', () => {
    const json = JSON.stringify({
      v: '2', ps: 'vm', add: 'c.example', port: '443', id: 'b831381d-6324-4d53-ad4f-8cda48b30811',
      net: 'ws', path: '/p', host: 'h.example', tls: 'tls', sni: 's.example', scy: 'auto',
    });
    const n = parseChainProxy('vmess://' + Buffer.from(json).toString('base64'));
    expect(n.protocol).toBe('vmess');
    expect(n.transport.path).toBe('/p');
    expect(n.security.server_name).toBe('s.example');
  });

  test('rejects an unsupported scheme and unparseable input', () => {
    expect(() => parseChainProxy('hysteria2://x@y:443')).toThrow(ChainParseError);
    expect(() => parseChainProxy('not a url')).toThrow(ChainParseError);
    expect(() => parseChainProxy('')).toThrow(ChainParseError);
  });

  test('a parsed chain survives a round-trip through the exporters', () => {
    const n = parseChainProxy('trojan://pw@c.example:443?type=ws&path=%2Fp&security=tls&sni=c.example');
    const out = renderSubscription('links', { cfg: cfg(), nodes: classify([n], 'vps'), title: 't' });
    expect(out.body).toContain('trojan://pw@c.example:443');
    expect(out.body).toContain('type=ws');
  });
});
