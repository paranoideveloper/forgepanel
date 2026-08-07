/**
 * Backend Mode, the WARP scanner, clean-IP handling and config validation.
 *
 * The theme running through this file is the platform constraint: a Worker has
 * outbound TCP and nothing else. The tests assert that the code says so plainly
 * — that the scanner returns `measured: false` rather than a made-up latency,
 * and that the backend forwarder preserves the client's own path so the VPS
 * sees an untouched upgrade.
 */

import { describe, expect, test } from 'bun:test';
import { backendTarget } from '../src/protocols/backend';
import {
  enumerateCandidates, rank, WARP_PREFIXES, type WarpCandidate,
} from '../src/warp/scanner';
import { wireguardConf, warpNode, warpNodes, amneziaTuning } from '../src/warp/config';
import { reservedFromClientID, type WarpAccount } from '../src/warp/account';
import {
  isValidCleanEntry, parseCleanList, BUILTIN_CLEAN_HOSTS,
} from '../src/cleanip/list';
import { validateConfig } from '../src/config/validate';
import { defaultConfig, DEFAULT_WARP, type EdgeConfig } from '../src/config/schema';
import { retryTarget } from '../src/protocols/retry';
import { nodeURI } from '../src/export/uri';
import { singboxOutbound } from '../src/export/singbox';

describe('Backend Mode target composition', () => {
  test('a bare backend origin keeps the client path and query', () => {
    const incoming = new URL('https://edge.workers.dev/vl/abc123?ed=2560');
    expect(backendTarget('https://vps.example.com', incoming))
      .toBe('https://vps.example.com/vl/abc123?ed=2560');
  });

  test('a backend URL with a path pins the endpoint', () => {
    const incoming = new URL('https://edge.workers.dev/vl/abc123');
    expect(backendTarget('https://vps.example.com/forgeedge', incoming))
      .toBe('https://vps.example.com/forgeedge');
  });

  test('ws:// and wss:// are rewritten to what fetch() accepts', () => {
    const incoming = new URL('https://edge.workers.dev/tr/x');
    expect(backendTarget('wss://vps.example.com', incoming)).toBe('https://vps.example.com/tr/x');
    expect(backendTarget('ws://vps.example.com:8080', incoming)).toBe('http://vps.example.com:8080/tr/x');
  });

  test('a non-URL backend yields null instead of throwing', () => {
    expect(backendTarget('not a url', new URL('https://e.dev/x'))).toBeNull();
    expect(backendTarget('', new URL('https://e.dev/x'))).toBeNull();
  });
});

describe('outbound retry strategy', () => {
  const base = { proxyIPs: [], nat64Prefixes: ['[2602:fc59:b0:64::]'], dohUpstream: '' };

  test('mode "off" has no retry — the failure is reported, not papered over', async () => {
    expect(await retryTarget('example.com', 443, { ...base, proxyIPMode: 'off' })).toBeNull();
  });

  test('mode "proxyip" targets the configured relay, carrying its port when given', async () => {
    const one = await retryTarget('example.com', 443, {
      ...base, proxyIPMode: 'proxyip', proxyIPs: ['relay.example.com:8443'],
    });
    expect(one).toEqual({ address: 'relay.example.com', port: 8443 });

    const noPort = await retryTarget('example.com', 443, {
      ...base, proxyIPMode: 'proxyip', proxyIPs: ['relay.example.com'],
    });
    expect(noPort).toEqual({ address: 'relay.example.com', port: 443 });
  });

  test('mode "proxyip" with no relays configured yields null', async () => {
    expect(await retryTarget('example.com', 443, { ...base, proxyIPMode: 'proxyip' })).toBeNull();
  });

  test('mode "nat64" maps an IPv4 destination without needing DNS', async () => {
    const t = await retryTarget('93.184.216.34', 443, { ...base, proxyIPMode: 'nat64' });
    expect(t).toEqual({ address: '[2602:fc59:b0:64::5db8:d822]', port: 443 });
  });

  test('mode "nat64" with no prefixes yields null', async () => {
    expect(await retryTarget('1.2.3.4', 443, { ...base, proxyIPMode: 'nat64', nat64Prefixes: [] })).toBeNull();
  });
});

describe('WARP endpoint scanner', () => {
  test('candidates are well-formed host:port pairs from the published prefixes', () => {
    const c = enumerateCandidates(28);
    expect(c).toHaveLength(28);
    for (const { endpoint } of c) {
      const [host, port] = endpoint.split(':');
      expect(WARP_PREFIXES.some((p) => host.startsWith(p + '.'))).toBe(true);
      const last = Number(host.split('.')[3]);
      expect(last).toBeGreaterThanOrEqual(1);
      expect(last).toBeLessThanOrEqual(254);
      expect(Number(port)).toBeGreaterThan(0);
    }
  });

  test('candidates are unique and spread across every prefix', () => {
    const c = enumerateCandidates(28);
    expect(new Set(c.map((x) => x.endpoint)).size).toBe(28);
    const prefixes = new Set(c.map((x) => x.endpoint.split('.').slice(0, 3).join('.')));
    // A single blocked /24 must not be able to kill the whole list.
    expect(prefixes.size).toBe(WARP_PREFIXES.length);
  });

  test('enumeration is deterministic per seed and differs across seeds', () => {
    expect(enumerateCandidates(10, 'a')).toEqual(enumerateCandidates(10, 'a'));
    expect(enumerateCandidates(10, 'a')).not.toEqual(enumerateCandidates(10, 'b'));
  });

  test('unmeasured candidates never carry a latency — no invented numbers', () => {
    for (const c of enumerateCandidates(20)) {
      expect(c.measured).toBe(false);
      expect(c.latencyMs).toBeUndefined();
    }
  });

  test('rank puts measured endpoints first, fastest first, then the rest in order', () => {
    const input: WarpCandidate[] = [
      { endpoint: 'a:1', measured: false },
      { endpoint: 'b:2', measured: true, latencyMs: 120 },
      { endpoint: 'c:3', measured: false },
      { endpoint: 'd:4', measured: true, latencyMs: 40 },
    ];
    expect(rank(input).map((c) => c.endpoint)).toEqual(['d:4', 'b:2', 'a:1', 'c:3']);
  });
});

describe('WARP / WireGuard config generation', () => {
  const account: WarpAccount = {
    privateKey: '4NyxMUme2zGv5r3QWI0hJBlNglm1J/thoCE55PK29G8=',
    publicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
    warpIPv6: '2606:4700:110:8fd2:11f3:8e67:11d4:3704/128',
    reserved: 'N16D',
  };

  test('the plain conf is a standard wg-quick file with no Amnezia lines', () => {
    const conf = wireguardConf(account, 'engage.cloudflareclient.com:2408', DEFAULT_WARP, false);
    expect(conf).toContain('[Interface]');
    expect(conf).toContain(`PrivateKey = ${account.privateKey}`);
    expect(conf).toContain('Address = 172.16.0.2/32, 2606:4700:110:8fd2:11f3:8e67:11d4:3704/128');
    expect(conf).toContain('MTU = 1280');
    expect(conf).toContain('[Peer]');
    expect(conf).toContain('AllowedIPs = 0.0.0.0/0, ::/0');
    expect(conf).toContain('Endpoint = engage.cloudflareclient.com:2408');
    expect(conf).not.toContain('Jc =');
  });

  test('the pro conf adds junk packets but leaves the header magics standard', () => {
    const conf = wireguardConf(account, '162.159.192.1:2408', DEFAULT_WARP, true);
    expect(conf).toContain(`Jc = ${DEFAULT_WARP.amneziaNoiseCount}`);
    expect(conf).toContain(`Jmin = ${DEFAULT_WARP.amneziaNoiseSizeMin}`);
    expect(conf).toContain(`Jmax = ${DEFAULT_WARP.amneziaNoiseSizeMax}`);
    // Cloudflare's server is not Amnezia-aware: changing S1/S2 or H1..H4 would
    // make it drop the handshake, so only the discardable junk is used.
    expect(conf).toContain('S1 = 0');
    expect(conf).toContain('S2 = 0');
    expect(conf).toContain('H1 = 1');
    expect(conf).toContain('H4 = 4');
  });

  test('amneziaTuning keeps the safe constants regardless of the noise settings', () => {
    const t = amneziaTuning({ ...DEFAULT_WARP, amneziaNoiseCount: 12 });
    expect(t.jc).toBe(12);
    expect([t.s1, t.s2, t.h1, t.h2, t.h3, t.h4]).toEqual([0, 0, 1, 2, 3, 4]);
  });

  test('the WARP node carries the client key where every renderer reads it', () => {
    const n = warpNode(account, '162.159.192.1:2408', DEFAULT_WARP, false, 'WARP 1');
    expect(n.protocol).toBe('wireguard');
    expect(n.address).toBe('162.159.192.1');
    expect(n.port).toBe(2408);
    expect(n.wireguard?.peer_private_key).toBe(account.privateKey);
    expect(n.wireguard?.reserved).toEqual(reservedFromClientID('N16D'));
    // render/singbox.go reads peer_private_key for a client outbound.
    const sb = singboxOutbound(n) as Record<string, unknown>;
    expect(sb.private_key).toBe(account.privateKey);
    expect(sb.peer_public_key).toBe(account.publicKey);
  });

  test('the pro node is amneziawg and keeps its obfuscation parameters', () => {
    const n = warpNode(account, '162.159.192.1:2408', DEFAULT_WARP, true, 'WARP Pro');
    expect(n.protocol).toBe('amneziawg');
    expect(n.amneziawg?.jc).toBe(DEFAULT_WARP.amneziaNoiseCount);
    expect(n.amneziawg?.h1).toBe(1);
  });

  test('reserved bytes can be switched off, yielding [0,0,0]', () => {
    const n = warpNode(account, '162.159.192.1:2408', { ...DEFAULT_WARP, reservedBytes: false }, false, 'x');
    expect(n.wireguard?.reserved).toEqual([0, 0, 0]);
  });

  test('one node per configured endpoint, and each exports as a link', () => {
    const nodes = warpNodes([account], { ...DEFAULT_WARP, endpoints: ['a.example:2408', 'b.example:500'] }, false);
    expect(nodes).toHaveLength(2);
    for (const n of nodes) expect(nodeURI(n)).toStartWith('wireguard://');
  });

  test('no accounts means no nodes — never a placeholder tunnel', () => {
    expect(warpNodes([], DEFAULT_WARP, false)).toHaveLength(0);
  });

  test('reservedFromClientID decodes to exactly three bytes', () => {
    const r = reservedFromClientID('N16D');
    expect(r).toHaveLength(3);
    for (const b of r) expect(b).toBeGreaterThanOrEqual(0);
  });
});

describe('clean IP list', () => {
  test('accepts hostnames and IP literals, with or without a port', () => {
    for (const good of ['speed.cloudflare.com', '104.16.0.1', '104.16.0.1:8443',
      '[2606:4700::1]', '[2606:4700::1]:2053', 'cf.090227.xyz']) {
      expect(isValidCleanEntry(good), good).toBe(true);
    }
  });

  test('rejects anything that is not an address', () => {
    for (const bad of ['', '   ', 'not a host', 'http://example.com/', '<script>',
      'a'.repeat(300), '999.999.999.999']) {
      expect(isValidCleanEntry(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test('parses a list, skipping comments and taking the first CSV column', () => {
    const text = [
      '# comment', '// also a comment', '', '  ',
      '104.16.0.1', '104.16.0.2,120ms,fast', 'cf.example.com  ',
      'garbage entry with spaces', 'http://nope',
    ].join('\n');
    expect(parseCleanList(text)).toEqual(['104.16.0.1', '104.16.0.2', 'cf.example.com']);
  });

  test('respects the entry limit so a huge source cannot blow up KV', () => {
    const text = Array.from({ length: 5000 }, (_, i) => `104.16.${i % 256}.${(i * 7) % 256}`).join('\n');
    expect(parseCleanList(text, 500)).toHaveLength(500);
  });

  test('the built-in seeds are all valid entries', () => {
    for (const h of BUILTIN_CLEAN_HOSTS) expect(isValidCleanEntry(h), h).toBe(true);
  });
});

describe('config validation', () => {
  const base = (): EdgeConfig => ({
    ...defaultConfig(),
    vlessUUID: 'b831381d-6324-4d53-ad4f-8cda48b30811',
    trojanPassword: 'pw',
  });

  test('the default config is valid', () => {
    expect(validateConfig(base())).toEqual([]);
  });

  test('rejects a protocol the edge cannot terminate', () => {
    const errs = validateConfig({ ...base(), protocols: ['hysteria2' as never] });
    expect(errs.join(' ')).toContain('vless');
  });

  test('rejects an empty protocol or port list', () => {
    expect(validateConfig({ ...base(), protocols: [] }).length).toBeGreaterThan(0);
    expect(validateConfig({ ...base(), ports: [] }).length).toBeGreaterThan(0);
  });

  test('rejects a port Cloudflare does not front', () => {
    const errs = validateConfig({ ...base(), ports: [1234] });
    expect(errs.join(' ')).toContain('1234');
  });

  test('rejects a malformed UUID and a missing Trojan password', () => {
    expect(validateConfig({ ...base(), vlessUUID: 'nope' }).join(' ')).toContain('UUID');
    expect(validateConfig({ ...base(), trojanPassword: '' }).join(' ')).toContain('trojanPassword');
  });

  test('rejects junk in the clean-IP and CDN lists', () => {
    expect(validateConfig({ ...base(), cleanIPs: ['<script>'] }).length).toBe(1);
    expect(validateConfig({ ...base(), customCdnAddrs: ['not a host'] }).length).toBe(1);
  });

  test('rejects an unparseable chain proxy', () => {
    expect(validateConfig({ ...base(), chainProxy: 'garbage' }).join(' ')).toContain('chainProxy');
    expect(validateConfig({ ...base(), chainProxy: 'trojan://pw@c.example:443' })).toEqual([]);
  });

  test('backend mode requires a usable URL', () => {
    expect(validateConfig({
      ...base(), backend: { enabled: true, url: '', token: '', fallbackToEdge: true },
    }).join(' ')).toContain('backend.url');
    expect(validateConfig({
      ...base(), backend: { enabled: true, url: 'ftp://x', token: '', fallbackToEdge: true },
    }).join(' ')).toContain('backend.url');
    expect(validateConfig({
      ...base(), backend: { enabled: true, url: 'wss://vps.example/ws', token: '', fallbackToEdge: true },
    })).toEqual([]);
  });

  test('a retry mode with nothing configured is rejected, not silently inert', () => {
    expect(validateConfig({ ...base(), proxyIPMode: 'proxyip', proxyIPs: [] }).length).toBe(1);
    expect(validateConfig({ ...base(), proxyIPMode: 'nat64', nat64Prefixes: [] }).length).toBe(1);
  });

  test('rejects a NAT64 prefix that is not a bracketed IPv6 prefix', () => {
    expect(validateConfig({
      ...base(), proxyIPMode: 'nat64', nat64Prefixes: ['2602:fc59:b0:64::'],
    }).join(' ')).toContain('bracketed');
  });

  test('reports every problem at once rather than stopping at the first', () => {
    const errs = validateConfig({
      ...base(), vlessUUID: 'bad', ports: [1234], cleanIPs: ['<x>'], chainProxy: 'junk',
    });
    expect(errs.length).toBeGreaterThanOrEqual(4);
  });
});
