import { describe, expect, test } from 'bun:test';
import { defaultConfig } from '../src/config/schema';
import { buildServerlessXray, serverlessVariant, SERVERLESS_VARIANTS } from '../src/export/serverless';

describe('serverless (workerless) configs', () => {
  const cfg = defaultConfig();

  test('produces a proxy-less config: only freedom/dns/blackhole outbounds', () => {
    const doc = JSON.parse(buildServerlessXray(cfg, SERVERLESS_VARIANTS[0]));
    const protos = doc.outbounds.map((o: { protocol: string }) => o.protocol);
    // No vless/trojan/etc. — the whole point is that there is no proxy.
    expect(protos).not.toContain('vless');
    expect(protos).not.toContain('trojan');
    expect(protos).toContain('freedom');
    expect(protos).toContain('dns');
    expect(protos).toContain('blackhole');
  });

  test('the default (proxy) outbound fragments the TLS ClientHello', () => {
    const doc = JSON.parse(buildServerlessXray(cfg, SERVERLESS_VARIANTS[0]));
    const proxy = doc.outbounds.find((o: { tag: string }) => o.tag === 'proxy');
    expect(proxy).toBeDefined();
    const frag = proxy.streamSettings.finalmask.tcp[0];
    expect(frag.type).toBe('fragment');
    expect(frag.settings.packets).toBe('tlshello');
    // proxy is the FIRST outbound, so unmatched traffic defaults to it.
    expect(doc.outbounds[0].tag).toBe('proxy');
  });

  test('UDP gets noise and QUIC (udp/443) is blocked so it cannot bypass the fragmenter', () => {
    const doc = JSON.parse(buildServerlessXray(cfg, SERVERLESS_VARIANTS[0]));
    const noise = doc.outbounds.find((o: { tag: string }) => o.tag === 'udp-noise');
    expect(noise.streamSettings.finalmask.udp[0].type).toBe('noise');
    const rules = doc.routing.rules as Array<Record<string, unknown>>;
    expect(rules.some((r) => r.network === 'udp' && r.port === '443' && r.outboundTag === 'block')).toBe(true);
    expect(rules.some((r) => r.outboundTag === 'udp-noise')).toBe(true);
  });

  test('the two variants differ by resolver + remark; unknown id falls back to cf', () => {
    expect(SERVERLESS_VARIANTS.map((v) => v.dnsIP)).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(serverlessVariant('google').dnsIP).toBe('8.8.8.8');
    expect(serverlessVariant('nonsense').id).toBe('cf');
    expect(serverlessVariant(undefined).id).toBe('cf');
    const g = JSON.parse(buildServerlessXray(cfg, serverlessVariant('google')));
    expect(g.inbounds.find((i: { tag: string }) => i.tag === 'dns-in').settings.address).toBe('8.8.8.8');
  });
});
