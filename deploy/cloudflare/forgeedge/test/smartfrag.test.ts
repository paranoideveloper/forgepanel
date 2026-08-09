import { describe, expect, test } from 'bun:test';
import { defaultConfig } from '../src/config/schema';
import { buildEdgeNodes } from '../src/edge/nodes';
import { buildSmartFragmentXray, SMART_FRAGMENT_LENGTHS } from '../src/export/smartfrag';

describe('smart fragment sweep', () => {
  const cfg = defaultConfig();
  cfg.vlessUUID = '11111111-2222-3333-4444-555555555555';
  cfg.wsPathSalt = 'salt';
  const node = buildEdgeNodes({
    cfg,
    identity: { vlessUUID: cfg.vlessUUID, trojanPassword: 'pw', subjectKey: 'shared' },
    workerHost: 'forgeedge.example.workers.dev',
    addresses: ['forgeedge.example.workers.dev'],
  }).filter((n) => n.protocol === 'vless' && n.port === 443)[0];

  test('emits one outbound per fragment length, all leastPing-grouped', () => {
    const doc = JSON.parse(buildSmartFragmentXray(cfg, node, 'ForgeEdge'));
    const frags = doc.outbounds.filter((o: { tag?: string }) => o.tag?.startsWith('frag '));
    expect(frags.length).toBe(SMART_FRAGMENT_LENGTHS.length);
    expect(SMART_FRAGMENT_LENGTHS.length).toBe(20);
    // Every variant carries a distinct fragment length; all are vless to the worker.
    const lengths = frags.map((o: { streamSettings: { finalmask: { tcp: [{ settings: { length: string } }] } } }) =>
      o.streamSettings.finalmask.tcp[0].settings.length);
    expect(new Set(lengths).size).toBe(20);
    for (const o of frags) expect(o.protocol).toBe('vless');
    // The balancer selects across exactly those tags with leastPing.
    const bal = doc.routing.balancers[0];
    expect(bal.strategy.type).toBe('leastPing');
    expect(bal.selector.length).toBe(20);
    expect(doc.observatory.subjectSelector.length).toBe(20);
  });

  test('the fragment always fragments the ClientHello (tlshello)', () => {
    const doc = JSON.parse(buildSmartFragmentXray(cfg, node, 'ForgeEdge'));
    const frag = doc.outbounds.find((o: { tag?: string }) => o.tag?.startsWith('frag '));
    expect(frag.streamSettings.finalmask.tcp[0].settings.packets).toBe('tlshello');
  });
});
