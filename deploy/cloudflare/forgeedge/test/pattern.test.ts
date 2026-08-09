import { describe, expect, test } from 'bun:test';
import { applyPattern, plainLinksMode } from '../src/export/uri';
import type { Node } from '../src/model/node';

describe('unsafe-uTLS pattern', () => {
  test('applyPattern stamps cs/fm/fp=unsafe on a TLS link, skips non-TLS', () => {
    const out = applyPattern('vless://u@1.2.3.4:443?security=tls&type=ws&encryption=none#N');
    const q = new URLSearchParams(out.slice(out.indexOf('?') + 1, out.indexOf('#')));
    expect(q.get('fp')).toBe('unsafe');
    expect(q.get('cs')!.split(':').length).toBe(13);
    expect(q.get('fm')).toContain('"maxSplit":"355"');
    expect(out.endsWith('#N')).toBe(true);
    // non-tls + base64 vmess untouched
    expect(applyPattern('vless://u@1.2.3.4:80?security=none#x')).toBe('vless://u@1.2.3.4:80?security=none#x');
    expect(applyPattern('vmess://eyABC')).toBe('vmess://eyABC');
  });

  test('plainLinksMode: off/only/both', () => {
    const nodes: Node[] = [{ tag: 'n', remark: 'n', protocol: 'vless', address: '1.2.3.4', port: 443, uuid: 'u',
      transport: { network: 'ws', path: '/x' }, security: { type: 'tls', server_name: 'a.example' } } as unknown as Node];
    expect(plainLinksMode(nodes, 'off').includes('fp=unsafe')).toBe(false);
    expect((plainLinksMode(nodes, 'only').match(/fp=unsafe/g) || []).length).toBe(1);
    const both = plainLinksMode(nodes, 'both').trim().split('\n');
    expect(both.length).toBe(2);
    expect((plainLinksMode(nodes, 'both').match(/fp=unsafe/g) || []).length).toBe(1);
  });
});
