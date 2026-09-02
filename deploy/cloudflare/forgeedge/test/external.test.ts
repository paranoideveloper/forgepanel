import { describe, expect, test } from 'bun:test';
import { parseSubBody, nodeKey } from '../src/edge/external';
import { b64EncodeUtf8 } from '../src/common/encoding';

const VLESS = 'vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=ws&security=tls&sni=a.example.com&path=%2Fx#Node%20A';
const TROJAN = 'trojan://pass123@b.example.com:8443?type=ws&security=tls&sni=b.example.com#Node%20B';
const SS = 'ss://YWVzLTI1Ni1nY206c2VjcmV0@c.example.com:8388#Node%20C';

describe('external subscription merge', () => {
  test('parses a plain-text sub body into canonical nodes', () => {
    const nodes = parseSubBody([VLESS, TROJAN, SS].join('\n'), new Set());
    expect(nodes.length).toBe(3);
    expect(nodes.map((n) => n.protocol).sort()).toEqual(['shadowsocks', 'trojan', 'vless']);
    const vl = nodes.find((n) => n.protocol === 'vless')!;
    expect(vl.address).toBe('a.example.com');
    expect(vl.security.type).toBe('tls');
    expect(vl.transport.network).toBe('ws');
  });

  test('accepts a base64 (v2ray) sub body', () => {
    const nodes = parseSubBody(b64EncodeUtf8([VLESS, TROJAN].join('\n')), new Set());
    expect(nodes.length).toBe(2);
  });

  test('skips lines the parser cannot handle without failing the whole body', () => {
    const body = [VLESS, 'hysteria2://nope@x:443', 'garbage', 'ss://also-bad', TROJAN].join('\n');
    const nodes = parseSubBody(body, new Set());
    // The two well-formed configs survive; the junk is dropped.
    expect(nodes.map((n) => n.protocol).sort()).toEqual(['trojan', 'vless']);
  });

  test('de-duplicates the same node seen across bodies', () => {
    const seen = new Set<string>();
    const first = parseSubBody(VLESS, seen);
    const second = parseSubBody(VLESS, seen); // same node again
    expect(first.length).toBe(1);
    expect(second.length).toBe(0);
  });

  test('honours the per-body limit', () => {
    const many = Array.from({ length: 10 }, (_, i) =>
      `vless://11111111-2222-3333-4444-555555555555@n${i}.example.com:443?security=tls#N${i}`).join('\n');
    expect(parseSubBody(many, new Set(), 4).length).toBe(4);
  });

  test('nodeKey is stable per identity', () => {
    const [a] = parseSubBody(VLESS, new Set());
    const [b] = parseSubBody(VLESS, new Set());
    expect(nodeKey(a)).toBe(nodeKey(b));
  });
});
