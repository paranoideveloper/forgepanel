/**
 * The hand-rolled crypto and encoders, checked against independent references:
 * SHA-224/256 against `node:crypto`, base64 against `Buffer`, and the Go URL
 * escaping against literal expectations taken from net/url's documented rules.
 */

import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';

import { sha224Hex, sha256Hex, sha224Bytes, sha256Bytes, toHex } from '../src/common/sha';
import {
  b64Std, b64RawURL, b64StdDecode, b64AnyDecode, b64EncodeUtf8, b64DecodeUtf8,
  goQueryEscape, goPathEscape, Values,
} from '../src/common/encoding';
import { goMarshal, goMarshalIndent } from '../src/export/gojson';
import { toNAT64, hostPort, parseHostPort, isDomain, isIPv4, isIPv6 } from '../src/common/net';

const TE = new TextEncoder();

describe('SHA-256 / SHA-224 vs node:crypto', () => {
  const inputs = [
    '', 'a', 'abc', 'The quick brown fox jumps over the lazy dog',
    'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(57), 'x'.repeat(63),
    'x'.repeat(64), 'x'.repeat(65), 'x'.repeat(119), 'x'.repeat(1000),
    'unicode: café → 日本語 🔐',
  ];

  for (const s of inputs) {
    const label = s.length > 24 ? `${s.slice(0, 12)}…(${s.length})` : JSON.stringify(s);
    test(`sha256 ${label}`, () => {
      expect(sha256Hex(s)).toBe(createHash('sha256').update(s).digest('hex'));
    });
    test(`sha224 ${label}`, () => {
      expect(sha224Hex(s)).toBe(createHash('sha224').update(s).digest('hex'));
    });
  }

  test('digest lengths are 32 and 28 bytes', () => {
    expect(sha256Bytes(TE.encode('x')).length).toBe(32);
    expect(sha224Bytes(TE.encode('x')).length).toBe(28);
  });

  test('binary input matches too', () => {
    const buf = new Uint8Array(300);
    for (let i = 0; i < buf.length; i++) buf[i] = (i * 37) & 0xff;
    expect(toHex(sha256Bytes(buf))).toBe(createHash('sha256').update(buf).digest('hex'));
    expect(toHex(sha224Bytes(buf))).toBe(createHash('sha224').update(buf).digest('hex'));
  });
});

describe('base64', () => {
  const samples = ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar', 'café 🔐', '\x00\xff\xfe'];

  for (const s of samples) {
    test(`std encode ${JSON.stringify(s)}`, () => {
      expect(b64Std(TE.encode(s))).toBe(Buffer.from(s, 'utf8').toString('base64'));
    });
    test(`rawurl encode ${JSON.stringify(s)}`, () => {
      expect(b64RawURL(TE.encode(s))).toBe(Buffer.from(s, 'utf8').toString('base64url'));
    });
    test(`round-trip ${JSON.stringify(s)}`, () => {
      expect(b64DecodeUtf8(b64EncodeUtf8(s))).toBe(s);
    });
  }

  test('decodes padded and unpadded, std and url alphabets', () => {
    const raw = new Uint8Array([0xfb, 0xff, 0xbe, 0x01]);
    const std = b64Std(raw);           // "+/++AQ=="
    const url = b64RawURL(raw);        // "-_--AQ"
    expect(Array.from(b64StdDecode(std))).toEqual(Array.from(raw));
    expect(Array.from(b64AnyDecode(url))).toEqual(Array.from(raw));
    expect(Array.from(b64AnyDecode(std))).toEqual(Array.from(raw));
  });

  test('rejects a non-base64 character', () => {
    expect(() => b64AnyDecode('!!!!')).toThrow();
  });
});

describe('Go net/url escaping', () => {
  test('QueryEscape: space becomes +, everything reserved is escaped', () => {
    expect(goQueryEscape('a b')).toBe('a+b');
    expect(goQueryEscape('/path/to')).toBe('%2Fpath%2Fto');
    expect(goQueryEscape('a&b=c')).toBe('a%26b%3Dc');
    expect(goQueryEscape('p@ss w/ord+special&chars')).toBe('p%40ss+w%2Ford%2Bspecial%26chars');
    expect(goQueryEscape('-_.~')).toBe('-_.~');
    expect(goQueryEscape('日本')).toBe('%E6%97%A5%E6%9C%AC');
  });

  test('PathEscape: space becomes %20; $ & + : = @ stay bare; / ; , ? are escaped', () => {
    expect(goPathEscape('a b')).toBe('a%20b');
    expect(goPathEscape('Edge 1. VLESS - Domain : 443')).toBe('Edge%201.%20VLESS%20-%20Domain%20:%20443');
    expect(goPathEscape('a/b')).toBe('a%2Fb');
    expect(goPathEscape('a;b,c?d')).toBe('a%3Bb%2Cc%3Fd');
    expect(goPathEscape('a$b&c+d:e=f@g')).toBe('a$b&c+d:e=f@g');
    expect(goPathEscape('-_.~')).toBe('-_.~');
  });

  test('Values.encode sorts keys and returns "" when empty', () => {
    const v = new Values();
    expect(v.encode()).toBe('');
    v.set('type', 'ws');
    v.set('alpn', 'http/1.1');
    v.set('security', 'tls');
    expect(v.encode()).toBe('alpn=http%2F1.1&security=tls&type=ws');
  });

  test('Values.add keeps insertion order within a key', () => {
    const v = new Values();
    v.add('x', '1');
    v.add('x', '2');
    v.set('a', '0');
    expect(v.encode()).toBe('a=0&x=1&x=2');
  });
});

describe('Go encoding/json compatibility', () => {
  test('sorts object keys', () => {
    expect(goMarshal({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  test('HTML-escapes <, > and &, as Go does by default', () => {
    expect(goMarshal({ ps: 'a<b>c&d' })).toBe('{"ps":"a\\u003cb\\u003ec\\u0026d"}');
  });

  test('escapes control characters and the JS line separators', () => {
    expect(goMarshal({ s: ' ' })).toBe('{"s":"\\u0001\\u2028"}');
  });

  test('MarshalIndent matches Go\'s two-space form', () => {
    expect(goMarshalIndent({ b: [1, 2], a: {} }, '  ')).toBe(
      '{\n  "a": {},\n  "b": [\n    1,\n    2\n  ]\n}',
    );
  });
});

describe('address helpers', () => {
  test('hostPort brackets a bare IPv6 literal only', () => {
    expect(hostPort('example.com', 443)).toBe('example.com:443');
    expect(hostPort('1.2.3.4', 80)).toBe('1.2.3.4:80');
    expect(hostPort('2606:4700::1', 443)).toBe('[2606:4700::1]:443');
    expect(hostPort('[2606:4700::1]', 443)).toBe('[2606:4700::1]:443');
  });

  test('parseHostPort handles every form', () => {
    expect(parseHostPort('example.com:8443')).toEqual({ host: 'example.com', port: 8443 });
    expect(parseHostPort('example.com')).toEqual({ host: 'example.com', port: 0 });
    expect(parseHostPort('[2606:4700::1]:2408', true)).toEqual({ host: '[2606:4700::1]', port: 2408 });
    expect(parseHostPort('[2606:4700::1]:2408', false)).toEqual({ host: '2606:4700::1', port: 2408 });
  });

  test('classifiers agree with the Go regexes', () => {
    expect(isDomain('example.com')).toBe(true);
    expect(isDomain('1.2.3.4')).toBe(false);
    expect(isIPv4('192.0.2.1')).toBe(true);
    expect(isIPv4('192.0.2.256')).toBe(false);
    expect(isIPv6('[2606:4700::1]')).toBe(true);
    expect(isIPv6('2606:4700::1')).toBe(false);
  });

  test('NAT64 maps IPv4 into a /64 prefix', () => {
    // Each octet is emitted as two zero-padded hex digits, so 192.0.2.33
    // (c0 00 02 21) becomes the group pair c000:0221. Leading zeros inside a
    // group are legal IPv6 and this is the form NAT64 gateways expect.
    expect(toNAT64('192.0.2.33', '[2602:fc59:b0:64::]')).toBe('[2602:fc59:b0:64::c000:0221]');
    expect(toNAT64('1.1.1.1', '[2a02:898:146:64::]')).toBe('[2a02:898:146:64::0101:0101]');
    expect(toNAT64('255.255.255.255', '[2602:fc59:11:64::]')).toBe('[2602:fc59:11:64::ffff:ffff]');
  });

  test('NAT64 returns null rather than throwing on bad input', () => {
    expect(toNAT64('not-an-ip', '[2602:fc59:b0:64::]')).toBeNull();
    expect(toNAT64('192.0.2.999', '[2602:fc59:b0:64::]')).toBeNull();
    expect(toNAT64('192.0.2.1', 'not-a-prefix')).toBeNull();
  });
});
